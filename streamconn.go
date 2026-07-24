package samizdat

import (
	"io"
	"net"
	"sync"
	"time"
)

const (
	// readChunkSize bounds how far ahead the read pump reads from the
	// underlying stream. The pump blocks on delivery until the caller consumes
	// a chunk, so at most one chunk is buffered.
	readChunkSize = 32 * 1024

	// drainForceTimeout bounds how long Close waits for the server to end the
	// stream cleanly before force-closing the reader. Draining to EOF rather
	// than sending RST_STREAM avoids an abrupt-reset fingerprint.
	drainForceTimeout = 5 * time.Second
)

// streamConn wraps an io.ReadWriteCloser (typically an HTTP/2 stream body)
// as a net.Conn. Because the underlying stream body reads block in a way that
// a socket deadline cannot interrupt (the body is fed by a background HTTP/2
// frame-reader goroutine), a dedicated read pump owns all reads from rwc and
// Read selects the pump's output against the read deadline. This makes
// SetReadDeadline actually interrupt an in-flight blocked read.
type streamConn struct {
	rwc         io.ReadWriteCloser
	localAddr   net.Addr
	remoteAddr  net.Addr
	shaper      *Shaper
	destination string

	readDeadline  *pipeDeadline
	writeDeadline *pipeDeadline

	readResults chan readResult
	done        chan struct{} // closed by Close; stops Read and drains the pump
	pumpDone    chan struct{} // closed when the pump goroutine exits

	// readBuf and pendingErr hold the tail of a chunk that didn't fit in the
	// caller's buffer. Accessed only from Read, which net.Conn callers
	// serialize (concurrent Reads are not supported).
	readBuf    []byte
	pendingErr error

	closeOnce sync.Once
	mu        sync.Mutex
	closed    bool
}

type readResult struct {
	data []byte
	err  error
}

// newStreamConn creates a net.Conn backed by the given ReadWriteCloser.
func newStreamConn(rwc io.ReadWriteCloser, localAddr, remoteAddr net.Addr, destination string, shaper *Shaper) *streamConn {
	sc := &streamConn{
		rwc:           rwc,
		localAddr:     localAddr,
		remoteAddr:    remoteAddr,
		destination:   destination,
		shaper:        shaper,
		readDeadline:  newPipeDeadline(),
		writeDeadline: newPipeDeadline(),
		readResults:   make(chan readResult),
		done:          make(chan struct{}),
		pumpDone:      make(chan struct{}),
	}
	go sc.readLoop()
	return sc
}

// readLoop is the sole reader of rwc. It delivers chunks to Read over an
// unbuffered channel (providing backpressure) and, after Close, keeps reading
// to drain the stream to EOF.
func (sc *streamConn) readLoop() {
	defer close(sc.pumpDone)
	for {
		buf := make([]byte, readChunkSize)
		n, err := sc.rwc.Read(buf)
		if n > 0 {
			select {
			case sc.readResults <- readResult{data: buf[:n]}:
			case <-sc.done: // draining after Close: discard
			}
		}
		if err != nil {
			select {
			case sc.readResults <- readResult{err: err}:
			case <-sc.done:
			}
			return
		}
	}
}

func (sc *streamConn) Read(b []byte) (int, error) {
	// An already-expired deadline takes precedence over buffered or new data.
	select {
	case <-sc.readDeadline.wait():
		return 0, &timeoutError{}
	default:
	}

	if len(sc.readBuf) > 0 {
		n := copy(b, sc.readBuf)
		sc.readBuf = sc.readBuf[n:]
		return n, nil
	}
	if sc.pendingErr != nil {
		err := sc.pendingErr
		sc.pendingErr = nil
		return 0, err
	}

	select {
	case res := <-sc.readResults:
		if len(res.data) == 0 {
			return 0, res.err
		}
		n := copy(b, res.data)
		if n < len(res.data) {
			sc.readBuf = res.data[n:]
		}
		sc.pendingErr = res.err
		return n, nil
	case <-sc.readDeadline.wait():
		return 0, &timeoutError{}
	case <-sc.done:
		return 0, io.EOF
	}
}

func (sc *streamConn) Write(b []byte) (int, error) {
	select {
	case <-sc.writeDeadline.wait():
		return 0, &timeoutError{}
	default:
	}
	if sc.shaper != nil {
		return sc.shaper.Write(sc.rwc, b)
	}
	return sc.rwc.Write(b)
}

func (sc *streamConn) Close() error {
	sc.closeOnce.Do(func() {
		sc.mu.Lock()
		sc.closed = true
		sc.mu.Unlock()

		sc.readDeadline.set(time.Time{})
		sc.writeDeadline.set(time.Time{})

		// Half-close so the server ends the stream; the pump then drains the
		// response to EOF rather than aborting it with an RST.
		if cw, ok := sc.rwc.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		close(sc.done)

		forceTimer := time.AfterFunc(drainForceTimeout, func() { sc.rwc.Close() })
		go func() {
			<-sc.pumpDone
			forceTimer.Stop()
			sc.rwc.Close()
		}()
	})
	return nil
}

func (sc *streamConn) LocalAddr() net.Addr  { return sc.localAddr }
func (sc *streamConn) RemoteAddr() net.Addr { return sc.remoteAddr }

func (sc *streamConn) SetDeadline(t time.Time) error {
	sc.readDeadline.set(t)
	sc.writeDeadline.set(t)
	return nil
}

func (sc *streamConn) SetReadDeadline(t time.Time) error {
	sc.readDeadline.set(t)
	return nil
}

func (sc *streamConn) SetWriteDeadline(t time.Time) error {
	sc.writeDeadline.set(t)
	return nil
}

// CloseWrite performs a half-close on the write side of the connection,
// signaling EOF to the remote peer while keeping the read side open.
// This is critical for protocols like TLS where the server sends remaining
// data after the client signals it's done writing.
func (sc *streamConn) CloseWrite() error {
	sc.mu.Lock()
	closed := sc.closed
	sc.mu.Unlock()
	if closed {
		return nil
	}
	if cw, ok := sc.rwc.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}

// pipeDeadline is a net.Conn deadline whose expiry is observable on a channel,
// so a blocked Read can select against it. It follows the implementation of
// the standard library's net.Pipe deadline.
type pipeDeadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{} // closed when the deadline is reached; never nil
}

func newPipeDeadline() *pipeDeadline {
	return &pipeDeadline{cancel: make(chan struct{})}
}

// set arms the deadline. A zero time clears it.
func (d *pipeDeadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel // a fired timer already closed cancel; drain it
	}
	d.timer = nil

	closed := isClosedChan(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}

	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		d.timer = time.AfterFunc(dur, func() { close(d.cancel) })
		return
	}

	// Deadline in the past: expire immediately.
	if !closed {
		close(d.cancel)
	}
}

// wait returns a channel that is closed when the deadline is reached.
func (d *pipeDeadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosedChan(c <-chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}

// timeoutError implements the net.Error interface for deadline timeouts.
type timeoutError struct{}

func (e *timeoutError) Error() string   { return "i/o timeout" }
func (e *timeoutError) Timeout() bool   { return true }
func (e *timeoutError) Temporary() bool { return true }

// streamAddr implements net.Addr for H2 stream connections.
type streamAddr struct {
	network string
	address string
}

func (a *streamAddr) Network() string { return a.network }
func (a *streamAddr) String() string  { return a.address }
