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

	bufPool sync.Pool // reusable readChunkSize buffers for the pump

	// readMu serializes Read so concurrent callers (which net.Conn permits)
	// don't race on readBuf/readErr. readBuf holds the tail of a chunk that
	// didn't fit in the caller's buffer; readErr is the sticky terminal error
	// from the pump, returned by every subsequent Read (matching io.Reader) so
	// a read past EOF returns the error rather than blocking on the exited pump.
	readMu  sync.Mutex
	readBuf []byte
	readErr error

	closeOnce    sync.Once
	rwcCloseOnce sync.Once
	mu           sync.Mutex
	closed       bool
}

// readResult carries a pooled buffer plus the length read and any terminal
// error. The receiver copies the data out and returns buf to the pool.
type readResult struct {
	buf []byte
	n   int
	err error
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
	sc.bufPool.New = func() any { return make([]byte, readChunkSize) }
	go sc.readLoop()
	return sc
}

// readLoop is the sole reader of rwc. It delivers chunks to Read over an
// unbuffered channel (providing backpressure) and, after Close, keeps reading
// to drain the stream to EOF.
func (sc *streamConn) readLoop() {
	defer close(sc.pumpDone)
	for {
		buf := sc.bufPool.Get().([]byte)
		n, err := sc.rwc.Read(buf)
		if n == 0 && err == nil {
			sc.bufPool.Put(buf)
			continue
		}
		// Deliver data and a terminal error in one result so the pump can exit
		// after a single send. A separate error send could block forever if the
		// caller consumes the final data but never reads again or closes.
		select {
		case sc.readResults <- readResult{buf: buf, n: n, err: err}:
			// Read owns buf now and returns it to the pool.
		case <-sc.done: // draining after Close: discard
			sc.bufPool.Put(buf)
		}
		if err != nil {
			return
		}
	}
}

func (sc *streamConn) Read(b []byte) (int, error) {
	sc.readMu.Lock()
	defer sc.readMu.Unlock()

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
	if sc.readErr != nil {
		return 0, sc.readErr
	}

	select {
	case res := <-sc.readResults:
		if res.err != nil {
			sc.readErr = res.err
		}
		if res.n == 0 {
			sc.bufPool.Put(res.buf)
			return 0, sc.readErr
		}
		n := copy(b, res.buf[:res.n])
		if n < res.n {
			// Copy the tail into our own buffer so the pooled buffer can be
			// reused immediately; aliasing it would race with the pump's next
			// read. Any terminal error stays in readErr and surfaces once this
			// buffered tail is drained, so the caller sees all bytes first.
			sc.readBuf = append([]byte(nil), res.buf[n:res.n]...)
		}
		sc.bufPool.Put(res.buf)
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

		// The timer only aborts the read to unblock a stalled pump; it must not
		// run the graceful drain in closeRWC, which would read rwc concurrently
		// with the still-blocked pump. Once the pump exits, the goroutine runs
		// the graceful close.
		forceTimer := time.AfterFunc(drainForceTimeout, sc.abortRWC)
		go func() {
			<-sc.pumpDone
			forceTimer.Stop()
			sc.closeRWC()
		}()
	})
	return nil
}

// readAborter can force its read side closed to unblock a stalled read,
// bypassing the drain that Close performs.
type readAborter interface {
	abort()
}

// abortRWC unblocks a pump stalled in rwc.Read. A readAborter (the H2 stream)
// closes just its reader; a plain conn is closed outright, since that is its
// only way to interrupt a blocked read.
func (sc *streamConn) abortRWC() {
	if a, ok := sc.rwc.(readAborter); ok {
		a.abort()
		return
	}
	sc.closeRWC()
}

func (sc *streamConn) closeRWC() {
	sc.rwcCloseOnce.Do(func() { sc.rwc.Close() })
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
func (d *pipeDeadline) wait() <-chan struct{} {
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
