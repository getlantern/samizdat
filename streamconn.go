package samizdat

import (
	"io"
	"net"
	"sync"
	"time"
)

// streamConn wraps an io.ReadWriteCloser (typically an HTTP/2 stream body)
// as a net.Conn. It implements all required net.Conn methods, delegating
// Read/Write to the underlying stream and supporting deadline-based timeouts.
type streamConn struct {
	rwc         io.ReadWriteCloser
	localAddr   net.Addr
	remoteAddr  net.Addr
	shaper      *Shaper
	destination string

	readDeadline  *deadlineTimer
	writeDeadline *deadlineTimer

	mu     sync.Mutex
	closed bool
}

// newStreamConn creates a net.Conn backed by the given ReadWriteCloser.
func newStreamConn(rwc io.ReadWriteCloser, localAddr, remoteAddr net.Addr, destination string, shaper *Shaper) *streamConn {
	return &streamConn{
		rwc:           rwc,
		localAddr:     localAddr,
		remoteAddr:    remoteAddr,
		destination:   destination,
		shaper:        shaper,
		readDeadline:  newDeadlineTimer(),
		writeDeadline: newDeadlineTimer(),
	}
}

func (sc *streamConn) Read(b []byte) (int, error) {
	if err := sc.readDeadline.wait(); err != nil {
		return 0, err
	}
	return sc.rwc.Read(b)
}

func (sc *streamConn) Write(b []byte) (int, error) {
	if err := sc.writeDeadline.wait(); err != nil {
		return 0, err
	}
	if sc.shaper != nil {
		return sc.shaper.Write(sc.rwc, b)
	}
	return sc.rwc.Write(b)
}

func (sc *streamConn) Close() error {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed {
		return nil
	}
	sc.closed = true
	sc.readDeadline.stop()
	sc.writeDeadline.stop()
	return sc.rwc.Close()
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

// deadlineTimer supports net.Conn deadline semantics.
type deadlineTimer struct {
	mu      sync.Mutex
	timer   *time.Timer
	expired bool
}

func newDeadlineTimer() *deadlineTimer {
	return &deadlineTimer{}
}

// set configures the deadline. A zero time clears the deadline.
func (dt *deadlineTimer) set(t time.Time) {
	dt.mu.Lock()
	defer dt.mu.Unlock()

	dt.expired = false
	if dt.timer != nil {
		dt.timer.Stop()
		dt.timer = nil
	}

	if t.IsZero() {
		return
	}

	d := time.Until(t)
	if d <= 0 {
		dt.expired = true
		return
	}

	dt.timer = time.AfterFunc(d, func() {
		dt.mu.Lock()
		dt.expired = true
		dt.mu.Unlock()
	})
}

func (dt *deadlineTimer) stop() {
	dt.mu.Lock()
	defer dt.mu.Unlock()
	if dt.timer != nil {
		dt.timer.Stop()
	}
}

// wait returns a timeout error if the deadline has expired, nil otherwise.
func (dt *deadlineTimer) wait() error {
	dt.mu.Lock()
	expired := dt.expired
	dt.mu.Unlock()
	if expired {
		return &timeoutError{}
	}
	return nil
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
