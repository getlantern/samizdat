package samizdat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

// errSecondDial is what h2Transport's x/net Transport gets if it tries to dial
// a second connection; see newH2Transport.
var errSecondDial = errors.New("samizdat: HTTP/2 transport has only one connection")

// transportIDs numbers transports for logs.
var transportIDs atomic.Uint64

// discardLogger is the logger of a transport whose client has none.
var discardLogger = slog.New(slog.DiscardHandler)

// slowConnect is how long a CONNECT that succeeds can take before it's logged.
const slowConnect = 3 * time.Second

// connectAnswerTimeout is how long a CONNECT waits for the server's answer
// before its transport is taken for deaf. Both servers answer before dialing
// the destination, so the answer takes a round trip or two however slow the
// destination is; one that doesn't come means the connection no longer carries
// what the client sends, though what the server sends may still arrive. A var
// so tests can shorten it.
var connectAnswerTimeout = 5 * time.Second

// errConnectUnanswered is the error of a CONNECT abandoned because its
// transport went deaf. It's conn-fatal, so the dial retries on another
// transport.
var errConnectUnanswered = errors.New("samizdat: server did not answer CONNECT")

// h2Transport manages a single TLS+HTTP/2 connection to the server and
// multiplexes CONNECT tunnels over it as separate H2 streams.
type h2Transport struct {
	// conn is the TLS connection, counting what it reads.
	conn        *readTrackingConn
	h2Roundtrip http.RoundTripper
	serverAddr  string
	localAddr   net.Addr
	remoteAddr  net.Addr

	mu            sync.Mutex
	activeStreams atomic.Int32
	// retired is set when x/net's Transport stops using the connection for
	// new streams (see errSecondDial), or when it's deaf (see markDeaf). The
	// pool stops handing the transport out, and it closes once its last
	// stream ends.
	retired atomic.Bool
	// idleSince is when a stream last closed, in Unix nanoseconds, or when
	// the transport was created if no stream has.
	idleSince  atomic.Int64
	maxStreams int
	closed     bool
	// deaf is closed once a CONNECT on the transport has gone unanswered for
	// connectAnswerTimeout, failing every CONNECT still waiting on it.
	// Created on first use, under mu.
	deaf       chan struct{}
	deafMarked bool

	id     uint64
	logger *slog.Logger
	// closeLogged is set once a close has been logged, so two paths closing
	// it at once log it once.
	closeLogged atomic.Bool
	// created is when the transport was created.
	created time.Time
}

// readTrackingConn records when its connection last read anything, so a
// failed CONNECT's log can tell a connection that went silent from one still
// carrying other tunnels.
type readTrackingConn struct {
	net.Conn
	// lastRead is when a read last returned data, in Unix nanoseconds, or
	// zero if none has.
	lastRead  atomic.Int64
	bytesRead atomic.Int64
	// readErr is the first error a read returned.
	readErr atomic.Pointer[error]
	// closed is set once anything closes the connection.
	closed atomic.Bool
}

func (c *readTrackingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.bytesRead.Add(int64(n))
		c.lastRead.Store(time.Now().UnixNano())
	}
	// An error after the connection was closed here is that close's, and
	// says nothing about why.
	if err != nil && !c.closed.Load() {
		c.readErr.CompareAndSwap(nil, &err)
	}
	return n, err
}

func (c *readTrackingConn) Close() error {
	c.closed.Store(true)
	return c.Conn.Close()
}

// sinceRead returns how long ago the connection last read anything as of now,
// or since created if it never has.
func (t *h2Transport) sinceRead(now time.Time) time.Duration {
	last := t.conn.lastRead.Load()
	if last == 0 {
		return now.Sub(t.created)
	}
	return now.Sub(time.Unix(0, last))
}

// newH2Transport creates an HTTP/2 transport over an existing TLS connection.
// receiveWindows are how much a transport lets the server send ahead of what
// it has read, per stream and per connection.
type receiveWindows struct {
	perStream, perConn int
}

func newH2Transport(tlsConn net.Conn, serverAddr string, maxStreams int, win receiveWindows) (*h2Transport, error) {
	conn := &readTrackingConn{Conn: tlsConn}

	// Create HTTP/2 client transport over the existing TLS connection.
	// The transport must never dial a second connection: it would get this
	// same one back and write a new preface into the middle of the first
	// connection's frames, corrupting every stream on it. x/net dials again
	// when it thinks the connection is full (it assumes 100 streams until the
	// server's SETTINGS arrive), so StrictMaxConcurrentStreams makes it wait
	// for a stream slot instead, and any later dial is refused.
	//
	// x/net takes receive windows only from an http.Transport's HTTP2Config,
	// through ConfigureTransports, which also gives the transport a pool that
	// never dials; clearing ConnPool restores the default one, which dials
	// through DialTLSContext.
	var dialed atomic.Bool
	h2t, err := http2.ConfigureTransports(&http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerStream:     win.perStream,
		MaxReceiveBufferPerConnection: win.perConn,
	}})
	if err != nil {
		return nil, err
	}
	h2t.ConnPool = nil
	h2t.DialTLSContext = func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
		if dialed.Swap(true) {
			return nil, errSecondDial
		}
		return conn, nil
	}
	h2t.AllowHTTP = false
	h2t.DisableCompression = true
	h2t.StrictMaxConcurrentStreams = true

	t := &h2Transport{
		conn:        conn,
		h2Roundtrip: h2t,
		serverAddr:  serverAddr,
		localAddr:   tlsConn.LocalAddr(),
		remoteAddr:  tlsConn.RemoteAddr(),
		maxStreams:  maxStreams,
		id:          transportIDs.Add(1),
		created:     time.Now(),
	}
	t.idleSince.Store(time.Now().UnixNano())

	return t, nil
}

// openReserved issues an HTTP/2 CONNECT request to open a tunnel to the
// destination through the proxy server, and returns a net.Conn backed by the
// H2 stream. The caller must hold a stream slot for it, reserved by
// tryReserve or by the pool creating the transport. The slot is released on
// every path that doesn't produce a tunnel.
func (t *h2Transport) openReserved(ctx context.Context, destination string) (net.Conn, error) {
	// The stream has counted since its slot was reserved, not from the
	// CONNECT's response, so a transport retired meanwhile isn't closed
	// under a CONNECT in flight.
	opened := false
	defer func() {
		if !opened {
			t.releaseReserved()
		}
	}()

	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		// Wrap net.ErrClosed so a transport retired concurrently between
		// getTransport and this check reads as connFatal, letting DialContext
		// redial on a fresh transport instead of hard-failing.
		return nil, fmt.Errorf("transport closed: %w", net.ErrClosed)
	}
	t.mu.Unlock()

	// A destination with no valid encoding fails here, not in RoundTrip,
	// whose error would quote it into the transport's logs.
	if _, err := httpguts.PunycodeHostPort(destination); err != nil {
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, err)
	}

	// Issue CONNECT request
	pr, pw := io.Pipe()

	// Create a detachable context for the H2 CONNECT request. During
	// RoundTrip we propagate cancellation from the caller's ctx so that
	// DialContext timeouts are respected. After RoundTrip succeeds, we
	// stop propagation so that post-establishment context cancellation
	// (e.g. sing-box canceling ctx when bidirectional copy finishes)
	// doesn't reach the H2 transport's writeRequest goroutine — which
	// would send RST_STREAM and disrupt other multiplexed streams.
	tunnelCtx, tunnelCancel := context.WithCancel(context.Background())
	stop := context.AfterFunc(ctx, func() { tunnelCancel() })

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodConnect, "https://"+t.serverAddr, pr)
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		return nil, fmt.Errorf("creating CONNECT request: %w", err)
	}
	req.Host = destination
	// Standard HTTP/2 CONNECT uses the :authority pseudo-header which is set from Host

	// A CONNECT the server doesn't answer in time marks the transport deaf,
	// which abandons it and every other CONNECT waiting on the transport.
	// answer settles the race between the answer and the abandonment.
	const (
		waiting int32 = iota
		answered
		abandoned
	)
	var answer atomic.Int32
	// The timer claims the CONNECT as the answer would, so one answered or
	// given up on by its caller as the timer fires leaves the transport be.
	answerTimeout := connectAnswerTimeout
	answerTimer := time.AfterFunc(answerTimeout, func() {
		if ctx.Err() == nil && answer.CompareAndSwap(waiting, abandoned) {
			t.markDeaf(answerTimeout)
			tunnelCancel()
		}
	})
	answerDone := make(chan struct{})
	go func() {
		select {
		case <-t.deafSignal():
			if answer.CompareAndSwap(waiting, abandoned) {
				tunnelCancel()
			}
		case <-answerDone:
		}
	}()
	settle := func() bool {
		answerTimer.Stop()
		close(answerDone)
		return answer.CompareAndSwap(waiting, answered)
	}

	start := time.Now()
	readBefore := t.conn.bytesRead.Load()
	resp, err := t.h2Roundtrip.RoundTrip(req)
	if !settle() {
		// Abandoned as deaf; the transport is retired already, but its
		// live tunnels carry on.
		stop()
		tunnelCancel()
		pw.Close()
		if err == nil {
			resp.Body.Close()
		}
		t.log().Warn("samizdat CONNECT unanswered",
			"transport", t.id,
			"waited", time.Since(start),
			"since_read", t.sinceRead(time.Now()),
			"read_while_waiting", t.conn.bytesRead.Load() != readBefore,
			"streams", t.streamCount(),
			"age", time.Since(t.created))
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, errConnectUnanswered)
	}
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		now := time.Now()
		t.log().Warn("samizdat CONNECT failed",
			"transport", t.id,
			"error", err,
			"waited", now.Sub(start),
			"since_read", t.sinceRead(now),
			"read_while_waiting", t.conn.bytesRead.Load() != readBefore,
			"streams", t.streamCount(),
			"age", now.Sub(t.created))
		// This transport wraps a single, non-redialable conn (see
		// newH2Transport's DialTLSContext). A conn-fatal error poisons every
		// subsequent RoundTrip, so retire the transport here; otherwise the
		// pool keeps handing back the dead transport on each getTransport
		// until a later cleanup tick, producing sustained error bursts.
		switch {
		case errors.Is(err, errSecondDial):
			// The connection can't take new streams (a GOAWAY, or stream
			// IDs used up) but may still carry live tunnels; keep them.
			reason := "connection takes no new streams"
			if t.conn.closed.Load() {
				reason = "connection closed under the transport"
			}
			t.retireWithReason(reason)
		case connFatal(err):
			t.closeWithReason("CONNECT failed: " + err.Error())
		}
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, err)
	}

	// Detach: stop propagating caller's context cancellation into the
	// H2 stream now that the tunnel is established.
	stop()

	if resp.StatusCode != http.StatusOK {
		t.log().Warn("samizdat CONNECT refused",
			"transport", t.id,
			"status", resp.StatusCode,
			"waited", time.Since(start),
			"streams", t.streamCount())
	} else if waited := time.Since(start); waited >= slowConnect {
		t.log().Info("samizdat CONNECT slow",
			"transport", t.id,
			"waited", waited,
			"since_read", t.sinceRead(time.Now()),
			"read_while_waiting", t.conn.bytesRead.Load() != readBefore,
			"streams", t.streamCount())
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		return nil, fmt.Errorf("CONNECT to %s returned status %d", destination, resp.StatusCode)
	}

	opened = true

	// Create a ReadWriteCloser that reads from the response body and writes to the pipe
	rwc := &h2StreamRWC{
		reader:       resp.Body,
		writer:       pw,
		transport:    t,
		tunnelCancel: tunnelCancel,
	}

	conn := newStreamConn(
		rwc,
		t.localAddr,
		&streamAddr{network: "tcp", address: destination},
		destination,
	)

	return conn, nil
}

// connFatal reports whether a RoundTrip error means the transport's underlying
// connection is dead and should be retired. Caller-driven cancellation is
// excluded — it reflects the caller abandoning a single request, not a broken
// conn, and retiring the transport would tear down the healthy sibling streams
// multiplexed over it.
func connFatal(err error) bool {
	if errors.Is(err, errConnectUnanswered) {
		return true
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, errSecondDial) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// tryReserve takes a stream slot if the transport has one, atomically, so
// callers choosing a transport at once can't overbook it.
func (t *h2Transport) tryReserve() bool {
	for {
		n := t.activeStreams.Load()
		if t.retired.Load() || int(n) >= t.maxStreams {
			return false
		}
		if t.activeStreams.CompareAndSwap(n, n+1) {
			return true
		}
	}
}

// releaseStream ends one of the transport's open streams, and closes a
// retired transport once none is left.
func (t *h2Transport) releaseStream() {
	// The timestamp is stored before the count can reach zero, so cleanup
	// never sees an idle transport with a stale one.
	t.idleSince.Store(time.Now().UnixNano())
	t.releaseReserved()
}

// releaseReserved gives back a stream slot whose CONNECT produced no tunnel,
// and closes a retired transport once no stream is left. Unlike a stream
// ending, it leaves idleSince alone: a transport whose CONNECTs keep failing
// carried nothing, and must still idle out.
func (t *h2Transport) releaseReserved() {
	if t.activeStreams.Add(-1) == 0 && t.retired.Load() {
		t.closeWithReason("retired, and its last stream ended")
	}
}

// retireWithReason stops the transport taking new streams, logging why, and
// closes it once the ones it carries, including any still opening, have
// ended.
func (t *h2Transport) retireWithReason(reason string) {
	if !t.retired.Swap(true) && !t.isClosed() {
		t.log().Info("samizdat transport retired", t.logAttrs(reason)...)
	}
	if t.streamCount() == 0 {
		t.closeWithReason("retired with no streams")
	}
}

// markDeaf retires the transport after a CONNECT on it went unanswered for
// after, and fails every CONNECT still waiting on it so each retries elsewhere
// at once rather than waiting out its own timeout.
func (t *h2Transport) markDeaf(after time.Duration) {
	t.mu.Lock()
	if t.deafMarked {
		t.mu.Unlock()
		return
	}
	t.deafMarked = true
	t.mu.Unlock()
	// Retired before the waiters fail, so their retries can't take this
	// transport again.
	t.retireWithReason(fmt.Sprintf("a CONNECT went unanswered for %s", after))
	t.mu.Lock()
	if t.deaf == nil {
		t.deaf = make(chan struct{})
	}
	close(t.deaf)
	t.mu.Unlock()
}

// deafSignal returns a channel closed once the transport is marked deaf.
func (t *h2Transport) deafSignal() <-chan struct{} {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.deaf == nil {
		t.deaf = make(chan struct{})
	}
	return t.deaf
}

// closeWithReason closes the transport, logging why.
func (t *h2Transport) closeWithReason(reason string) {
	if !t.isClosed() && t.closeLogged.CompareAndSwap(false, true) {
		t.log().Info("samizdat transport closed", t.logAttrs(reason)...)
	}
	t.close()
}

// log returns the transport's logger, which discards everything if it has
// none.
func (t *h2Transport) log() *slog.Logger {
	if t.logger == nil {
		return discardLogger
	}
	return t.logger
}

func (t *h2Transport) logAttrs(reason string) []any {
	now := time.Now()
	attrs := []any{
		"transport", t.id,
		"reason", reason,
		"streams", t.streamCount(),
		"since_read", t.sinceRead(now),
		"read", t.conn.bytesRead.Load(),
		"age", now.Sub(t.created),
	}
	if err := t.conn.readErr.Load(); err != nil {
		attrs = append(attrs, "read_error", *err)
	}
	return attrs
}

// streamCount returns the number of active streams.
func (t *h2Transport) streamCount() int {
	return int(t.activeStreams.Load())
}

// idleFor returns how long the transport has had no open stream as of now,
// or zero while it has one.
func (t *h2Transport) idleFor(now time.Time) time.Duration {
	if t.streamCount() > 0 {
		return 0
	}
	return now.Sub(time.Unix(0, t.idleSince.Load()))
}

// close shuts down the H2 transport and underlying TLS connection.
func (t *h2Transport) close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	if closer, ok := t.h2Roundtrip.(io.Closer); ok {
		closer.Close()
	}
	return t.conn.Close()
}

// isClosed returns true if the transport has been closed.
func (t *h2Transport) isClosed() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.closed
}

// h2StreamRWC wraps a response body (reader) and pipe writer as an
// io.ReadWriteCloser for use as a bidirectional stream.
type h2StreamRWC struct {
	reader       io.ReadCloser
	writer       io.WriteCloser
	transport    *h2Transport
	tunnelCancel context.CancelFunc // releases the detached tunnel context
	once         sync.Once
	writerOnce   sync.Once
}

func (s *h2StreamRWC) Read(b []byte) (int, error) {
	return s.reader.Read(b)
}

func (s *h2StreamRWC) Write(b []byte) (int, error) {
	return s.writer.Write(b)
}

// abort force-closes the response body to unblock a read stalled on a stream
// the server never ends. This sends RST_STREAM and is a last resort; the
// graceful path is Close, which drains to EOF first.
func (s *h2StreamRWC) abort() {
	s.reader.Close()
}

// Close finalizes the stream. It drains any remaining response body to EOF
// before closing the reader: closing resp.Body while data is still pending
// makes net/http2 abort the stream with RST_STREAM, an abrupt reset a censor
// could fingerprint, whereas draining first lets the stream end with a normal
// END_STREAM. A server that never ends the stream is force-closed after
// drainForceTimeout. streamConn's read pump has normally already drained (or
// aborted) the body before Close runs, so the copy returns at once; the drain
// keeps Close self-safe for any direct caller.
func (s *h2StreamRWC) Close() error {
	var closeErr error
	s.once.Do(func() {
		closeErr = s.closeWriter()
		timer := time.AfterFunc(drainForceTimeout, func() { s.reader.Close() })
		io.Copy(io.Discard, s.reader)
		timer.Stop()
		s.reader.Close()
		if s.tunnelCancel != nil {
			s.tunnelCancel()
		}
		s.transport.releaseStream()
	})
	return closeErr
}

// closeWriter closes the writer at most once, safe to call from both
// CloseWrite and Close.
func (s *h2StreamRWC) closeWriter() error {
	var err error
	s.writerOnce.Do(func() {
		err = s.writer.Close()
	})
	return err
}

// CloseWrite closes only the write side (pipe writer), sending END_STREAM on
// the H2 request body while keeping the response body (reader) open to receive
// remaining data from the server.
func (s *h2StreamRWC) CloseWrite() error {
	return s.closeWriter()
}
