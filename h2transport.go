package samizdat

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
)

// errSecondDial is what h2Transport's x/net Transport gets if it tries to dial
// a second connection; see newH2Transport.
var errSecondDial = errors.New("samizdat: HTTP/2 transport has only one connection")

// errPingLost marks a CONNECT that failed because its connection's ping went
// unanswered and the transport closed the connection (see checkUnanswered).
var errPingLost = errors.New("samizdat: connection lost: ping unanswered")

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
// what the client sends, though what the server sends may still arrive. The
// clock starts once connection-start shaping is over: CONNECTs wait behind its
// schedule, which takes several round trips (and is bounded by shapingTimeout),
// and a slow path is no sign of a deaf one. After it, the TLS handshake and
// the schedule have shown the path carries both ways. A var so tests can
// shorten it.
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
	// pingLost is set when the transport closes the connection over an
	// unanswered ping, before x/net fails the connection's streams.
	pingLost atomic.Bool
	// pool holds the connection's x/net ClientConn, which pings go through.
	pool *onePool
	ka   keepAlive
	// checkMu guards checkArmed and checkTimer, which runs checkUnanswered
	// while a tunnel's write has had nothing read after it.
	checkMu    sync.Mutex
	checkArmed bool
	checkTimer *time.Timer
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
	// unanswered is when a tunnel first wrote something that nothing has
	// been read since, in Unix nanoseconds, or zero once something has.
	unanswered atomic.Int64
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
		c.unanswered.Store(0)
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

// keepAlive is how long a transport lets a tunnel's write go with nothing
// read on the connection before it pings it, and how long it waits for the
// reply. A zero or negative interval means no pings.
type keepAlive struct {
	interval, timeout time.Duration
}

func newH2Transport(tlsConn net.Conn, serverAddr string, maxStreams int, win receiveWindows, ka keepAlive) (*h2Transport, error) {
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
	// through ConfigureTransports. Its connection pool is replaced by onePool,
	// which holds this one connection and refuses where x/net's own pool
	// would dial another.
	h2t, err := http2.ConfigureTransports(&http.Transport{HTTP2: &http.HTTP2Config{
		MaxReceiveBufferPerStream:     win.perStream,
		MaxReceiveBufferPerConnection: win.perConn,
	}})
	if err != nil {
		return nil, err
	}
	pool := &onePool{h2t: h2t, conn: conn}
	h2t.ConnPool = pool
	h2t.AllowHTTP = false
	h2t.DisableCompression = true
	h2t.StrictMaxConcurrentStreams = true
	// No ReadIdleTimeout: x/net would ping every connection that reads
	// nothing for that long, quiet tunnels and idle pooled connections
	// alike, for as long as they stay open. On a phone that keeps the radio
	// awake, and a small exchange at a fixed interval on an otherwise silent
	// connection is easy to spot. The transport pings only when a tunnel's
	// write has gone unanswered (see checkUnanswered). A dead idle connection
	// is found by the next CONNECT, which connectAnswerTimeout bounds.

	t := &h2Transport{
		conn:        conn,
		h2Roundtrip: h2t,
		serverAddr:  serverAddr,
		localAddr:   tlsConn.LocalAddr(),
		remoteAddr:  tlsConn.RemoteAddr(),
		maxStreams:  maxStreams,
		id:          transportIDs.Add(1),
		created:     time.Now(),
		pool:        pool,
		ka:          ka,
	}
	t.idleSince.Store(time.Now().UnixNano())

	return t, nil
}

// onePool is x/net's connection pool for a transport's one connection. It
// hands out the connection while x/net would still open streams on it, and
// otherwise refuses with errSecondDial, where x/net's own pool would dial a
// second: that would get this same connection back and write a new preface
// into the middle of its frames. Holding the ClientConn is also what lets
// the transport ping it.
type onePool struct {
	h2t  *http2.Transport
	conn net.Conn

	mu sync.Mutex
	cc *http2.ClientConn
	// err is NewClientConn's, if it failed.
	err error
}

func (p *onePool) GetClientConn(req *http.Request, addr string) (*http2.ClientConn, error) {
	p.mu.Lock()
	if p.cc == nil && p.err == nil {
		p.cc, p.err = p.h2t.NewClientConn(p.conn)
	}
	cc, err := p.cc, p.err
	p.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if !cc.ReserveNewRequest() {
		return nil, errSecondDial
	}
	return cc, nil
}

// MarkDead does nothing: a dead ClientConn refuses ReserveNewRequest.
func (p *onePool) MarkDead(*http2.ClientConn) {}

// clientConn returns the connection's ClientConn, or nil before the first
// CONNECT has created it.
func (p *onePool) clientConn() *http2.ClientConn {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cc
}

// noteWrite records that a tunnel wrote to the connection, and arms
// checkUnanswered if it isn't already waiting on an earlier write.
func (t *h2Transport) noteWrite() {
	if t.ka.interval <= 0 || !t.conn.unanswered.CompareAndSwap(0, time.Now().UnixNano()) {
		return
	}
	t.checkMu.Lock()
	defer t.checkMu.Unlock()
	t.armCheckLocked(t.ka.interval)
}

// armCheckLocked runs checkUnanswered after d, unless it's already due.
// checkMu must be held.
func (t *h2Transport) armCheckLocked(d time.Duration) {
	if t.checkArmed {
		return
	}
	t.checkArmed = true
	if t.checkTimer == nil {
		t.checkTimer = time.AfterFunc(d, t.checkUnanswered)
	} else {
		t.checkTimer.Reset(d)
	}
}

// checkUnanswered pings the connection if a tunnel's write has had nothing
// read after it for the keepalive interval, and closes the connection if the
// reply doesn't come within the keepalive timeout. Pinging only then,
// rather than on a clock, costs nothing on a quiet connection: the radio is
// already awake for the write, and an idle connection sends nothing. It
// finds a connection a network dropped silently when a tunnel needs it,
// instead of when TCP gives up on its unacknowledged data, minutes later.
func (t *h2Transport) checkUnanswered() {
	t.checkMu.Lock()
	since := t.conn.unanswered.Load()
	if since == 0 || t.isClosed() {
		t.checkArmed = false
		t.checkMu.Unlock()
		return
	}
	if wait := t.ka.interval - time.Since(time.Unix(0, since)); wait > 0 {
		t.checkTimer.Reset(wait)
		t.checkMu.Unlock()
		return
	}
	// Still armed while the ping runs, so writes meanwhile don't start a
	// second one.
	t.checkMu.Unlock()

	if cc := t.pool.clientConn(); cc != nil {
		ctx, cancel := context.WithTimeout(context.Background(), t.ka.timeout)
		err := cc.Ping(ctx)
		cancel()
		if err != nil && !t.isClosed() {
			t.pingLost.Store(true)
			t.closeWithReason("ping unanswered")
			return
		}
	}

	t.checkMu.Lock()
	defer t.checkMu.Unlock()
	t.checkArmed = false
	// The reply cleared unanswered; a write since then sets it again.
	if t.conn.unanswered.Load() != 0 && !t.isClosed() {
		t.armCheckLocked(t.ka.interval)
	}
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
	// The watcher abandons the CONNECT if the transport goes deaf, and starts
	// its answer clock once shaping is over. The clock claims the CONNECT as
	// the answer would, so one answered or given up on by its caller as it
	// runs out leaves the transport be.
	answerTimeout := connectAnswerTimeout
	answerDone := make(chan struct{})
	go func() {
		shaped := t.shapingDone()
		var expired <-chan time.Time
		for {
			select {
			case <-shaped:
				shaped = nil
				timer := time.NewTimer(answerTimeout)
				defer timer.Stop()
				expired = timer.C
			case <-expired:
				if ctx.Err() == nil && answer.CompareAndSwap(waiting, abandoned) {
					t.markDeaf(answerTimeout)
					tunnelCancel()
				}
				return
			case <-t.deafSignal():
				if answer.CompareAndSwap(waiting, abandoned) {
					tunnelCancel()
				}
				return
			case <-answerDone:
				return
			}
		}
	}()
	settle := func() bool {
		close(answerDone)
		return answer.CompareAndSwap(waiting, answered)
	}

	start := time.Now()
	readBefore := t.conn.bytesRead.Load()
	resp, err := t.h2Roundtrip.RoundTrip(req)
	if !settle() {
		// Abandoned as deaf. The transport's live tunnels carry on, but the
		// retry must not take it again: wait until it's retired, which
		// markDeaf does before closing the deaf signal, since the timer
		// claims the CONNECT before markDeaf runs and a second timer's
		// markDeaf returns while the first is still retiring it.
		<-t.deafSignal()
		stop()
		tunnelCancel()
		pw.Close()
		if err == nil {
			// An answer that came too late. Closing its body can write to
			// the deaf connection and block, so not on the retry's path.
			go resp.Body.Close()
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
	err = t.markPingLost(err)
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
	if errors.Is(err, net.ErrClosed) ||
		errors.Is(err, errSecondDial) ||
		errors.Is(err, errPingLost) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	for _, errno := range fatalErrnos {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// markPingLost wraps err in errPingLost if the connection lost a ping. A
// stream reset is about that stream alone, so it's left as it is even then.
func (t *h2Transport) markPingLost(err error) error {
	if err == nil || !t.pingLost.Load() || errors.As(err, new(http2.StreamError)) {
		return err
	}
	return fmt.Errorf("%w: %w", errPingLost, err)
}

// tryReserve takes a stream slot if the transport has one, atomically, so
// callers choosing a transport at once can't overbook it.
func (t *h2Transport) tryReserve() bool {
	for {
		n := t.activeStreams.Load()
		if t.retired.Load() || t.conn.closed.Load() || int(n) >= t.maxStreams {
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

// shapingActive reports whether the transport's connection-start shaping
// schedule is still running.
func (t *h2Transport) shapingActive() bool {
	sc, ok := t.conn.Conn.(*shapedConn)
	return ok && sc.shapingActive()
}

// closedChan is an already-closed channel.
var closedChan = func() chan struct{} { c := make(chan struct{}); close(c); return c }()

// shapingDone returns a channel closed once the transport's connection-start
// shaping is over, at once for a connection that isn't shaped.
func (t *h2Transport) shapingDone() <-chan struct{} {
	if sc, ok := t.conn.Conn.(*shapedConn); ok {
		return sc.shapingDone()
	}
	return closedChan
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
	if len(b) > 0 {
		s.transport.noteWrite()
	}
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
