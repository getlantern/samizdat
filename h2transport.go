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
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// errConnUnusable is returned, wrapped, by a CONNECT that failed because its
// connection takes no new streams: after a GOAWAY, with its stream IDs used
// up, or once closed. A new connection can carry it.
var errConnUnusable = errors.New("samizdat: connection takes no new streams")

// Health checks. A connection that goes silent, such as one whose NAT mapping
// a router dropped, gives no sign of it: writes still succeed, and every
// CONNECT on it waits until its caller gives up. So a CONNECT pings its
// connection when it has read nothing for pingIfIdle, as Chrome does before
// reusing an idle session, or when the CONNECT itself has waited
// pingIfSilent without the connection reading anything. A connection that
// answers nothing, its ping included, for pingTimeout is retired, and the
// CONNECTs waiting on it are abandoned for a new connection; it is closed,
// with the tunnels it carries, if it stays silent for closeIfSilent more,
// since a lossy link backing off its retransmissions can be silent that long
// and recover. Pinging only when a CONNECT has reason to doubt the
// connection, rather than on a timer, keeps idle connections from sending
// PINGs in a regular rhythm that Chrome's don't.
var (
	pingIfIdle    = 10 * time.Second
	pingIfSilent  = 2 * time.Second
	pingTimeout   = 5 * time.Second
	closeIfSilent = 15 * time.Second
)

// transportIDs numbers transports for logs.
var transportIDs atomic.Uint64

// discardLogger is the logger of a transport whose client has none.
var discardLogger = slog.New(slog.DiscardHandler)

// h2Transport manages a single TLS+HTTP/2 connection to the server and
// multiplexes CONNECT tunnels over it as separate H2 streams.
type h2Transport struct {
	// conn is the TLS connection, counting what it reads.
	conn        *readTrackingConn
	h2Roundtrip http.RoundTripper
	// cc is h2Roundtrip as a ClientConn, for health checks; nil in tests
	// that supply their own RoundTripper.
	cc         *http2.ClientConn
	serverAddr string
	localAddr  net.Addr
	remoteAddr net.Addr

	mu            sync.Mutex
	activeStreams atomic.Int32
	// retired is set when the connection should take no new streams (see
	// errConnUnusable). The pool stops handing the transport out, and it
	// closes once its last stream ends.
	retired atomic.Bool
	// pinging is set while a health check's ping is outstanding.
	pinging atomic.Bool
	// waiting is cancelled, abandoning the CONNECTs waiting for an answer,
	// when the connection fails a health check; nil in tests that build a
	// transport by hand.
	waiting        context.Context
	abandonWaiting context.CancelFunc
	// idleSince is when a stream last closed, in Unix nanoseconds, or when
	// the transport was created if no stream has.
	idleSince  atomic.Int64
	maxStreams int
	closed     bool

	id     uint64
	logger *slog.Logger
	// created is when the transport was created.
	created time.Time
}

// readTrackingConn records when its connection last read anything, so a
// CONNECT that times out can tell a connection that went silent from one that
// is merely slow to answer.
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
func newH2Transport(tlsConn net.Conn, serverAddr string, maxStreams int) (*h2Transport, error) {
	conn := &readTrackingConn{Conn: tlsConn}

	// The ClientConn is used directly, never through the Transport, which
	// would dial a second connection when it thinks this one is full (it
	// assumes 100 streams until the server's SETTINGS arrive).
	// StrictMaxConcurrentStreams makes a CONNECT wait for a stream slot
	// instead.
	h2t := &http2.Transport{
		AllowHTTP:                  false,
		DisableCompression:         true,
		StrictMaxConcurrentStreams: true,
	}
	cc, err := h2t.NewClientConn(conn)
	if err != nil {
		return nil, err
	}

	t := &h2Transport{
		conn:        conn,
		h2Roundtrip: cc,
		cc:          cc,
		serverAddr:  serverAddr,
		localAddr:   tlsConn.LocalAddr(),
		remoteAddr:  tlsConn.RemoteAddr(),
		maxStreams:  maxStreams,
		id:          transportIDs.Add(1),
		created:     time.Now(),
	}
	t.waiting, t.abandonWaiting = context.WithCancel(context.Background())
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
	stopAbandon := func() bool { return true }
	if t.waiting != nil {
		stopAbandon = context.AfterFunc(t.waiting, func() { tunnelCancel() })
	}

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodConnect, "https://"+t.serverAddr, pr)
	if err != nil {
		stop()
		stopAbandon()
		tunnelCancel()
		pw.Close()
		return nil, fmt.Errorf("creating CONNECT request: %w", err)
	}
	req.Host = destination
	// Standard HTTP/2 CONNECT uses the :authority pseudo-header which is set from Host

	start := time.Now()
	readBefore := t.conn.bytesRead.Load()
	if since := t.sinceRead(start); since >= pingIfIdle {
		t.checkAlive(fmt.Sprintf("reused after %v without a read", since.Round(time.Second)))
	}
	silentCheck := time.AfterFunc(pingIfSilent, func() {
		if t.conn.bytesRead.Load() == readBefore {
			t.checkAlive("CONNECT unanswered for " + pingIfSilent.String())
		}
	})
	resp, err := t.h2Roundtrip.RoundTrip(req)
	silentCheck.Stop()
	if err != nil {
		stop()
		stopAbandon()
		tunnelCancel()
		pw.Close()
		now := time.Now()
		// Nothing read while the CONNECT waited means the connection, not
		// the destination, is what failed to answer.
		silent := t.conn.bytesRead.Load() == readBefore
		t.log().Warn("samizdat CONNECT failed",
			"transport", t.id,
			"error", err,
			"waited", now.Sub(start),
			"since_read", t.sinceRead(now),
			"read_while_waiting", !silent,
			"streams", t.streamCount(),
			"age", now.Sub(t.created))
		// This transport wraps a single, non-redialable conn. A conn-fatal
		// error poisons every subsequent RoundTrip, so retire the transport
		// here; otherwise the pool keeps handing back the dead transport on
		// each getTransport until a later cleanup tick, producing sustained
		// error bursts.
		switch {
		case t.waiting != nil && t.waiting.Err() != nil:
			// A health check abandoned this CONNECT, and retired the
			// transport; the caller can have a new connection.
			if ctx.Err() == nil {
				err = fmt.Errorf("%w: %v", errConnUnusable, err)
			}
		case t.cc != nil && (t.conn.closed.Load() || !t.cc.CanTakeNewRequest()):
			// x/net still reports a connection that closed before its first
			// stream as able to take one, so that request can see why.
			// The connection can't take new streams (a GOAWAY, stream IDs
			// used up, or closed) but may still carry live tunnels; keep
			// them. A caller still waiting can have a new connection.
			t.retireWithReason("connection takes no new streams")
			if ctx.Err() == nil {
				err = fmt.Errorf("%w: %v", errConnUnusable, err)
			}
		case connFatal(err):
			t.closeWithReason("CONNECT failed: " + err.Error())
		case silent && now.Sub(start) >= silentConnectRetire:
			// A caller gave up on a connection that stayed silent the whole
			// time. Stop opening streams on it, so the next CONNECT gets a
			// new connection rather than waiting on this one as well; if
			// it's alive, the streams it carries finish on it.
			t.retireWithReason(fmt.Sprintf("silent for %v during a CONNECT", now.Sub(start).Round(time.Millisecond)))
		}
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, err)
	}

	// Detach: stop propagating caller's context cancellation into the
	// H2 stream now that the tunnel is established. If either already
	// cancelled it, the stream is being reset, and is no tunnel.
	if callerLive, waiting := stop(), stopAbandon(); !callerLive || !waiting {
		resp.Body.Close()
		pw.Close()
		if callerLive {
			return nil, fmt.Errorf("CONNECT to %s: %w", destination, errConnUnusable)
		}
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, ctx.Err())
	}

	if waited := time.Since(start); waited >= slowConnect {
		t.log().Info("samizdat CONNECT slow",
			"transport", t.id,
			"waited", waited,
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
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return false
	}
	return errors.Is(err, net.ErrClosed) ||
		errors.Is(err, errConnUnusable) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// silentConnectRetire is how long a failed CONNECT must have waited, with its
// connection reading nothing, for the transport to be retired. A CONNECT
// cancelled sooner says little about the connection: its caller may simply
// have moved on.
var silentConnectRetire = 5 * time.Second

// slowConnect is how long a CONNECT that succeeds can take before it's logged.
const slowConnect = 3 * time.Second

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
		t.close()
	}
}

// checkAlive pings the connection, unless a ping is already outstanding. If
// neither the ping's answer nor anything else arrives within pingTimeout, it
// retires the transport and abandons the CONNECTs waiting on it, and closes
// the connection if it then stays silent for closeIfSilent. A connection
// still reading is alive, if slow to answer.
func (t *h2Transport) checkAlive(why string) {
	if t.cc == nil || t.pinging.Swap(true) {
		return
	}
	readBefore := t.conn.bytesRead.Load()
	silent := func() bool { return t.conn.bytesRead.Load() == readBefore && !t.isClosed() }
	answerWithin, closeAfter := pingTimeout, closeIfSilent
	go func() {
		defer t.pinging.Store(false)
		ctx, cancel := context.WithTimeout(context.Background(), answerWithin)
		defer cancel()
		err := t.cc.Ping(ctx)
		if err == nil || !silent() {
			return
		}
		t.retireWithReason(fmt.Sprintf("unanswered ping (%s): %v", why, err))
		t.abandonWaiting()
		time.Sleep(closeAfter)
		if silent() {
			t.closeWithReason(fmt.Sprintf("silent for %v after an unanswered ping", answerWithin+closeAfter))
		}
	}()
}

// retireWithReason stops the transport taking new streams, logging why, and
// closes it once the ones it carries, including any still opening, have
// ended.
func (t *h2Transport) retireWithReason(reason string) {
	if !t.retired.Swap(true) && !t.isClosed() {
		t.log().Info("samizdat transport retired", t.logAttrs(reason)...)
	}
	if t.streamCount() == 0 {
		t.close()
	}
}

// closeWithReason closes the transport, logging why.
func (t *h2Transport) closeWithReason(reason string) {
	if !t.isClosed() {
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
	if t.abandonWaiting != nil {
		t.abandonWaiting()
	}

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
