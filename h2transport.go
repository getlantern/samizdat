package samizdat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/net/http2"
)

// errSecondDial is what h2Transport's x/net Transport gets if it tries to dial
// a second connection; see newH2Transport.
var errSecondDial = errors.New("samizdat: HTTP/2 transport has only one connection")

// h2Transport manages a single TLS+HTTP/2 connection to the server and
// multiplexes CONNECT tunnels over it as separate H2 streams.
type h2Transport struct {
	tlsConn     net.Conn
	h2Roundtrip http.RoundTripper
	serverAddr  string
	localAddr   net.Addr
	remoteAddr  net.Addr
	shaper      *Shaper

	mu            sync.Mutex
	activeStreams atomic.Int32
	// retired is set when x/net's Transport stops using the connection for
	// new streams (see errSecondDial). The pool stops handing the transport
	// out, and it closes once its last stream ends.
	retired atomic.Bool
	// idleSince is when a stream last closed, in Unix nanoseconds, or when
	// the transport was created if no stream has.
	idleSince  atomic.Int64
	maxStreams int
	closed     bool
}

// newH2Transport creates an HTTP/2 transport over an existing TLS connection.
func newH2Transport(tlsConn net.Conn, serverAddr string, maxStreams int, shaper *Shaper) (*h2Transport, error) {
	// Create HTTP/2 client transport over the existing TLS connection.
	// The transport must never dial a second connection: it would get this
	// same one back and write a new preface into the middle of the first
	// connection's frames, corrupting every stream on it. x/net dials again
	// when it thinks the connection is full (it assumes 100 streams until the
	// server's SETTINGS arrive), so StrictMaxConcurrentStreams makes it wait
	// for a stream slot instead, and any later dial is refused.
	var dialed atomic.Bool
	h2t := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			if dialed.Swap(true) {
				return nil, errSecondDial
			}
			return tlsConn, nil
		},
		AllowHTTP:                  false,
		DisableCompression:         true,
		StrictMaxConcurrentStreams: true,
	}

	t := &h2Transport{
		tlsConn:     tlsConn,
		h2Roundtrip: h2t,
		serverAddr:  serverAddr,
		localAddr:   tlsConn.LocalAddr(),
		remoteAddr:  tlsConn.RemoteAddr(),
		maxStreams:  maxStreams,
		shaper:      shaper,
	}
	t.idleSince.Store(time.Now().UnixNano())

	return t, nil
}

// openTunnel issues an HTTP/2 CONNECT request to open a tunnel to the
// destination through the proxy server. Returns a net.Conn backed by the
// H2 stream.
func (t *h2Transport) openTunnel(ctx context.Context, destination string) (net.Conn, error) {
	t.activeStreams.Add(1)
	return t.openReserved(ctx, destination)
}

// openReserved is openTunnel for a stream slot already reserved, by
// tryReserve or the pool creating the transport. The slot is released on
// every path that doesn't produce a tunnel.
func (t *h2Transport) openReserved(ctx context.Context, destination string) (net.Conn, error) {
	// The stream has counted since its slot was reserved, not from the
	// CONNECT's response, so a transport retired meanwhile isn't closed
	// under a CONNECT in flight.
	opened := false
	defer func() {
		if !opened {
			t.releaseStream()
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

	req, err := http.NewRequestWithContext(tunnelCtx, http.MethodConnect, "https://"+t.serverAddr, pr)
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		return nil, fmt.Errorf("creating CONNECT request: %w", err)
	}
	req.Host = destination
	// Standard HTTP/2 CONNECT uses the :authority pseudo-header which is set from Host

	resp, err := t.h2Roundtrip.RoundTrip(req)
	if err != nil {
		stop()
		tunnelCancel()
		pw.Close()
		// This transport wraps a single, non-redialable conn (see
		// newH2Transport's DialTLSContext). A conn-fatal error poisons every
		// subsequent RoundTrip, so retire the transport here; otherwise the
		// pool keeps handing back the dead transport on each getTransport
		// until a later cleanup tick, producing sustained error bursts.
		switch {
		case errors.Is(err, errSecondDial):
			// The connection can't take new streams (a GOAWAY, or stream
			// IDs used up) but may still carry live tunnels; keep them.
			t.retire()
		case connFatal(err):
			t.close()
		}
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, err)
	}

	// Detach: stop propagating caller's context cancellation into the
	// H2 stream now that the tunnel is established.
	stop()

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
		t.shaper,
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
		errors.Is(err, errSecondDial) ||
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// hasCapacity returns true if the transport can accept more streams.
func (t *h2Transport) hasCapacity() bool {
	return !t.retired.Load() && int(t.activeStreams.Load()) < t.maxStreams
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

// releaseStream ends one of the transport's streams, open or still opening,
// and closes a retired transport once none is left.
func (t *h2Transport) releaseStream() {
	// The timestamp is stored before the count can reach zero, so cleanup
	// never sees an idle transport with a stale one.
	t.idleSince.Store(time.Now().UnixNano())
	if t.activeStreams.Add(-1) == 0 && t.retired.Load() {
		t.close()
	}
}

// retire stops the transport taking new streams and closes it once the ones
// it carries, including any still opening, have ended.
func (t *h2Transport) retire() {
	t.retired.Store(true)
	if t.streamCount() == 0 {
		t.close()
	}
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
	return t.tlsConn.Close()
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
