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

	"golang.org/x/net/http2"
)

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
	maxStreams    int
	closed        bool
}

// newH2Transport creates an HTTP/2 transport over an existing TLS connection.
func newH2Transport(tlsConn net.Conn, serverAddr string, maxStreams int, shaper *Shaper) (*h2Transport, error) {
	// Create HTTP/2 client transport over the existing TLS connection
	h2t := &http2.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string, cfg *tls.Config) (net.Conn, error) {
			// Return the existing TLS connection — this is called only once
			return tlsConn, nil
		},
		AllowHTTP:          false,
		DisableCompression: true,
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

	return t, nil
}

// openTunnel issues an HTTP/2 CONNECT request to open a tunnel to the
// destination through the proxy server. Returns a net.Conn backed by the
// H2 stream.
func (t *h2Transport) openTunnel(ctx context.Context, destination string) (net.Conn, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil, errors.New("transport closed")
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
		if connFatal(err) {
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

	t.activeStreams.Add(1)

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
		errors.Is(err, io.EOF) ||
		errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.EPIPE)
}

// hasCapacity returns true if the transport can accept more streams.
func (t *h2Transport) hasCapacity() bool {
	return int(t.activeStreams.Load()) < t.maxStreams
}

// streamCount returns the number of active streams.
func (t *h2Transport) streamCount() int {
	return int(t.activeStreams.Load())
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

// Close finalizes the stream. streamConn drains the response body to EOF (or
// force-closes it after a timeout) via its read pump before calling Close, so
// closing the reader here does not abort an in-flight stream with an RST that
// a censor could fingerprint.
func (s *h2StreamRWC) Close() error {
	var closeErr error
	s.once.Do(func() {
		closeErr = s.closeWriter()
		s.reader.Close()
		if s.tunnelCancel != nil {
			s.tunnelCancel()
		}
		s.transport.activeStreams.Add(-1)
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
