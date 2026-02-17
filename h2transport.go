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

	"golang.org/x/net/http2"
)

// h2Transport manages a single TLS+HTTP/2 connection to the server and
// multiplexes CONNECT tunnels over it as separate H2 streams.
type h2Transport struct {
	tlsConn    net.Conn
	h2Client   *http.Client
	h2Roundtrip http.RoundTripper
	serverAddr string
	localAddr  net.Addr
	remoteAddr net.Addr
	shaper     *Shaper

	mu           sync.Mutex
	activeStreams atomic.Int32
	maxStreams    int
	closed       bool
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
		maxStreams:   maxStreams,
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

	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+t.serverAddr, pr)
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("creating CONNECT request: %w", err)
	}
	req.Host = destination
	// Standard HTTP/2 CONNECT uses the :authority pseudo-header which is set from Host

	resp, err := t.h2Roundtrip.RoundTrip(req)
	if err != nil {
		pw.Close()
		return nil, fmt.Errorf("CONNECT to %s: %w", destination, err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		pw.Close()
		return nil, fmt.Errorf("CONNECT to %s returned status %d", destination, resp.StatusCode)
	}

	t.activeStreams.Add(1)

	// Create a ReadWriteCloser that reads from the response body and writes to the pipe
	rwc := &h2StreamRWC{
		reader:    resp.Body,
		writer:    pw,
		transport: t,
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
	reader    io.ReadCloser
	writer    io.WriteCloser
	transport *h2Transport
	once      sync.Once
}

func (s *h2StreamRWC) Read(b []byte) (int, error) {
	return s.reader.Read(b)
}

func (s *h2StreamRWC) Write(b []byte) (int, error) {
	return s.writer.Write(b)
}

func (s *h2StreamRWC) Close() error {
	var errs []error
	s.once.Do(func() {
		s.transport.activeStreams.Add(-1)
		if err := s.writer.Close(); err != nil {
			errs = append(errs, err)
		}
		if err := s.reader.Close(); err != nil {
			errs = append(errs, err)
		}
	})
	return errors.Join(errs...)
}
