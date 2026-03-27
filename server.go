package samizdat

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"
)

// ErrServerClosed is the cause set on the server's context when Close is called.
var ErrServerClosed = errors.New("server closed")

// Server accepts Samizdat connections, authenticates them via Reality-style
// auth in the TLS ClientHello, and proxies authenticated HTTP/2 CONNECT
// tunnels. Non-authenticated connections are transparently proxied to the
// masquerade domain at the TCP level.
type Server struct {
	config       ServerConfig
	serverPubKey []byte // derived from config.PrivateKey
	listener     net.Listener
	masquerade   *Masquerade
	ctx          context.Context
	cancel       context.CancelCauseFunc
	wg           sync.WaitGroup
}

// NewServer creates a new Samizdat server.
func NewServer(config ServerConfig) (*Server, error) {
	config.applyDefaults()

	if len(config.PrivateKey) != 32 {
		return nil, fmt.Errorf("PrivateKey must be exactly 32 bytes, got %d", len(config.PrivateKey))
	}
	if len(config.ShortIDs) == 0 {
		return nil, fmt.Errorf("at least one ShortID is required")
	}
	if config.Handler == nil {
		return nil, fmt.Errorf("Handler is required")
	}

	// Derive server public key from private key
	_, serverPubKey, err := derivePublicKey(config.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("deriving server public key: %w", err)
	}

	ctx, cancel := context.WithCancelCause(context.Background())

	s := &Server{
		config:       config,
		serverPubKey: serverPubKey,
		ctx:          ctx,
		cancel:       cancel,
	}

	// Set up masquerade if configured
	if config.MasqueradeDomain != "" {
		s.masquerade = NewMasquerade(
			config.MasqueradeDomain,
			config.MasqueradeAddr,
			config.MasqueradeIdleTimeout,
			config.MasqueradeMaxDuration,
		)
	}

	return s, nil
}

// ListenAndServe creates a TCP listener on the configured ListenAddr and
// calls Serve. ListenAddr must be set in the ServerConfig.
func (s *Server) ListenAndServe() error {
	if s.config.ListenAddr == "" {
		return fmt.Errorf("ListenAddr is required")
	}
	ln, err := net.Listen("tcp", s.config.ListenAddr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", s.config.ListenAddr, err)
	}
	return s.Serve(ln)
}

// Serve accepts connections on the given listener. This is useful when the
// caller manages the listener (e.g. sing-box's listener.Listener).
func (s *Server) Serve(ln net.Listener) error {
	s.listener = ln

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return nil
			default:
				return fmt.Errorf("accepting connection: %w", err)
			}
		}

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handleConnection(conn)
		}()
	}
}

// Close shuts down the server.
func (s *Server) Close() error {
	s.cancel(ErrServerClosed)
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	s.wg.Wait()
	return err
}

// Addr returns the server's listen address, or nil if not listening.
func (s *Server) Addr() net.Addr {
	if s.listener != nil {
		return s.listener.Addr()
	}
	return nil
}

// handleConnection processes a new TCP connection:
// 1. Read the ClientHello (buffer raw bytes)
// 2. Attempt Samizdat auth verification
// 3. If auth passes: complete TLS handshake, enter H2 proxy mode
// 4. If auth fails: masquerade (forward to real domain)
func (s *Server) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set initial read deadline for the ClientHello
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read and buffer the TLS record containing the ClientHello
	clientHelloRecord, handshakeMsg, err := readClientHelloRecord(conn)
	if err != nil {
		return
	}

	// Reset deadline
	conn.SetReadDeadline(time.Time{})

	// Extract the session ID from the ClientHello
	sessionID, err := ExtractSessionID(handshakeMsg)
	if err != nil {
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	// Verify Samizdat auth using PSK derived from server public key
	_, authenticated, err := VerifySessionID(sessionID, s.serverPubKey, s.config.ShortIDs)
	if err != nil || !authenticated {
		// Auth failed — enter masquerade mode
		s.doMasquerade(conn, clientHelloRecord)
		return
	}

	// Auth passed — complete TLS handshake and enter H2 proxy mode
	s.handleAuthenticated(conn, clientHelloRecord)
}

// doMasquerade forwards the connection to the real masquerade domain.
func (s *Server) doMasquerade(conn net.Conn, clientHelloRecord []byte) {
	if s.masquerade == nil {
		// No masquerade configured — just close
		return
	}
	s.masquerade.ProxyConnection(conn, clientHelloRecord)
}

// handleAuthenticated completes the TLS handshake with the authenticated
// client and serves HTTP/2 CONNECT requests.
func (s *Server) handleAuthenticated(conn net.Conn, clientHelloRecord []byte) {
	// Create a connection that replays the ClientHello record first,
	// then reads from the real connection
	replayConn := newReplayConn(conn, clientHelloRecord)

	// Load TLS certificate
	cert, err := tls.X509KeyPair(s.config.CertPEM, s.config.KeyPEM)
	if err != nil {
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS13,
	}

	// Complete TLS handshake
	tlsConn := tls.Server(replayConn, tlsConfig)
	if err := tlsConn.HandshakeContext(s.ctx); err != nil {
		tlsConn.Close()
		return
	}

	// Verify h2 was negotiated
	if tlsConn.ConnectionState().NegotiatedProtocol != "h2" {
		tlsConn.Close()
		return
	}

	// Serve HTTP/2 with CONNECT handler
	s.serveH2(tlsConn)
}

// serveH2 serves HTTP/2 over the authenticated TLS connection, handling
// CONNECT requests to establish proxy tunnels.
func (s *Server) serveH2(tlsConn net.Conn) {
	h2Server := &http2.Server{
		MaxConcurrentStreams: uint32(s.config.MaxConcurrentStreams),
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// The CONNECT target is in the Host header (or :authority pseudo-header)
		destination := r.Host
		if destination == "" {
			http.Error(w, "No destination", http.StatusBadRequest)
			return
		}

		log.Printf("[samizdat] CONNECT %s: handler started", destination)

		// Hijack the connection to get raw bidirectional stream
		w.WriteHeader(http.StatusOK)
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush()
		}

		// Keep a direct reference to r.Body for draining after the handler
		// returns. serverStreamConn.Close() will close r.Body to unblock
		// in-flight reads, but we still need to drain any remaining data
		// to ensure the client sends END_STREAM.
		body := r.Body

		// Create a net.Conn from the H2 stream
		streamConn := &serverStreamConn{
			reader: body,
			writer: flushWriter{w: w, flusher: flusher},
		}

		s.config.Handler(r.Context(), streamConn, destination)

		// Mark the stream as closed and wait for any in-flight writes to
		// finish. This prevents the "Write called after Handler finished"
		// panic — sing-box may have a lingering copy goroutine that hasn't
		// observed the connection closure yet.
		streamConn.shutdown()

		log.Printf("[samizdat] CONNECT %s: handler returned, starting drain", destination)

		// Drain r.Body to ensure the client sends END_STREAM before the
		// handler returns. Without this, if the stream is still in stateOpen
		// (client hasn't sent END_STREAM), the H2 server sends RST_STREAM
		// which can cause the client to lose in-flight response data.
		// Use a timeout to avoid blocking forever if the client disappears.
		drainDone := make(chan struct{})
		go func() {
			n, err := io.Copy(io.Discard, body)
			log.Printf("[samizdat] CONNECT %s: drain finished, n=%d, err=%v", destination, n, err)
			close(drainDone)
		}()
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-drainDone:
			timer.Stop()
			log.Printf("[samizdat] CONNECT %s: drain completed, handler returning cleanly", destination)
		case <-timer.C:
			log.Printf("[samizdat] CONNECT %s: drain timeout, closing body", destination)
			// Timeout: close the body to unblock the drain goroutine.
			body.Close()
			<-drainDone
		}
	})

	// Serve directly using the http2.Server
	log.Printf("[samizdat] serveH2: starting ServeConn")
	h2Server.ServeConn(tlsConn, &http2.ServeConnOpts{
		Handler: handler,
	})
	log.Printf("[samizdat] serveH2: ServeConn returned")
}

// readClientHelloRecord reads a complete TLS record from the connection.
// Returns the full TLS record (header + payload) and the handshake message within it.
// Reads directly from the connection (no buffering) to avoid losing data.
func readClientHelloRecord(conn net.Conn) ([]byte, []byte, error) {
	// TLS record header: content_type(1) + version(2) + length(2)
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, nil, fmt.Errorf("reading TLS record header: %w", err)
	}

	// Verify it's a handshake record (type 22)
	if header[0] != 22 {
		return nil, nil, fmt.Errorf("expected handshake record (type 22), got type %d", header[0])
	}

	recordLen := int(header[3])<<8 | int(header[4])
	if recordLen > 16384 {
		return nil, nil, fmt.Errorf("TLS record too large: %d", recordLen)
	}

	payload := make([]byte, recordLen)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, nil, fmt.Errorf("reading TLS record payload: %w", err)
	}

	// Full record = header + payload
	record := make([]byte, 5+recordLen)
	copy(record[:5], header)
	copy(record[5:], payload)

	return record, payload, nil
}

// replayConn wraps a net.Conn and prepends buffered data before reading
// from the real connection. This is used to "replay" the ClientHello
// to the Go TLS stack after we've already read it for auth verification.
type replayConn struct {
	net.Conn
	buf    []byte
	offset int
}

func newReplayConn(conn net.Conn, data []byte) *replayConn {
	return &replayConn{
		Conn: conn,
		buf:  data,
	}
}

func (rc *replayConn) Read(b []byte) (int, error) {
	if rc.offset < len(rc.buf) {
		n := copy(b, rc.buf[rc.offset:])
		rc.offset += n
		return n, nil
	}
	return rc.Conn.Read(b)
}

// serverStreamConn wraps an HTTP/2 stream (request body + response writer)
// as a net.Conn for use by the ConnHandler.
type serverStreamConn struct {
	reader io.ReadCloser
	writer flushWriter
	closed atomic.Bool
	mu     sync.Mutex // guards writes; shutdown() takes this to wait for in-flight writes
}

func (sc *serverStreamConn) Read(b []byte) (int, error) {
	if sc.closed.Load() {
		return 0, net.ErrClosed
	}
	return sc.reader.Read(b)
}

func (sc *serverStreamConn) Write(b []byte) (n int, err error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if sc.closed.Load() {
		return 0, net.ErrClosed
	}
	// Recover from "Write called after Handler finished" panics that occur
	// when the HTTP/2 handler returns while a sing-box copy goroutine is
	// still writing. The mutex + shutdown() prevents new races, but
	// recover() is defense-in-depth.
	defer func() {
		if r := recover(); r != nil {
			s, ok := r.(string)
			if ok && s == "Write called after Handler finished" {
				log.Printf("[samizdat] recovered expected panic in Write: %v", r)
				sc.closed.Store(true)
				n = 0
				err = net.ErrClosed
				return
			}
			// Unexpected panic — log and re-panic so real bugs aren't masked.
			log.Printf("[samizdat] unexpected panic in Write: %v", r)
			panic(r)
		}
	}()
	n, err = sc.writer.Write(b)
	if err == nil {
		sc.writer.Flush()
	}
	return n, err
}

func (sc *serverStreamConn) Close() error {
	sc.closed.Store(true)
	// Do NOT close r.Body here. The HTTP handler holds its own reference
	// to the body and will drain it after the proxy handler returns, waiting
	// for the client to send END_STREAM. Closing it here would defeat the
	// drain and cause the H2 server to send RST_STREAM.
	// The upload goroutine exits due to a write error (not a blocked read),
	// so there are no in-flight reads on r.Body to unblock.
	return nil
}

// shutdown marks the conn as closed and waits for any in-flight Write to
// finish. The HTTP handler must call this before returning so that no
// goroutine can write to the ResponseWriter after it becomes invalid.
func (sc *serverStreamConn) shutdown() {
	sc.mu.Lock()
	sc.closed.Store(true)
	sc.mu.Unlock()
}

// CloseWrite signals that no more data will be written. For the server-side
// H2 stream this is a no-op — the response writer stays open until the HTTP
// handler returns. Implementing this prevents sing-box's bidirectional copy
// from calling Close() (which kills the entire stream) when one copy direction
// finishes.
func (sc *serverStreamConn) CloseWrite() error {
	return nil
}

func (sc *serverStreamConn) LocalAddr() net.Addr  { return &streamAddr{"tcp", "server"} }
func (sc *serverStreamConn) RemoteAddr() net.Addr { return &streamAddr{"tcp", "client"} }
func (sc *serverStreamConn) SetDeadline(t time.Time) error      { return nil }
func (sc *serverStreamConn) SetReadDeadline(t time.Time) error   { return nil }
func (sc *serverStreamConn) SetWriteDeadline(t time.Time) error  { return nil }

// flushWriter wraps an http.ResponseWriter with a Flusher for immediate writes.
type flushWriter struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

func (fw flushWriter) Write(b []byte) (int, error) {
	return fw.w.Write(b)
}

func (fw flushWriter) Flush() {
	if fw.flusher != nil {
		fw.flusher.Flush()
	}
}

// defaultConnHandler is a simple handler that dials the destination and
// proxies data bidirectionally. Used when no custom handler is provided.
func defaultConnHandler(ctx context.Context, conn net.Conn, destination string) {
	defer conn.Close()

	// Parse destination to ensure it has a port
	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		// Try adding default HTTPS port
		host = destination
		port = "443"
	}
	_ = host

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
	}()

	wg.Wait()
}

// Verify interface compliance
var (
	_ net.Conn = (*serverStreamConn)(nil)
	_ net.Conn = (*replayConn)(nil)
)

