package samizdat

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"sync"

	utls "github.com/refraction-networking/utls"
)

// Client dials connections through a Samizdat server. Multiple calls to
// DialContext share the same underlying TLS+H2 connection via multiplexing.
type Client struct {
	config ClientConfig
	pool   *connPool
	shaper *Shaper
	mu     sync.Mutex
	closed bool
}

// NewClient creates a new Samizdat client.
func NewClient(config ClientConfig) (*Client, error) {
	config.applyDefaults()

	if len(config.PublicKey) != 32 {
		return nil, fmt.Errorf("PublicKey must be exactly 32 bytes, got %d", len(config.PublicKey))
	}
	if config.ServerAddr == "" {
		return nil, fmt.Errorf("ServerAddr is required")
	}
	if config.ServerName == "" {
		return nil, fmt.Errorf("ServerName is required")
	}

	c := &Client{
		config: config,
	}

	// Create shaper based on config
	c.shaper = NewShaper(
		config.Padding,
		config.Jitter,
		config.MaxJitterMs,
		config.DataThreshold,
		config.PaddingProfile,
	)

	// Create connection pool
	c.pool = newConnPool(config.MaxStreamsPerConn, config.IdleTimeout, c.createTransport)

	return c, nil
}

// DialContext opens a proxied connection to the destination through the server.
// Multiple calls share the same underlying TLS+H2 connection via multiplexing.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil, fmt.Errorf("client is closed")
	}
	c.mu.Unlock()

	// Get an H2 transport with available capacity
	transport, err := c.pool.getTransport(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting transport: %w", err)
	}

	// Open a CONNECT tunnel through the H2 connection
	conn, err := transport.openTunnel(ctx, address)
	if err != nil {
		return nil, fmt.Errorf("opening tunnel to %s: %w", address, err)
	}

	return conn, nil
}

// Close shuts down all connections.
func (c *Client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	return c.pool.close()
}

// createTransport creates a new TLS+H2 connection to the server with
// Reality-style auth embedded in the ClientHello.
func (c *Client) createTransport(ctx context.Context) (*h2Transport, error) {
	// Dial TCP connection
	var tcpConn net.Conn
	var err error

	if c.config.Dialer != nil {
		tcpConn, err = c.config.Dialer(ctx, "tcp", c.config.ServerAddr)
	} else {
		dialer := &net.Dialer{Timeout: c.config.ConnectTimeout}
		tcpConn, err = dialer.DialContext(ctx, "tcp", c.config.ServerAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("TCP dial to %s: %w", c.config.ServerAddr, err)
	}

	// Wrap in fragmenter for Geneva-style TCP fragmentation
	var conn net.Conn = tcpConn
	if c.config.TCPFragmentation {
		conn = NewFragmenter(tcpConn, true)
	}

	// Create uTLS connection with Chrome fingerprint
	tlsConfig := &utls.Config{
		ServerName:         c.config.ServerName,
		InsecureSkipVerify: true, // We verify via Reality auth, not PKI
		NextProtos:         []string{"h2"},
	}

	var helloID utls.ClientHelloID
	switch c.config.Fingerprint {
	case "firefox":
		helloID = utls.HelloFirefox_Auto
	case "safari":
		helloID = utls.HelloSafari_Auto
	default:
		helloID = utls.HelloChrome_Auto
	}

	uConn := utls.UClient(conn, tlsConfig, helloID)

	// Build auth-embedded SessionID using PSK derived from server public key
	sessionID, err := BuildSessionID(c.config.PublicKey, c.config.ShortID)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("building session ID: %w", err)
	}

	// Apply the SessionID to the ClientHello
	if err := c.applyAuthToClientHello(uConn, sessionID[:]); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("applying auth: %w", err)
	}

	// Perform TLS handshake
	if err := uConn.HandshakeContext(ctx); err != nil {
		uConn.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}

	// Verify h2 was negotiated
	state := uConn.ConnectionState()
	if state.NegotiatedProtocol != "h2" {
		uConn.Close()
		return nil, fmt.Errorf("expected h2, got %q", state.NegotiatedProtocol)
	}

	// Create H2 transport over the TLS connection
	// We need to wrap uConn as a standard net.Conn for the http2 transport.
	// The utls.UConn already implements net.Conn.
	transport, err := newH2Transport(uConn, c.config.ServerAddr, c.config.MaxStreamsPerConn, c.shaper)
	if err != nil {
		uConn.Close()
		return nil, fmt.Errorf("creating H2 transport: %w", err)
	}

	return transport, nil
}

// applyAuthToClientHello modifies the uTLS ClientHello to embed the auth
// SessionID. It uses BuildHandshakeState + direct SessionId mutation +
// MarshalClientHello to ensure the SessionID is actually used in the wire format.
func (c *Client) applyAuthToClientHello(uConn *utls.UConn, sessionID []byte) error {
	// Build the handshake state (generates the ClientHello internal structure)
	if err := uConn.BuildHandshakeState(); err != nil {
		return fmt.Errorf("building handshake state: %w", err)
	}

	// Directly set the SessionId in the generated ClientHello message
	uConn.HandshakeState.Hello.SessionId = make([]byte, len(sessionID))
	copy(uConn.HandshakeState.Hello.SessionId, sessionID)

	// Re-marshal the ClientHello with our modified SessionId
	if err := uConn.MarshalClientHello(); err != nil {
		return fmt.Errorf("marshaling client hello: %w", err)
	}

	return nil
}

// tlsConnWrapper wraps utls.UConn to satisfy interfaces that expect
// crypto/tls.Conn methods (e.g., http2.Transport).
type tlsConnWrapper struct {
	*utls.UConn
}

func (w *tlsConnWrapper) ConnectionState() tls.ConnectionState {
	state := w.UConn.ConnectionState()
	return tls.ConnectionState{
		Version:            state.Version,
		HandshakeComplete:  state.HandshakeComplete,
		NegotiatedProtocol: state.NegotiatedProtocol,
		ServerName:         state.ServerName,
	}
}
