package samizdat

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
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
	mu     sync.Mutex
	closed bool
}

// NewClient creates a new Samizdat client.
// testLegacyClients makes every client a legacy one, sending version 1 auth
// and not shaping, so the tests can run as today's clients against current
// servers. Set from SAMIZDAT_TEST_LEGACY_CLIENTS in tests.
var testLegacyClients bool

func NewClient(config ClientConfig) (*Client, error) {
	config.applyDefaults()
	if testLegacyClients {
		config.DisableShaping = true
		config.LegacyAuth = true
	}

	if len(config.PublicKey) != 32 {
		return nil, fmt.Errorf("PublicKey must be exactly 32 bytes, got %d", len(config.PublicKey))
	}
	if config.ServerAddr == "" {
		return nil, fmt.Errorf("ServerAddr is required")
	}
	if config.ServerName == "" {
		return nil, fmt.Errorf("ServerName is required")
	}
	if n := len(config.ServerCertSPKISHA256); n != 0 && n != sha256.Size {
		return nil, fmt.Errorf("ServerCertSPKISHA256 must be empty or %d bytes, got %d", sha256.Size, n)
	}

	c := &Client{
		config: config,
	}

	// Create connection pool
	c.pool = newConnPool(config.MaxStreamsPerConn, config.IdleTimeout, c.createTransport)

	return c, nil
}

// maxDialAttempts caps DialContext's redials after a conn-fatal failure. Each
// conn-fatal openReserved retires its dead transport, so a retry gets a fresh one;
// the cap bounds the reconnect burst when the server is genuinely unreachable.
const maxDialAttempts = 3

// DialContext opens a proxied connection to the destination through the server.
// Multiple calls share the same underlying TLS+H2 connection via multiplexing.
//
// A network that resets the shared connection can leave a pooled transport dead
// but not yet marked closed; DialContext retries such conn-fatal failures on a
// fresh transport, up to maxDialAttempts, rather than surfacing them.
func (c *Client) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if c.isClosed() {
		return nil, fmt.Errorf("client is closed")
	}

	var err error
	for attempt := 0; attempt < maxDialAttempts; attempt++ {
		// A conn-fatal error can race with caller cancellation; stop before
		// spending another transport on an already-abandoned dial.
		if err = ctx.Err(); err != nil {
			return nil, err
		}

		var transport *h2Transport
		transport, err = c.pool.getTransport(ctx)
		if err != nil {
			return nil, fmt.Errorf("getting transport: %w", err)
		}

		var conn net.Conn
		conn, err = transport.openReserved(ctx, address)
		if err == nil {
			return conn, nil
		}
		// A conn-fatal error retired this transport, so a retry gets a fresh
		// one; any other error is not transport-recoverable.
		if !connFatal(err) {
			break
		}
	}
	return nil, fmt.Errorf("opening tunnel to %s: %w", address, err)
}

// ErrCertPinMismatch is returned, wrapped, when ClientConfig.ServerCertSPKISHA256
// is set and the server's certificate does not match it.
var ErrCertPinMismatch = errors.New("samizdat: server certificate does not match pin")

// SPKISHA256 is the SHA-256 of a DER certificate's SubjectPublicKeyInfo,
// the value ClientConfig.ServerCertSPKISHA256 pins.
func SPKISHA256(certDER []byte) ([32]byte, error) {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(cert.RawSubjectPublicKeyInfo), nil
}

// DialSession dials and authenticates a new connection that is not pooled
// and runs no HTTP/2, for callers that layer their own protocol on it. ALPN
// "h2" has been negotiated on it. The caller owns the connection. When ctx
// has no deadline, ConnectTimeout bounds the dial and handshake. Of the
// ClientConfig options that shape traffic, only TCPFragmentation applies;
// RecordFragmentation and MaxStreamsPerConn belong to the
// pooled HTTP/2 layer DialSession does not use.
func (c *Client) DialSession(ctx context.Context) (net.Conn, error) {
	if c.isClosed() {
		return nil, fmt.Errorf("client is closed")
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.config.ConnectTimeout)
		defer cancel()
	}
	// Return an untyped nil on failure: a nil *utls.UConn in a net.Conn
	// would compare non-nil.
	uConn, err := c.dialConn(ctx)
	if err != nil {
		return nil, err
	}
	return uConn, nil
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
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
	uConn, err := c.dialConn(ctx)
	if err != nil {
		return nil, err
	}

	var conn net.Conn = uConn
	if state := uConn.ConnectionState(); !c.config.DisableShaping && state.Version == utls.VersionTLS13 {
		sched, marker, err := shapingSchedule(state.ExportKeyingMaterial)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("shaping: %w", err)
		}
		conn = newShapedConn(uConn, sched, true, marker, false)
	}

	// Create H2 transport over the TLS connection
	transport, err := newH2Transport(conn, c.config.ServerAddr, c.config.MaxStreamsPerConn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("creating H2 transport: %w", err)
	}

	return transport, nil
}

// dialConn dials the server and completes a TLS handshake with Reality-style
// auth embedded in the ClientHello, returning the connection once ALPN "h2"
// has been negotiated.
func (c *Client) dialConn(ctx context.Context) (*utls.UConn, error) {
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
		// Go's dynamic record sizing grows early records by the payload of
		// one assumed 1208-byte segment each, 1186 bytes under TLS 1.3,
		// which Chrome never does.
		DynamicRecordSizingDisabled: true,
	}
	if pin := c.config.ServerCertSPKISHA256; len(pin) > 0 {
		// InsecureSkipVerify skips only chain verification; this still runs.
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return ErrCertPinMismatch
			}
			got, err := SPKISHA256(rawCerts[0])
			if err != nil || subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return ErrCertPinMismatch
			}
			return nil
		}
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

	if c.config.LegacyAuth {
		sessionID, err := BuildSessionID(c.config.PublicKey, c.config.ShortID)
		if err != nil {
			uConn.Close()
			return nil, fmt.Errorf("building session ID: %w", err)
		}
		if err := c.applyAuthToClientHello(uConn, sessionID[:]); err != nil {
			uConn.Close()
			return nil, fmt.Errorf("applying auth: %w", err)
		}
	} else if err := c.applyAuthV2(uConn); err != nil {
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

	// The Chrome fingerprint's renegotiation_info extension sets
	// Renegotiation on tlsConfig, and while it's set uTLS refuses to export
	// keying material, which shaping needs. TLS 1.3 has no renegotiation, and
	// tlsConfig is this connection's alone.
	if state.Version == utls.VersionTLS13 {
		tlsConfig.Renegotiation = utls.RenegotiateNever
	}

	return uConn, nil
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

// applyAuthV2 builds the ClientHello and puts a version 2 SessionID in it
// (authv2.go), sealed under the shared secret between the client's own
// X25519 key share and the server's key.
func (c *Client) applyAuthV2(uConn *utls.UConn) error {
	if err := uConn.BuildHandshakeState(); err != nil {
		return fmt.Errorf("building handshake state: %w", err)
	}
	hs := &uConn.HandshakeState
	hs.Hello.SessionId = make([]byte, sessionIDLen)
	if err := uConn.MarshalClientHello(); err != nil {
		return fmt.Errorf("marshaling client hello: %w", err)
	}
	raw := hs.Hello.Raw
	// Use the key share the server will: parse the ClientHello as it does
	// and take the private key whose public key it finds.
	ch, err := parseClientHello(raw)
	if err != nil {
		return err
	}
	keys := hs.State13.KeyShareKeys
	var priv *ecdh.PrivateKey
	for _, k := range []*ecdh.PrivateKey{keys.Ecdhe, keys.MlkemEcdhe} {
		if k != nil && k.Curve() == ecdh.X25519() && bytes.Equal(k.PublicKey().Bytes(), ch.x25519) {
			priv = k
			break
		}
	}
	if priv == nil {
		return errors.New("samizdat: the ClientHello has no X25519 key share")
	}
	serverPub, err := ecdh.X25519().NewPublicKey(c.config.PublicKey)
	if err != nil {
		return err
	}
	shared, err := priv.ECDH(serverPub)
	if err != nil {
		return err
	}
	sid, err := sealSessionIDv2(shared, raw, c.config.ShortID, authNow())
	if err != nil {
		return err
	}
	// Written into the marshaled bytes in place, which are what uTLS sends:
	// the SessionID was sealed over exactly these bytes with it zeroed.
	copy(raw[sessionIDOffset:], sid[:])
	hs.Hello.SessionId = sid[:]
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
