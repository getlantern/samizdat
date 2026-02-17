// Package samizdat implements a censorship circumvention protocol that makes
// proxy traffic indistinguishable from a browser visiting a real website over
// HTTP/2. It uses a single TLS layer with Reality-style authentication,
// HTTP/2 CONNECT tunneling, multiplexed streams, Geneva-inspired TCP
// fragmentation, and traffic shaping with padding and timing jitter.
//
// The server acts as a real web server to unauthorized connections by
// transparently proxying them to the masquerade domain at the TCP level.
package samizdat

import (
	"context"
	"net"
	"time"
)

// DialFunc allows injecting a custom TCP dialer for the underlying connection.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// ConnHandler is called for each proxied connection with destination info.
type ConnHandler func(ctx context.Context, conn net.Conn, destination string)

// ClientConfig configures the Samizdat client.
type ClientConfig struct {
	// Server connection
	ServerAddr string // host:port of the Samizdat server
	ServerName string // cover site SNI (e.g. "ok.ru")

	// Authentication
	PublicKey []byte  // server X25519 public key (32 bytes)
	ShortID   [8]byte // pre-shared 8-byte identifier

	// TLS fingerprint
	Fingerprint string // "chrome" (default), "firefox", "safari"

	// Traffic shaping
	Padding        bool   // enable H2 DATA frame padding (default: true)
	Jitter         bool   // enable timing jitter (default: true)
	MaxJitterMs    int    // max jitter in ms (default: 30)
	PaddingProfile string // "chrome", "firefox" (default: "chrome")

	// TCP fragmentation (Geneva-inspired)
	TCPFragmentation    bool // fragment ClientHello across TCP segments (default: true)
	RecordFragmentation bool // fragment inner TLS records across H2 DATA frames (default: true)

	// Connection management
	MaxStreamsPerConn int           // max H2 streams per TCP conn (default: 100)
	IdleTimeout      time.Duration // close idle connections after (default: 5m)
	ConnectTimeout   time.Duration // TCP+TLS connect timeout (default: 15s)

	// Russia-specific evasion
	DataThreshold int // bytes before aggressive padding (default: 14000)

	// Optional: custom dialer for the underlying TCP connection
	Dialer DialFunc
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *ClientConfig) applyDefaults() {
	if c.Fingerprint == "" {
		c.Fingerprint = "chrome"
	}
	if c.MaxJitterMs == 0 {
		c.MaxJitterMs = 30
	}
	if c.PaddingProfile == "" {
		c.PaddingProfile = "chrome"
	}
	if c.MaxStreamsPerConn == 0 {
		c.MaxStreamsPerConn = 100
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 15 * time.Second
	}
	if c.DataThreshold == 0 {
		c.DataThreshold = 14000
	}
}

// ServerConfig configures the Samizdat server.
type ServerConfig struct {
	// Listen address
	ListenAddr string // e.g. ":8443"

	// Authentication
	PrivateKey []byte    // server X25519 private key (32 bytes)
	ShortIDs   [][8]byte // allowed client short IDs

	// TLS certificate (for the real server identity)
	CertPEM []byte
	KeyPEM  []byte

	// Masquerade: TCP-level transparent proxy to real domain when auth fails
	MasqueradeDomain      string        // domain to masquerade as (e.g. "ok.ru")
	MasqueradeAddr        string        // optional IP:port override (default: resolve domain)
	MasqueradeIdleTimeout time.Duration // close after no data (default: 5m)
	MasqueradeMaxDuration time.Duration // absolute max proxy duration (default: 10m)

	// Limits
	MaxConcurrentStreams int // per connection (default: 250)

	// Handler: called for each authenticated proxied connection
	Handler ConnHandler
}

// applyDefaults fills in zero-value fields with sensible defaults.
func (c *ServerConfig) applyDefaults() {
	if c.MasqueradeIdleTimeout == 0 {
		c.MasqueradeIdleTimeout = 5 * time.Minute
	}
	if c.MasqueradeMaxDuration == 0 {
		c.MasqueradeMaxDuration = 10 * time.Minute
	}
	if c.MaxConcurrentStreams == 0 {
		c.MaxConcurrentStreams = 250
	}
}
