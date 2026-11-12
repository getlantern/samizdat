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

// SessionHandler is called once per authenticated connection, in place of
// the built-in HTTP/2 CONNECT server, with the TLS connection (ALPN "h2"
// already negotiated) and the short ID the client authenticated with. The
// connection is closed when it returns.
//
// ctx ends when the session does: when a Read on conn fails other than by
// its deadline expiring (the peer went away), when any Write fails,
// including by its deadline expiring, when conn is closed, when SetShortIDs revokes shortID
// (cause ErrSessionRevoked), or when the server is closed (cause
// ErrServerClosed). A handler should return once ctx is done. Server.Close
// waits for handlers to return, so one that ignores ctx blocks it.
type SessionHandler func(ctx context.Context, conn net.Conn, shortID [8]byte)

// ClientConfig configures the Samizdat client.
type ClientConfig struct {
	// Server connection
	ServerAddr string // host:port of the Samizdat server
	ServerName string // cover site SNI (e.g. "ok.ru")

	// Authentication
	PublicKey []byte  // server X25519 public key (32 bytes)
	ShortID   [8]byte // pre-shared 8-byte identifier

	// ServerCertSPKISHA256, when set, pins the server's certificate: the
	// handshake fails with ErrCertPinMismatch unless the SHA-256 of the leaf
	// certificate's SubjectPublicKeyInfo (see SPKISHA256) equals it. It must
	// be empty or 32 bytes.
	ServerCertSPKISHA256 []byte

	// TLS fingerprint
	Fingerprint string // "chrome" (default), "firefox", "safari"

	// Traffic shaping
	Jitter      bool // enable timing jitter (default: true)
	MaxJitterMs int  // max jitter in ms (default: 30)

	// TCP fragmentation (Geneva-inspired)
	TCPFragmentation    bool // fragment ClientHello across TCP segments (default: true)
	RecordFragmentation bool // fragment inner TLS records across H2 DATA frames (default: true)

	// DisableShaping turns off shaping of the sizes and directions of each
	// connection's first TLS records (see shaping.go), which is on by
	// default. A shaping client needs a server that accepts shaping, as every
	// server does unless ServerConfig.DisableShaping is set; against one that
	// doesn't, the connection fails. The two ends take turns sending those
	// records, so a new connection's first request can take a few round
	// trips longer than without shaping; requests on a connection already
	// open don't.
	DisableShaping bool

	// LegacyAuth sends the version 1 SessionID (auth.go) instead of version
	// 2 (authv2.go), which servers from before version 2 need. Version 1's
	// SessionID can be copied into another ClientHello and starts with the
	// shortID in the clear.
	//
	// Version 2 carries the client's time, and a server refuses one more
	// than its MaxClockSkew (12 hours by default) from its own, as it does
	// any failed auth: by passing the connection to its cover site. A client
	// whose clock is that far off can't tell, unless ServerCertSPKISHA256 is
	// set: without it the client completes the cover site's handshake and
	// sends its CONNECT requests there. Set ServerCertSPKISHA256.
	LegacyAuth bool

	// Connection management
	// MaxStreamsPerConn is the most H2 streams the client opens per TCP
	// conn (default: 100). It must not exceed the server's
	// MaxConcurrentStreams (default: 250): a tunnel past the server's limit
	// waits for a stream to end rather than opening on a new connection.
	MaxStreamsPerConn int
	IdleTimeout      time.Duration // close idle connections after (default: 5m)
	ConnectTimeout   time.Duration // TCP+TLS connect timeout (default: 15s)

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
	if c.MaxStreamsPerConn == 0 {
		c.MaxStreamsPerConn = 100
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = 5 * time.Minute
	}
	if c.ConnectTimeout == 0 {
		c.ConnectTimeout = 15 * time.Second
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

	// ReplayWindow is how long the server remembers an authenticated
	// SessionID and refuses it again, sending the connection to the
	// masquerade as if auth had failed. Each is remembered for between
	// ReplayWindow and twice that (default: 24h). Negative turns replay
	// protection off, and with it off a version 2 ClientHello sent again
	// unchanged authenticates until MaxClockSkew has passed. It must be at
	// least twice MaxClockSkew. The record is this Server's alone and is kept in
	// memory: a restarted or newly created Server, or another one using the
	// same key pair, accepts a SessionID this one has seen.
	ReplayWindow time.Duration
	// ReplayCapacity is how many SessionIDs one ReplayWindow holds before
	// the server starts a new one early, which shortens how long each is
	// remembered under heavy load; the server logs when that happens. Memory
	// grows with the SessionIDs remembered, to at most about 10.7 bytes per
	// entry per generation, two generations once the first window has
	// passed (default: 1,000,000, at most about 21 MB in all).
	ReplayCapacity int

	// MaxClockSkew is how far a version 2 SessionID's time may be from the
	// server's (default: DefaultMaxClockSkew, or half of ReplayWindow if
	// that is less). A client whose clock is further off is refused like any
	// failed auth and sent to the masquerade; see ClientConfig.LegacyAuth.
	MaxClockSkew time.Duration

	// RequireAuthV2 refuses version 1 SessionIDs (auth.go), which can be
	// copied into another ClientHello and carry the shortID in the clear.
	// Set it once every client of this server sends version 2: clients from
	// before version 2, and ones with ClientConfig.LegacyAuth, then fail.
	RequireAuthV2 bool

	// LeanH2 serves tunnels with samizdat's own HTTP/2 server instead of
	// x/net's. Clients see the same frames; the server uses much less CPU
	// per byte (see leanh2.go). It applies to tunnels served through Handler
	// and has no effect when SessionHandler is set, since a session runs no
	// HTTP/2 server.
	LeanH2 bool

	// DisableShaping stops the server accepting clients that shape their
	// connections' first TLS records (see shaping.go), which it does by
	// default; clients that don't shape work either way. Shaping clients
	// fail against a server with it set. A server that accepts shaping sends
	// no TLS session tickets, to any client, since a ticket would be a record
	// ahead of the shaped ones. It has no effect when SessionHandler is set.
	DisableShaping bool

	// Handler: called for each authenticated proxied connection
	Handler ConnHandler

	// SessionHandler, when set, takes each authenticated connection instead
	// of the built-in HTTP/2 CONNECT server, and Handler is not used.
	SessionHandler SessionHandler
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
	if c.ReplayWindow == 0 {
		c.ReplayWindow = 24 * time.Hour
	}
	if c.MaxClockSkew == 0 {
		c.MaxClockSkew = DefaultMaxClockSkew
		// The replay filter has to outlast the time a version 2 ClientHello
		// stays valid; see NewServer.
		if c.ReplayWindow > 0 && c.ReplayWindow/2 < c.MaxClockSkew {
			c.MaxClockSkew = c.ReplayWindow / 2
		}
	}
	if c.ReplayCapacity == 0 {
		c.ReplayCapacity = 1_000_000
	}
}
