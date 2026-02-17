package samizdat

import (
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// Masquerade implements a TCP-level transparent proxy to the real masquerade
// domain. When the server receives a connection that fails Samizdat auth
// verification, it enters masquerade mode: the buffered raw ClientHello is
// forwarded to the real domain, and bidirectional TCP proxying begins.
//
// This makes the server indistinguishable from the real domain to active
// probes — the probe completes a real TLS handshake with the real domain's
// certificate and receives real HTTP responses.
type Masquerade struct {
	OriginAddr   string        // IP:port of real domain (or resolved from domain)
	OriginDomain string        // domain name for DNS resolution
	IdleTimeout  time.Duration // close after no data (default: 5m)
	MaxDuration  time.Duration // absolute max proxy duration (default: 10m)
	DialTimeout  time.Duration // timeout connecting to origin (default: 10s)
}

// NewMasquerade creates a new masquerade proxy with defaults.
func NewMasquerade(domain, addr string, idleTimeout, maxDuration time.Duration) *Masquerade {
	if idleTimeout == 0 {
		idleTimeout = 5 * time.Minute
	}
	if maxDuration == 0 {
		maxDuration = 10 * time.Minute
	}
	return &Masquerade{
		OriginAddr:   addr,
		OriginDomain: domain,
		IdleTimeout:  idleTimeout,
		MaxDuration:  maxDuration,
		DialTimeout:  10 * time.Second,
	}
}

// ProxyConnection forwards a non-authenticated connection to the real domain.
// clientHello contains the buffered raw ClientHello bytes that triggered the
// auth check failure. conn is the raw TCP connection from the probe (pre-TLS).
func (m *Masquerade) ProxyConnection(conn net.Conn, clientHello []byte) error {
	// Resolve origin address if needed
	addr := m.OriginAddr
	if addr == "" {
		addr = net.JoinHostPort(m.OriginDomain, "443")
	}

	// Connect to the real domain
	originConn, err := net.DialTimeout("tcp", addr, m.DialTimeout)
	if err != nil {
		return fmt.Errorf("connecting to masquerade origin %s: %w", addr, err)
	}

	// Forward the buffered ClientHello that we already read
	if len(clientHello) > 0 {
		if _, err := originConn.Write(clientHello); err != nil {
			originConn.Close()
			return fmt.Errorf("forwarding ClientHello to origin: %w", err)
		}
	}

	// Set absolute max duration deadline
	deadline := time.Now().Add(m.MaxDuration)
	conn.SetDeadline(deadline)
	originConn.SetDeadline(deadline)

	// Bidirectional proxy: two goroutines running io.Copy
	var wg sync.WaitGroup
	var copyErr error
	var errOnce sync.Once

	wg.Add(2)

	// probe -> origin
	go func() {
		defer wg.Done()
		_, err := io.Copy(originConn, conn)
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Signal the other direction to stop
		if tc, ok := originConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	// origin -> probe
	go func() {
		defer wg.Done()
		_, err := io.Copy(conn, originConn)
		if err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Signal the other direction to stop
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	wg.Wait()

	originConn.Close()
	conn.Close()

	return copyErr
}
