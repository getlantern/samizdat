package samizdat

import (
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// closeWithin calls server.Close and fails the test if it takes longer than d.
func closeWithin(t *testing.T, server *Server, d time.Duration) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		server.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("Close did not return within %v", d)
	}
}

// expectClosed fails the test unless conn reports a non-timeout read error,
// i.e. the server's end has gone away.
func expectClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		_, err := conn.Read(make([]byte, 4096))
		if err == nil {
			continue
		}
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			t.Fatalf("connection still open after Close: %v", err)
		}
		return
	}
}

func newCloseTestServer(t *testing.T, config ServerConfig) (*Server, string, []byte, [8]byte) {
	t.Helper()
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	id, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	config.ListenAddr = "127.0.0.1:0"
	config.PrivateKey = priv
	config.ShortIDs = [][8]byte{id}
	config.CertPEM = certPEM
	config.KeyPEM = keyPEM
	config.Handler = relayHandler
	server, ln := startTestServer(t, config)
	return server, ln.Addr().String(), pub, id
}

func TestCloseEndsAuthenticatedSessions(t *testing.T) {
	server, addr, pub, id := newCloseTestServer(t, ServerConfig{})
	held, err := dialEcho(t, addr, pub, id, startEcho(t))
	if err != nil {
		t.Fatalf("dialEcho: %v", err)
	}
	defer held.Close()

	closeWithin(t, server, time.Second)
	expectClosed(t, held)
}

func TestCloseEndsMasqueradedConns(t *testing.T) {
	// An origin that answers the first record, then holds the connection open
	// regardless of what the server does with its end.
	origin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("origin listener: %v", err)
	}
	defer origin.Close()
	release := make(chan struct{})
	defer close(release)
	go func() {
		for {
			c, err := origin.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.Read(make([]byte, 4096))
				c.Write([]byte("origin"))
				<-release
			}()
		}
	}()

	server, addr, _, _ := newCloseTestServer(t, ServerConfig{
		MasqueradeDomain: "fake.example.com",
		MasqueradeAddr:   origin.Addr().String(),
	})
	probe, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probe.Close()
	if _, err := probe.Write(buildFakeTLSRecord()); err != nil {
		t.Fatalf("probe write: %v", err)
	}
	probe.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(probe, make([]byte, len("origin"))); err != nil {
		t.Fatalf("masquerade not established: %v", err)
	}

	closeWithin(t, server, time.Second)
	expectClosed(t, probe)
}

func TestCloseEndsConnsAwaitingClientHello(t *testing.T) {
	server, addr, _, _ := newCloseTestServer(t, ServerConfig{})
	idle, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer idle.Close()
	// A partial record header: the server is mid-read, not yet waiting on
	// Accept.
	if _, err := idle.Write([]byte{22, 3}); err != nil {
		t.Fatalf("write: %v", err)
	}
	time.Sleep(100 * time.Millisecond)

	closeWithin(t, server, time.Second)
	expectClosed(t, idle)
}

func TestCloseTwiceAndRacingAccepts(t *testing.T) {
	server, addr, _, _ := newCloseTestServer(t, ServerConfig{})
	var wg sync.WaitGroup
	conns := make(chan net.Conn, 64)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
				conns <- c
			}
		}()
	}
	closeWithin(t, server, time.Second)
	closeWithin(t, server, time.Second)
	wg.Wait()
	close(conns)
	for c := range conns {
		expectClosed(t, c)
		c.Close()
	}
}
