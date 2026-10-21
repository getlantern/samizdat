package samizdat

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// startEcho starts a TCP echo server and returns its address.
func startEcho(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// relayHandler dials the CONNECT destination and copies both ways.
func relayHandler(_ context.Context, conn net.Conn, destination string) {
	defer conn.Close()
	target, err := net.DialTimeout("tcp", destination, 5*time.Second)
	if err != nil {
		return
	}
	defer target.Close()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(target, conn) }()
	go func() { defer wg.Done(); io.Copy(conn, target) }()
	wg.Wait()
}

// dialEcho opens a tunnel to echoAddr authenticating as shortID, and proves it
// with one round trip. It returns the open tunnel.
func dialEcho(t *testing.T, serverAddr string, pub []byte, shortID [8]byte, echoAddr string) (net.Conn, error) {
	t.Helper()
	client, err := NewClient(ClientConfig{
		ServerAddr:  serverAddr,
		ServerName:  "test.example.com",
		PublicKey:   pub,
		ShortID:     shortID,
		Fingerprint: "chrome",
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() { client.Close() })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		return nil, err
	}
	msg := []byte("ping")
	if _, err := conn.Write(msg); err != nil {
		conn.Close()
		return nil, err
	}
	buf := make([]byte, len(msg))
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(conn, buf); err != nil {
		conn.Close()
		return nil, err
	}
	conn.SetReadDeadline(time.Time{})
	return conn, nil
}

func TestSetShortIDsAddsAndRevokes(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	base, _ := GenerateShortID()
	paired, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	echo := startEcho(t)
	server, ln := startTestServer(t, ServerConfig{
		ListenAddr: "127.0.0.1:0",
		PrivateKey: priv,
		ShortIDs:   [][8]byte{base},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Handler:    relayHandler,
	})
	addr := ln.Addr().String()

	if c, err := dialEcho(t, addr, pub, paired, echo); err == nil {
		c.Close()
		t.Fatal("a short ID the server was never given authenticated")
	}

	if err := server.SetShortIDs([][8]byte{base, paired}); err != nil {
		t.Fatalf("SetShortIDs: %v", err)
	}
	held, err := dialEcho(t, addr, pub, paired, echo)
	if err != nil {
		t.Fatalf("an added short ID was rejected: %v", err)
	}
	defer held.Close()

	if err := server.SetShortIDs([][8]byte{base}); err != nil {
		t.Fatalf("SetShortIDs: %v", err)
	}
	if c, err := dialEcho(t, addr, pub, paired, echo); err == nil {
		c.Close()
		t.Fatal("a removed short ID still authenticates")
	}
	c, err := dialEcho(t, addr, pub, base, echo)
	if err != nil {
		t.Fatalf("the remaining short ID was rejected: %v", err)
	}
	c.Close()

	// The session that authenticated with the removed ID was closed, not left
	// to run until it ends on its own.
	held.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = held.Read(make([]byte, 1))
	var ne net.Error
	if err == nil || (errors.As(err, &ne) && ne.Timeout()) {
		t.Fatalf("a session using a removed short ID survived: %v", err)
	}
}

func TestSetShortIDsRejectsEmptySetAndCopies(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	a, _ := GenerateShortID()
	b, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	s, err := NewServer(ServerConfig{PrivateKey: priv, ShortIDs: [][8]byte{a}, CertPEM: certPEM, KeyPEM: keyPEM, Handler: relayHandler})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	if err := s.SetShortIDs(nil); err == nil {
		t.Fatal("an empty set must be refused")
	}
	if got := s.ShortIDs(); len(got) != 1 || got[0] != a {
		t.Fatalf("a refused update changed the set: %v", got)
	}
	ids := [][8]byte{b}
	if err := s.SetShortIDs(ids); err != nil {
		t.Fatalf("SetShortIDs: %v", err)
	}
	ids[0] = a
	if got := s.ShortIDs(); got[0] != b {
		t.Fatal("SetShortIDs must copy its argument")
	}
	got := s.ShortIDs()
	got[0] = a
	if s.ShortIDs()[0] != b {
		t.Fatal("ShortIDs must return a copy")
	}
}
