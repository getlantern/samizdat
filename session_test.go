package samizdat

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

func TestSessionHandlerGetsAuthenticatedConn(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	got := make(chan [8]byte, 1)
	_, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(ctx context.Context, conn net.Conn, shortID [8]byte) {
			if _, ok := SessionConnFromContext(ctx); !ok {
				t.Error("no session conn in ctx")
			}
			if id, ok := ShortIDFromContext(ctx); !ok || id != shortID {
				t.Error("no short ID in ctx")
			}
			got <- shortID
			io.Copy(conn, conn) // echo until closed
		},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
	if s := <-got; s != sid {
		t.Fatal("wrong short ID")
	}
}

func TestSessionHandlerCtxCancelledByClose(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	started := make(chan struct{})
	done := make(chan error, 1)
	srv, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(ctx context.Context, _ net.Conn, _ [8]byte) {
			close(started)
			<-ctx.Done()
			done <- context.Cause(ctx)
		},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, started, "handler start")
	srv.Close()
	select {
	case cause := <-done:
		if !errors.Is(cause, ErrServerClosed) {
			t.Fatalf("cause = %v, want ErrServerClosed", cause)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler ctx not cancelled by Close")
	}
}

func TestSessionHandlerReturnClosesConn(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(context.Context, net.Conn, [8]byte) {},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("read after handler returned = %v, want EOF", err)
	}
}

func TestNewServerNeedsAHandler(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	if _, err := NewServer(ServerConfig{PrivateKey: priv, ShortIDs: [][8]byte{sid}}); err == nil {
		t.Fatal("expected error with neither Handler nor SessionHandler")
	}
	h := func(context.Context, net.Conn, [8]byte) {}
	if _, err := NewServer(ServerConfig{PrivateKey: priv, ShortIDs: [][8]byte{sid}, SessionHandler: h}); err != nil {
		t.Fatalf("SessionHandler alone: %v", err)
	}
}

func TestDialSessionPinsCertificate(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(ctx context.Context, conn net.Conn, _ [8]byte) { io.Copy(io.Discard, conn) },
	})
	block, _ := pem.Decode(certPEM)
	good, err := SPKISHA256(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	dial := func(pin []byte) error {
		c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid, ServerCertSPKISHA256: pin})
		if err != nil {
			return err
		}
		defer c.Close()
		conn, err := c.DialSession(ctx(t))
		if err != nil {
			if conn != nil {
				t.Errorf("DialSession returned a non-nil conn (%T) with error %v", conn, err)
			}
			return err
		}
		conn.Close()
		return nil
	}
	if err := dial(good[:]); err != nil {
		t.Fatalf("good pin: %v", err)
	}
	if err := dial(nil); err != nil {
		t.Fatalf("no pin: %v", err)
	}
	bad := good
	bad[0] ^= 1
	if err := dial(bad[:]); !errors.Is(err, ErrCertPinMismatch) {
		t.Fatalf("bad pin: %v", err)
	}
}

func TestNewClientRejectsBadPinLength(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	if _, err := NewClient(ClientConfig{ServerAddr: "127.0.0.1:1", ServerName: "x", PublicKey: pub, ServerCertSPKISHA256: make([]byte, 31)}); err == nil {
		t.Fatal("expected error for a 31-byte pin")
	}
}

func TestDialSessionAfterClose(t *testing.T) {
	_, pub, _ := GenerateKeyPair()
	c, _ := NewClient(ClientConfig{ServerAddr: "127.0.0.1:1", ServerName: "x", PublicKey: pub})
	c.Close()
	if conn, err := c.DialSession(ctx(t)); err == nil || conn != nil {
		t.Fatalf("after Close: conn = %v, err = %v, want nil and an error", conn, err)
	}
}

// waitFor fails the test if ch is not ready within 5s.
func waitFor[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		var zero T
		return zero
	}
}

func TestSessionHandlerCtxEndsWhenClientDisconnects(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	started := make(chan struct{})
	done := make(chan error, 1)
	_, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(ctx context.Context, conn net.Conn, _ [8]byte) {
			// Like an http2.ClientConn's read loop: a Read is always pending.
			go io.Copy(io.Discard, conn)
			close(started)
			<-ctx.Done()
			done <- context.Cause(ctx)
		},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, started, "handler start")
	conn.Close()
	if cause := waitFor(t, done, "handler ctx to end after disconnect"); cause == nil || errors.Is(cause, ErrServerClosed) {
		t.Fatalf("cause = %v, want a connection error", cause)
	}
}

func TestSessionHandlerCtxEndsWhenShortIDRevoked(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	other, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	started := make(chan struct{})
	done := make(chan error, 1)
	srv, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid, other}, CertPEM: certPEM, KeyPEM: keyPEM,
		// No Read pending: revocation must end ctx on its own.
		SessionHandler: func(ctx context.Context, _ net.Conn, _ [8]byte) {
			close(started)
			<-ctx.Done()
			done <- context.Cause(ctx)
		},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	waitFor(t, started, "handler start")
	if err := srv.SetShortIDs([][8]byte{other}); err != nil {
		t.Fatal(err)
	}
	if cause := waitFor(t, done, "handler ctx to end after revocation"); !errors.Is(cause, ErrSessionRevoked) {
		t.Fatalf("cause = %v, want ErrSessionRevoked", cause)
	}
}

func TestSessionHandlerConnKeepsConnectionState(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	proto := make(chan string, 1)
	_, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(_ context.Context, conn net.Conn, _ [8]byte) {
			cs, ok := conn.(interface{ ConnectionState() tls.ConnectionState })
			if !ok {
				proto <- ""
				return
			}
			proto <- cs.ConnectionState().NegotiatedProtocol
		},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if p := waitFor(t, proto, "handler"); p != "h2" {
		t.Fatalf("NegotiatedProtocol = %q, want h2", p)
	}
}

func TestDialSessionCancelledCtx(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	_, pub, _ := GenerateKeyPair()
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "x", PublicKey: pub})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	cctx, cancel := context.WithCancel(ctx(t))
	cancel()
	conn, err := c.DialSession(cctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if conn != nil {
		t.Fatalf("conn = %T, want nil", conn)
	}
}

func TestDialSessionConnectTimeout(t *testing.T) {
	// The listener accepts but never answers the ClientHello.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	_, pub, _ := GenerateKeyPair()
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "x", PublicKey: pub, ConnectTimeout: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if conn, err := c.DialSession(ctx(t)); err == nil || conn != nil {
		t.Fatalf("conn = %v, err = %v, want nil and a timeout", conn, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("DialSession took %v, want about ConnectTimeout", d)
	}
}

func TestSessionHandlerCtxEndsOnWriteTimeout(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	type result struct {
		readCause, writeCause error
		writeErr              error
	}
	res := make(chan result, 1)
	_, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(ctx context.Context, conn net.Conn, _ [8]byte) {
			var r result
			// A read timeout leaves the session usable, so ctx stays live.
			conn.SetReadDeadline(time.Now().Add(-time.Second))
			conn.Read(make([]byte, 1))
			r.readCause = context.Cause(ctx)
			conn.SetReadDeadline(time.Time{})
			// A write timeout poisons the TLS conn, so it ends the session.
			conn.SetWriteDeadline(time.Now().Add(-time.Second))
			_, r.writeErr = conn.Write([]byte("x"))
			select {
			case <-ctx.Done():
				r.writeCause = context.Cause(ctx)
			case <-time.After(2 * time.Second):
			}
			res <- r
		},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	r := waitFor(t, res, "handler")
	if r.readCause != nil {
		t.Fatalf("a read timeout ended the session: %v", r.readCause)
	}
	if !errors.Is(r.writeErr, os.ErrDeadlineExceeded) {
		t.Fatalf("write err = %v, want a deadline error", r.writeErr)
	}
	if !errors.Is(r.writeCause, os.ErrDeadlineExceeded) {
		t.Fatalf("cause after write timeout = %v, want a deadline error", r.writeCause)
	}
}

func TestServerSharesOneTLSConfig(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	h := func(context.Context, net.Conn, [8]byte) {}
	s, err := NewServer(ServerConfig{PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM, SessionHandler: h})
	if err != nil {
		t.Fatal(err)
	}
	a, err := s.tlsConfig()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := s.tlsConfig()
	if a != b {
		t.Fatal("each session got its own TLS config, so session tickets can never be resumed")
	}
	if len(a.Certificates) != 1 || a.MinVersion != tls.VersionTLS13 || len(a.NextProtos) != 1 || a.NextProtos[0] != "h2" {
		t.Fatalf("unexpected TLS config: %d certs, min version %x, ALPN %v", len(a.Certificates), a.MinVersion, a.NextProtos)
	}
}
