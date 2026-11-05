package samizdat

import (
	"context"
	"encoding/pem"
	"errors"
	"io"
	"net"
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
	<-started
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
		if err == nil {
			conn.Close()
		}
		return err
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
	if _, err := c.DialSession(ctx(t)); err == nil {
		t.Fatal("expected error after Close")
	}
}
