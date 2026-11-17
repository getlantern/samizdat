package samizdat

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func shortenConnectAnswerTimeout(t *testing.T, d time.Duration) {
	t.Helper()
	old := connectAnswerTimeout
	connectAnswerTimeout = d
	t.Cleanup(func() { connectAnswerTimeout = old })
}

// blockingRoundTripper never answers, returning only when the request's
// context ends.
var blockingRoundTripper = roundTripperFunc(func(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
})

func TestUnansweredConnectRetiresTransport(t *testing.T) {
	shortenConnectAnswerTimeout(t, 100*time.Millisecond)
	tr := newTestTransport(blockingRoundTripper)

	_, err := tr.openTunnel(ctx(t), "example.com:443")
	if !errors.Is(err, errConnectUnanswered) {
		t.Fatalf("openTunnel: got %v, want errConnectUnanswered", err)
	}
	if !connFatal(err) {
		t.Error("an unanswered CONNECT must be conn-fatal, so the dial retries on another transport")
	}
	if !tr.retired.Load() {
		t.Error("the transport must be retired once a CONNECT on it goes unanswered")
	}
}

func TestUnansweredConnectFailsOtherWaiters(t *testing.T) {
	shortenConnectAnswerTimeout(t, 200*time.Millisecond)
	tr := newTestTransport(blockingRoundTripper)

	// The first CONNECT starts the clock; the second, opened just before it
	// runs out, must fail with it rather than waiting out its own.
	first := make(chan error, 1)
	go func() {
		_, err := tr.openTunnel(ctx(t), "a.example:443")
		first <- err
	}()
	time.Sleep(150 * time.Millisecond)
	start := time.Now()
	_, err := tr.openTunnel(ctx(t), "b.example:443")
	if !errors.Is(err, errConnectUnanswered) {
		t.Fatalf("second openTunnel: got %v, want errConnectUnanswered", err)
	}
	if took := time.Since(start); took > 150*time.Millisecond {
		t.Errorf("second CONNECT waited %s; it should fail as soon as the transport is deaf", took)
	}
	if err := <-first; !errors.Is(err, errConnectUnanswered) {
		t.Fatalf("first openTunnel: got %v, want errConnectUnanswered", err)
	}
}

func TestCallerCancelDoesNotRetireTransport(t *testing.T) {
	shortenConnectAnswerTimeout(t, time.Second)
	tr := newTestTransport(blockingRoundTripper)

	c, cancel := context.WithTimeout(ctx(t), 50*time.Millisecond)
	defer cancel()
	_, err := tr.openTunnel(c, "example.com:443")
	if errors.Is(err, errConnectUnanswered) || err == nil {
		t.Fatalf("openTunnel: got %v, want the caller's cancellation", err)
	}
	time.Sleep(1200 * time.Millisecond) // past the answer timeout
	if tr.retired.Load() {
		t.Error("a CONNECT its caller gave up on must not retire the transport")
	}
}

// muteRelay forwards TCP to target. mute stops it forwarding what the
// client sends on the connections open so far, while still forwarding what
// the server sends: a path that has stopped carrying one direction.
type muteRelay struct {
	mu    sync.Mutex
	muted []*atomic.Bool
}

func (r *muteRelay) mute() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, m := range r.muted {
		m.Store(true)
	}
}

func startMuteRelay(t *testing.T, target string) (*muteRelay, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	r := &muteRelay{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s, err := net.Dial("tcp", target)
			if err != nil {
				c.Close()
				continue
			}
			t.Cleanup(func() { c.Close(); s.Close() })
			muted := new(atomic.Bool)
			r.mu.Lock()
			r.muted = append(r.muted, muted)
			r.mu.Unlock()
			go io.Copy(c, s)
			go func() {
				b := make([]byte, 32<<10)
				for {
					n, err := c.Read(b)
					if err != nil {
						s.Close()
						return
					}
					if !muted.Load() {
						s.Write(b[:n])
					}
				}
			}()
		}
	}()
	return r, ln.Addr().String()
}

// TestDialRecoversFromDeafTransport checks that dials on a transport whose
// connection stops carrying what the client sends move to a new transport
// within about connectAnswerTimeout, instead of waiting until they're
// canceled.
func TestDialRecoversFromDeafTransport(t *testing.T) {
	shortenConnectAnswerTimeout(t, 500*time.Millisecond)
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	sid, err := GenerateShortID()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr: "127.0.0.1:0",
		PrivateKey: priv,
		ShortIDs:   [][8]byte{sid},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, dest string) {
			defer conn.Close()
			io.Copy(conn, conn)
		},
		LeanH2: true,
	})
	relay, addr := startMuteRelay(t, ln.Addr().String())
	client, err := NewClient(ClientConfig{
		ServerAddr: addr, ServerName: "test.example.com",
		PublicKey: pub, ShortID: sid,
		TCPFragmentation: false, RecordFragmentation: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	dial := func() (time.Duration, error) {
		start := time.Now()
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := client.DialContext(c, "tcp", "echo:1")
		if err != nil {
			return time.Since(start), err
		}
		defer conn.Close()
		if _, err := conn.Write([]byte("ping")); err != nil {
			return time.Since(start), err
		}
		b := make([]byte, 4)
		_, err = io.ReadFull(conn, b)
		return time.Since(start), err
	}
	if _, err := dial(); err != nil {
		t.Fatalf("dial before muting: %v", err)
	}

	relay.mute()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			took, err := dial()
			if err != nil {
				t.Errorf("dial after muting: %v", err)
			} else if took > 3*time.Second {
				t.Errorf("dial after muting took %s", took)
			}
		}()
	}
	wg.Wait()
}
