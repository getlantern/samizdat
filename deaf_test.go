package samizdat

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
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
	shortenConnectAnswerTimeout(t, 500*time.Millisecond)
	entered := make(chan struct{}, 2)
	tr := newTestTransport(roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		entered <- struct{}{}
		<-req.Context().Done()
		return nil, req.Context().Err()
	}))

	// The first CONNECT starts the clock; the second, waiting from later,
	// must fail with it rather than waiting out its own.
	first := make(chan error, 1)
	go func() {
		_, err := tr.openTunnel(ctx(t), "a.example:443")
		first <- err
	}()
	<-entered
	time.Sleep(200 * time.Millisecond)
	second := make(chan error, 1)
	go func() {
		_, err := tr.openTunnel(ctx(t), "b.example:443")
		second <- err
	}()
	<-entered
	start := time.Now()
	err := <-second
	if !errors.Is(err, errConnectUnanswered) {
		t.Fatalf("second openTunnel: got %v, want errConnectUnanswered", err)
	}
	if took := time.Since(start); took >= connectAnswerTimeout {
		t.Errorf("second CONNECT waited %s, its own timeout; it should fail once the first's runs out", took)
	}
	if err := <-first; !errors.Is(err, errConnectUnanswered) {
		t.Fatalf("first openTunnel: got %v, want errConnectUnanswered", err)
	}
}

func TestConnectDuringShapingTimedFromShapingEnd(t *testing.T) {
	shortenConnectAnswerTimeout(t, 200*time.Millisecond)
	tr := newTestTransport(blockingRoundTripper)
	_, server := net.Pipe()
	t.Cleanup(func() { server.Close() })
	sc := &shapedConn{Conn: server, shaping: true, done: make(chan struct{})}
	sc.cond = sync.NewCond(&sc.mu)
	tr.conn = &readTrackingConn{Conn: sc}

	result := make(chan error, 1)
	go func() {
		_, err := tr.openTunnel(ctx(t), "example.com:443")
		result <- err
	}()
	// While shaping runs, the CONNECT waits behind it however long it takes.
	select {
	case err := <-result:
		t.Fatalf("CONNECT abandoned during shaping: %v", err)
	case <-time.After(3 * connectAnswerTimeout):
	}
	if tr.retired.Load() {
		t.Fatal("a transport still shaping must not be taken for deaf")
	}

	// Once shaping is over, it gets the full timeout and no more.
	ended := time.Now()
	close(sc.done)
	err := <-result
	if !errors.Is(err, errConnectUnanswered) {
		t.Fatalf("openTunnel: got %v, want errConnectUnanswered", err)
	}
	if took := time.Since(ended); took < connectAnswerTimeout || took > 5*connectAnswerTimeout {
		t.Errorf("CONNECT abandoned %s after shaping ended, want about %s", took, connectAnswerTimeout)
	}
	if !tr.retired.Load() {
		t.Error("the transport must be retired once a CONNECT on it goes unanswered")
	}
}

func TestFirstConnectOnNewTransportHeldToAnswerTimeout(t *testing.T) {
	shortenConnectAnswerTimeout(t, 100*time.Millisecond)
	// A transport that has never answered, past shaping: its first CONNECT
	// is held to the timeout like any other.
	tr := newTestTransport(blockingRoundTripper)
	_, err := tr.openTunnel(ctx(t), "example.com:443")
	if !errors.Is(err, errConnectUnanswered) {
		t.Fatalf("openTunnel: got %v, want errConnectUnanswered", err)
	}
	if !tr.retired.Load() {
		t.Error("the transport must be retired once a CONNECT on it goes unanswered")
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
	// Mute once shaping is over: until then, CONNECTs aren't held to the
	// answer timeout.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		client.pool.mu.Lock()
		shaping := slices.ContainsFunc(client.pool.transports, (*h2Transport).shapingActive)
		client.pool.mu.Unlock()
		if !shaping {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("shaping never finished")
		}
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
