package samizdat

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestPoolCreatesOneTransportAtATime: CONNECTs that find no capacity at once
// share the one transport being created rather than each dialing its own.
func TestPoolCreatesOneTransportAtATime(t *testing.T) {
	var creates atomic.Int32
	release := make(chan struct{})
	pool := newConnPool(100, time.Minute, func(ctx context.Context) (*h2Transport, error) {
		creates.Add(1)
		<-release
		return newTestTransport(okRoundTripper()), nil
	})
	defer pool.close()

	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := pool.getTransport(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := creates.Load(); n != 1 {
		t.Fatalf("20 CONNECTs at once created %d transports, want 1", n)
	}
}

// TestPoolFailedCreateFailsWaiters: CONNECTs waiting on a creation that
// fails all fail with it at once, rather than each trying in turn against a
// server that isn't answering, and the next CONNECT tries again.
func TestPoolFailedCreateFailsWaiters(t *testing.T) {
	var creates atomic.Int32
	first := make(chan struct{})
	pool := newConnPool(100, time.Minute, func(ctx context.Context) (*h2Transport, error) {
		if creates.Add(1) == 1 {
			<-first
			return nil, errors.New("dial failed")
		}
		return newTestTransport(okRoundTripper()), nil
	})
	defer pool.close()

	errs := make(chan error, 5)
	for range 5 {
		go func() {
			_, err := pool.getTransport(context.Background())
			errs <- err
		}()
	}
	time.Sleep(20 * time.Millisecond)
	close(first)
	for range 5 {
		if err := <-errs; err == nil || err.Error() != "dial failed" {
			t.Fatalf("a waiter got %v, want the creation's error", err)
		}
	}
	if n := creates.Load(); n != 1 {
		t.Fatalf("%d creates for one failure, want 1", n)
	}
	if _, err := pool.getTransport(context.Background()); err != nil {
		t.Fatalf("the next CONNECT got %v, want a new transport", err)
	}
}

// TestPoolCreateOutlivesItsStarter: the CONNECT that starts a shared creation
// giving up neither cancels it nor costs the others waiting on it.
func TestPoolCreateOutlivesItsStarter(t *testing.T) {
	release := make(chan struct{})
	var cancelled atomic.Bool
	pool := newConnPool(100, time.Minute, func(ctx context.Context) (*h2Transport, error) {
		<-release
		cancelled.Store(ctx.Err() != nil)
		return newTestTransport(okRoundTripper()), nil
	})
	defer pool.close()

	starter, cancel := context.WithCancel(context.Background())
	started := make(chan error, 1)
	go func() {
		_, err := pool.getTransport(starter)
		started <- err
	}()
	time.Sleep(20 * time.Millisecond)
	waited := make(chan error, 1)
	go func() {
		_, err := pool.getTransport(context.Background())
		waited <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := <-started; !errors.Is(err, context.Canceled) {
		t.Fatalf("the starter got %v, want its own cancellation", err)
	}
	close(release)
	if err := <-waited; err != nil {
		t.Fatalf("a waiter got %v once the starter gave up", err)
	}
	if cancelled.Load() {
		t.Fatal("the starter giving up cancelled the shared creation")
	}
}

// TestPoolCloseWakesWaiters: closing the pool releases CONNECTs waiting for a
// transport being created, without waiting for that create to end.
func TestPoolCloseWakesWaiters(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	var creates atomic.Int32
	pool := newConnPool(100, time.Minute, func(ctx context.Context) (*h2Transport, error) {
		creates.Add(1)
		<-release
		return nil, errors.New("closed")
	})
	go pool.getTransport(context.Background())
	for creates.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	waited := make(chan error, 1)
	go func() {
		_, err := pool.getTransport(context.Background())
		waited <- err
	}()
	time.Sleep(20 * time.Millisecond)
	pool.close()
	select {
	case err := <-waited:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter got %v, want context.Canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("closing the pool left a waiter blocked")
	}
}

// TestTransportSetupBoundedByConnectTimeout: a server that accepts the TCP
// connection and never answers the TLS handshake fails the setup after
// ConnectTimeout, even for a caller with no deadline and a custom Dialer, so
// the pool's one create at a time can't wedge every CONNECT behind it.
func TestTransportSetupBoundedByConnectTimeout(t *testing.T) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{config: ClientConfig{
		ServerAddr:     "example.com:443",
		ServerName:     "example.com",
		PublicKey:      key.PublicKey().Bytes(),
		ConnectTimeout: 100 * time.Millisecond,
		Dialer: func(ctx context.Context, network, address string) (net.Conn, error) {
			c1, c2 := net.Pipe()
			t.Cleanup(func() { c1.Close(); c2.Close() })
			go io.Copy(io.Discard, c2)
			return c1, nil
		},
	}}
	c.config.applyDefaults()
	start := time.Now()
	if _, err := c.createTransport(context.Background()); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("setup against a server that never answers returned %v, want a deadline error", err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Fatalf("setup took %v, want about ConnectTimeout", took)
	}
}

// TestPoolCloseEndsDial: closing the pool cancels a creation in progress
// rather than leaving it to handshake with the server after the client is
// gone.
func TestPoolCloseEndsDial(t *testing.T) {
	ended := make(chan struct{})
	started := make(chan struct{})
	pool := newConnPool(100, time.Minute, func(ctx context.Context) (*h2Transport, error) {
		close(started)
		<-ctx.Done()
		close(ended)
		return nil, ctx.Err()
	})
	go pool.getTransport(context.Background())
	<-started
	pool.close()
	select {
	case <-ended:
	case <-time.After(time.Second):
		t.Fatal("the dial went on after the pool closed")
	}
}
