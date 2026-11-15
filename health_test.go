package samizdat

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// startQuietServer returns a transport whose server end reads everything the
// client sends and never answers a request. When pingEvery is nonzero it
// sends a PING that often, so the connection is busy without answering.
func startQuietServer(t *testing.T, pingEvery time.Duration) (*h2Transport, *bytes.Buffer) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	go io.Copy(io.Discard, c2)
	if pingEvery > 0 {
		go func() {
			fr := http2.NewFramer(c2, nil)
			if fr.WriteSettings() != nil {
				return
			}
			for {
				time.Sleep(pingEvery)
				if fr.WritePing(false, [8]byte{}) != nil {
					return
				}
			}
		}()
	}
	tr, err := newH2Transport(c1, "example.com:443", 10)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	tr.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return tr, &logs
}

func setVar[T any](t *testing.T, v *T, val T) {
	old := *v
	*v = val
	t.Cleanup(func() { *v = old })
}

// TestSilentConnectRetiresTransport: a CONNECT that times out while its
// connection reads nothing retires the transport, so the next CONNECT gets a
// new connection instead of waiting on a dead one.
func TestSilentConnectRetiresTransport(t *testing.T) {
	setVar(t, &silentConnectRetire, 50*time.Millisecond)
	tr, logs := startQuietServer(t, 0)
	tr.activeStreams.Store(1)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	// The deadline reaches RoundTrip as a cancellation of its detached
	// context.
	if _, err := tr.openReserved(ctx, "example.com:443"); !errors.Is(err, context.Canceled) {
		t.Fatalf("CONNECT returned %v, want a cancellation", err)
	}
	if !tr.retired.Load() {
		t.Fatal("a transport silent through a whole CONNECT wasn't retired")
	}
	if !tr.isClosed() {
		t.Fatal("retired transport with no streams left stayed open")
	}
	for _, want := range []string{"samizdat CONNECT failed", "read_while_waiting=false", "samizdat transport retired"} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("logs lack %q:\n%s", want, logs)
		}
	}
	if strings.Contains(logs.String(), "example.com") {
		t.Errorf("logs name the destination:\n%s", logs)
	}
}

// TestBusyConnectKeepsTransport: a CONNECT that times out while its
// connection still reads leaves the transport in use; the connection is
// alive, and only that request went unanswered.
func TestBusyConnectKeepsTransport(t *testing.T) {
	setVar(t, &silentConnectRetire, 50*time.Millisecond)
	tr, logs := startQuietServer(t, 20*time.Millisecond)
	tr.activeStreams.Store(1)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); err == nil {
		t.Fatal("CONNECT to a server that never answers succeeded")
	}
	if tr.retired.Load() || tr.isClosed() {
		t.Fatal("a transport that kept reading was retired")
	}
	if !strings.Contains(logs.String(), "read_while_waiting=true") {
		t.Errorf("logs lack read_while_waiting=true:\n%s", logs)
	}
}

// TestShortCancelKeepsTransport: a CONNECT its caller abandons quickly says
// nothing about the connection, even if it read nothing meanwhile.
func TestShortCancelKeepsTransport(t *testing.T) {
	tr, _ := startQuietServer(t, 0)
	tr.activeStreams.Store(1)

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); err == nil {
		t.Fatal("CONNECT to a server that never answers succeeded")
	}
	if tr.retired.Load() {
		t.Fatal("a CONNECT cancelled before silentConnectRetire retired the transport")
	}
}

// TestUnansweredPingClosesConnection: a CONNECT that waits pingIfSilent with
// its connection reading nothing pings it, and closes it when the ping goes
// unanswered, so the CONNECT fails in time for its caller to redial rather
// than waiting out its own deadline.
func TestUnansweredPingClosesConnection(t *testing.T) {
	setVar(t, &pingIfSilent, 50*time.Millisecond)
	setVar(t, &pingTimeout, 50*time.Millisecond)
	setVar(t, &silentConnectRetire, time.Hour)
	tr, logs := startQuietServer(t, 0)
	tr.activeStreams.Store(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := tr.openReserved(ctx, "example.com:443")
	if !connFatal(err) {
		t.Fatalf("CONNECT on a connection whose ping went unanswered returned %v, which DialContext won't redial", err)
	}
	if ctx.Err() != nil {
		t.Fatal("CONNECT waited out its caller's deadline")
	}
	if !tr.isClosed() {
		t.Fatal("transport stayed open after its ping went unanswered")
	}
	if !strings.Contains(logs.String(), "unanswered ping") {
		t.Errorf("logs lack the close reason:\n%s", logs)
	}
}

// TestIdleReusePings: a CONNECT on a connection that has read nothing for
// pingIfIdle pings it at once, without waiting for pingIfSilent.
func TestIdleReusePings(t *testing.T) {
	setVar(t, &pingIfIdle, 0)
	setVar(t, &pingIfSilent, time.Hour)
	setVar(t, &pingTimeout, 50*time.Millisecond)
	setVar(t, &silentConnectRetire, time.Hour)
	tr, _ := startQuietServer(t, 0)
	tr.activeStreams.Store(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); !connFatal(err) {
		t.Fatalf("CONNECT returned %v, want a conn-fatal error", err)
	}
	if ctx.Err() != nil || !tr.isClosed() {
		t.Fatal("reusing an idle connection didn't ping it")
	}
}

// TestReadingConnectionSurvivesUnansweredPing: a connection that keeps
// reading is alive, so it isn't closed even though its server never answers
// the ping or the CONNECT.
func TestReadingConnectionSurvivesUnansweredPing(t *testing.T) {
	// Every CONNECT pings at once, and the ping goes unanswered while the
	// server's own frames keep arriving.
	setVar(t, &pingIfIdle, 0)
	setVar(t, &pingIfSilent, time.Hour)
	setVar(t, &pingTimeout, 50*time.Millisecond)
	setVar(t, &silentConnectRetire, time.Hour)
	tr, _ := startQuietServer(t, 10*time.Millisecond)
	tr.activeStreams.Store(1)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	tr.openReserved(ctx, "example.com:443")
	if tr.isClosed() || tr.retired.Load() {
		t.Fatal("a connection that kept reading was closed")
	}
}

// TestUnansweredPingSparesTunnelsAWhile: a connection whose ping goes
// unanswered is retired at once, but the tunnels it carries keep it open
// until it has been silent for closeIfSilent too.
func TestUnansweredPingSparesTunnelsAWhile(t *testing.T) {
	setVar(t, &pingIfSilent, 20*time.Millisecond)
	setVar(t, &pingTimeout, 20*time.Millisecond)
	setVar(t, &closeIfSilent, 300*time.Millisecond)
	setVar(t, &silentConnectRetire, time.Hour)
	tr, _ := startQuietServer(t, 0)
	tr.activeStreams.Store(2) // a tunnel, and the CONNECT's slot

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); !connFatal(err) {
		t.Fatalf("CONNECT returned %v, want a conn-fatal error", err)
	}
	if !tr.retired.Load() {
		t.Fatal("transport wasn't retired after its ping went unanswered")
	}
	if tr.isClosed() {
		t.Fatal("transport closed under its tunnel before closeIfSilent")
	}
	deadline := time.Now().Add(2 * time.Second)
	for !tr.isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("transport stayed open after closeIfSilent more of silence")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestClosedBeforeFirstStream: a connection that closes before its first
// CONNECT gets a stream fails that CONNECT in a way DialContext redials, and
// leaves the transport unused, rather than failing every later CONNECT too.
func TestClosedBeforeFirstStream(t *testing.T) {
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close() })
	go io.Copy(io.Discard, c2)
	tr, err := newH2Transport(c1, "example.com:443", 10)
	if err != nil {
		t.Fatal(err)
	}
	http2.NewFramer(c2, nil).WriteSettings()
	c2.Close()
	for !tr.conn.closed.Load() {
		time.Sleep(time.Millisecond)
	}
	tr.activeStreams.Store(1)
	if _, err := tr.openReserved(context.Background(), "example.com:443"); !connFatal(err) {
		t.Fatalf("CONNECT returned %v, want a conn-fatal error", err)
	}
	if !tr.isClosed() {
		t.Fatal("a transport whose connection closed is still open")
	}
}

// TestSilenceAfterEarlyReadPings: a connection that reads something early in
// a CONNECT and then goes silent is still pinged, and the CONNECT fails in
// time for its caller to redial.
func TestSilenceAfterEarlyReadPings(t *testing.T) {
	setVar(t, &pingIfSilent, 100*time.Millisecond)
	setVar(t, &pingTimeout, 50*time.Millisecond)
	setVar(t, &silentConnectRetire, time.Hour)
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	go io.Copy(io.Discard, c2)
	tr, err := newH2Transport(c1, "example.com:443", 10)
	if err != nil {
		t.Fatal(err)
	}
	tr.activeStreams.Store(1)
	go func() {
		// SETTINGS arrive 30ms into the CONNECT; then nothing does.
		time.Sleep(30 * time.Millisecond)
		http2.NewFramer(c2, nil).WriteSettings()
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); !connFatal(err) {
		t.Fatalf("CONNECT returned %v, want a conn-fatal error", err)
	}
	if ctx.Err() != nil {
		t.Fatal("an early read kept the silence check from ever pinging")
	}
}

// TestUnencodableDestinationNotLogged: a destination with no valid encoding
// fails before reaching the connection, so its name stays out of the logs,
// and the transport stays in use.
func TestUnencodableDestinationNotLogged(t *testing.T) {
	tr, logs := startQuietServer(t, 0)
	tr.activeStreams.Store(1)
	// Its second label fails punycode decoding, and the error quotes it.
	const dest = "ü.xn--99999999999999.example:443"
	_, err := tr.openReserved(context.Background(), dest)
	if err == nil || connFatal(err) {
		t.Fatalf("CONNECT returned %v, want a non-fatal error", err)
	}
	if strings.Contains(logs.String(), "99999999999999") || strings.Contains(logs.String(), "ü") {
		t.Errorf("logs name the destination:\n%s", logs)
	}
	if tr.retired.Load() || tr.isClosed() {
		t.Fatal("a bad destination retired the transport")
	}
}

// fakeH2Server is the server end of a transport's connection. It sends
// SETTINGS and reads the client's frames, counting the client's PINGs, and
// never answers a request.
type fakeH2Server struct {
	pings atomic.Int32
	// headers receives the ID of each request's HEADERS, if anything is
	// waiting for it.
	headers chan uint32
}

type fakeH2Options struct {
	refuse     bool          // refuse every request
	pingEvery  time.Duration // send a PING this often, if set
	maxStreams uint32        // advertise this MaxConcurrentStreams, if set
	ackPings   *atomic.Bool  // answer the client's PINGs while it's true
}

func startFakeH2Server(t *testing.T, o fakeH2Options) (*h2Transport, *fakeH2Server, *bytes.Buffer) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	srv := &fakeH2Server{headers: make(chan uint32, 16)}
	var wmu sync.Mutex
	fr := http2.NewFramer(c2, c2)
	// Writes go in goroutines of their own: the client may be blocked
	// writing to the one reading its frames.
	write := func(f func() error) error {
		wmu.Lock()
		defer wmu.Unlock()
		return f()
	}
	go func() {
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(c2, preface); err != nil {
			return
		}
		go func() {
			var settings []http2.Setting
			if o.maxStreams > 0 {
				settings = append(settings, http2.Setting{ID: http2.SettingMaxConcurrentStreams, Val: o.maxStreams})
			}
			if write(func() error { return fr.WriteSettings(settings...) }) != nil || o.pingEvery == 0 {
				return
			}
			// PINGs only after SETTINGS, which must come first.
			for {
				time.Sleep(o.pingEvery)
				if write(func() error { return fr.WritePing(false, [8]byte{}) }) != nil {
					return
				}
			}
		}()
		for {
			f, err := fr.ReadFrame()
			if err != nil {
				return
			}
			switch f := f.(type) {
			case *http2.PingFrame:
				if !f.IsAck() {
					srv.pings.Add(1)
					if o.ackPings != nil && o.ackPings.Load() {
						data := f.Data
						go write(func() error { return fr.WritePing(true, data) })
					}
				}
			case *http2.HeadersFrame:
				select {
				case srv.headers <- f.StreamID:
				default:
				}
				if o.refuse {
					id := f.StreamID
					go write(func() error { return fr.WriteRSTStream(id, http2.ErrCodeRefusedStream) })
				}
			}
		}
	}()
	tr, err := newH2Transport(c1, "example.com:443", 10)
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	tr.logger = slog.New(slog.NewTextHandler(&logs, nil))
	return tr, srv, &logs
}

// TestStalledConnectOnLiveConnection: a CONNECT unanswered for connectStall
// on a connection that keeps reading, as one whose server takes no new
// streams does, is abandoned in time for its caller to redial, and the
// transport is retired while the tunnels it carries go on.
func TestStalledConnectOnLiveConnection(t *testing.T) {
	setVar(t, &connectStall, 100*time.Millisecond)
	setVar(t, &pingTimeout, 50*time.Millisecond)
	tr, _, logs := startFakeH2Server(t, fakeH2Options{pingEvery: 10 * time.Millisecond})
	tr.activeStreams.Store(2) // a tunnel, and the CONNECT's slot

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); !connFatal(err) {
		t.Fatalf("CONNECT returned %v, want a conn-fatal error", err)
	}
	if ctx.Err() != nil {
		t.Fatal("CONNECT waited out its caller's deadline")
	}
	if !tr.retired.Load() || tr.isClosed() {
		t.Fatalf("retired=%v closed=%v, want a retired transport still carrying its tunnel", tr.retired.Load(), tr.isClosed())
	}
	if !strings.Contains(logs.String(), "CONNECT unanswered") {
		t.Errorf("logs lack the retire reason:\n%s", logs)
	}
}

// TestRefusedStreamRedials: a server refusing a stream retires the transport
// and fails the CONNECT in a way DialContext redials.
func TestRefusedStreamRedials(t *testing.T) {
	tr, _, _ := startFakeH2Server(t, fakeH2Options{refuse: true})
	tr.activeStreams.Store(1)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); !connFatal(err) {
		t.Fatalf("CONNECT returned %v, want a conn-fatal error", err)
	}
	if !tr.retired.Load() {
		t.Fatal("a transport whose server refused a stream wasn't retired")
	}
}

// TestSlowConnectPingsLiveConnection: a CONNECT unanswered for pingIfSilent
// pings its connection even though it keeps reading, since the answer frees
// the slots x/net holds for cancelled streams.
func TestSlowConnectPingsLiveConnection(t *testing.T) {
	setVar(t, &pingIfSilent, 50*time.Millisecond)
	setVar(t, &pingTimeout, 50*time.Millisecond)
	tr, srv, _ := startFakeH2Server(t, fakeH2Options{pingEvery: 10 * time.Millisecond})
	tr.activeStreams.Store(1)

	// Count PINGs while the CONNECT still waits: x/net sends one of its own
	// with the RST_STREAM once the CONNECT is cancelled.
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.openReserved(ctx, "example.com:443")
	}()
	deadline := time.Now().Add(300 * time.Millisecond)
	for srv.pings.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	pinged := srv.pings.Load() > 0
	time.Sleep(100 * time.Millisecond) // let the unanswered ping time out
	cancel()
	<-done
	if !pinged {
		t.Fatal("a slow CONNECT on a connection still reading sent no PING")
	}
	if tr.retired.Load() || tr.isClosed() {
		t.Fatal("a connection still reading was retired over its unanswered ping")
	}
}

// TestPingFreesResetSlots: x/net counts the streams it cancels against the
// server's MaxConcurrentStreams until a PING is answered, so a server that
// leaves x/net's own PING unanswered can leave every new CONNECT waiting for
// a slot while the connection still reads. The ping a slow CONNECT sends
// frees those slots once it's answered, and the CONNECT goes out.
func TestPingFreesResetSlots(t *testing.T) {
	setVar(t, &pingIfSilent, 100*time.Millisecond)
	setVar(t, &pingIfIdle, time.Hour)
	setVar(t, &pingTimeout, time.Second)
	setVar(t, &connectStall, time.Hour)
	setVar(t, &silentConnectRetire, time.Hour)
	var ack atomic.Bool
	tr, srv, _ := startFakeH2Server(t, fakeH2Options{maxStreams: 2, pingEvery: 10 * time.Millisecond, ackPings: &ack})
	tr.activeStreams.Store(10)
	time.Sleep(50 * time.Millisecond) // for the client to take the SETTINGS

	// Fill both slots with CONNECTs cancelled after their HEADERS went out.
	var wg sync.WaitGroup
	for range 2 {
		ctx, cancel := context.WithCancel(context.Background())
		wg.Add(1)
		go func() {
			defer wg.Done()
			tr.openReserved(ctx, "example.com:443")
		}()
		select {
		case <-srv.headers:
		case <-time.After(2 * time.Second):
			t.Fatal("CONNECT never sent its HEADERS")
		}
		cancel()
	}
	wg.Wait()

	ack.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		tr.openReserved(ctx, "example.com:443")
	}()
	defer func() { cancel(); <-done }()
	select {
	case <-srv.headers:
	case <-time.After(2 * time.Second):
		t.Fatal("a CONNECT waiting on slots held for cancelled streams never went out")
	}
}

// TestPoolCreatesOneTransportAtATime: CONNECTs that find no capacity at once,
// as they do when a connection stalls under all of them, share the one
// transport being created rather than each dialing its own.
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

// TestPoolFailedCreateHandsOff: when the transport being created fails, a
// CONNECT that was waiting for it creates the next one itself.
func TestPoolFailedCreateHandsOff(t *testing.T) {
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

	failed := make(chan error, 1)
	go func() {
		_, err := pool.getTransport(context.Background())
		failed <- err
	}()
	for creates.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	waited := make(chan error, 1)
	go func() {
		_, err := pool.getTransport(context.Background())
		waited <- err
	}()
	time.Sleep(20 * time.Millisecond)
	close(first)
	if err := <-failed; err == nil {
		t.Fatal("the failed create reported no error")
	}
	if err := <-waited; err != nil {
		t.Fatalf("the waiting CONNECT got %v, want a transport of its own", err)
	}
	if n := creates.Load(); n != 2 {
		t.Fatalf("%d creates, want 2", n)
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
// ConnectTimeout, even for a caller with no deadline, so the pool's one
// create at a time can't wedge every CONNECT behind it.
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
