package samizdat

import (
	"bytes"
	"context"
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

// fakeH2Server is the server end of a transport's connection: it sends
// SETTINGS and reads the client's frames, refusing each request if refuse is
// set, sending a PING every pingEvery if set, and counting the client's
// PINGs, which it never answers.
type fakeH2Server struct {
	pings atomic.Int32
}

func startFakeH2Server(t *testing.T, refuse bool, pingEvery time.Duration) (*h2Transport, *fakeH2Server, *bytes.Buffer) {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })
	srv := &fakeH2Server{}
	var wmu sync.Mutex
	fr := http2.NewFramer(c2, c2)
	go func() {
		preface := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(c2, preface); err != nil {
			return
		}
		// The client reads only once its own preface is written.
		go func() {
			wmu.Lock()
			fr.WriteSettings()
			wmu.Unlock()
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
				}
			case *http2.HeadersFrame:
				if refuse {
					// Not from this goroutine: the client may be blocked
					// writing to it.
					go func(id uint32) {
						wmu.Lock()
						fr.WriteRSTStream(id, http2.ErrCodeRefusedStream)
						wmu.Unlock()
					}(f.StreamID)
				}
			}
		}
	}()
	if pingEvery > 0 {
		go func() {
			for {
				time.Sleep(pingEvery)
				wmu.Lock()
				err := fr.WritePing(false, [8]byte{})
				wmu.Unlock()
				if err != nil {
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
	return tr, srv, &logs
}

// TestStalledConnectOnLiveConnection: a CONNECT unanswered for connectStall
// on a connection that keeps reading, as one whose server takes no new
// streams does, is abandoned in time for its caller to redial, and the
// transport is retired while the tunnels it carries go on.
func TestStalledConnectOnLiveConnection(t *testing.T) {
	setVar(t, &connectStall, 100*time.Millisecond)
	setVar(t, &pingTimeout, 50*time.Millisecond)
	tr, _, logs := startFakeH2Server(t, false, 10*time.Millisecond)
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
	tr, _, _ := startFakeH2Server(t, true, 0)
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
	tr, srv, _ := startFakeH2Server(t, false, 10*time.Millisecond)
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
