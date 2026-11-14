package samizdat

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strings"
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

// TestUnansweredPingClosesConnection: a connection that receives nothing is
// pinged, and closed when the ping goes unanswered, so a transport whose
// connection died without a word doesn't keep taking CONNECTs.
func TestUnansweredPingClosesConnection(t *testing.T) {
	setVar(t, &h2ReadIdleTimeout, 50*time.Millisecond)
	setVar(t, &h2PingTimeout, 50*time.Millisecond)
	setVar(t, &silentConnectRetire, time.Hour)
	tr, logs := startQuietServer(t, 0)

	// The first CONNECT makes x/net take the connection; it then pings it
	// and closes it when the ping goes unanswered.
	tr.activeStreams.Store(1)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := tr.openReserved(ctx, "example.com:443"); err == nil {
		t.Fatal("CONNECT to a server that never answers succeeded")
	}
	if !tr.conn.closed.Load() {
		t.Fatal("x/net didn't close a connection whose ping went unanswered")
	}

	tr.activeStreams.Store(1)
	if _, err := tr.openReserved(context.Background(), "example.com:443"); err == nil {
		t.Fatal("CONNECT on a closed connection succeeded")
	}
	if !tr.retired.Load() {
		t.Fatal("transport wasn't retired after x/net closed its connection")
	}
	if !strings.Contains(logs.String(), "connection closed under the transport") {
		t.Errorf("logs lack the close reason:\n%s", logs)
	}
}
