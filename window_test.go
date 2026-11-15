package samizdat

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// advertisedWindows returns the stream window the client's SETTINGS
// advertise and the connection window its first WINDOW_UPDATE grants, for a
// transport created with win.
func advertisedWindows(t *testing.T, win receiveWindows) (perStream, perConn uint32) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	tr, err := newH2Transport(c1, "example.com:443", 10, win)
	if err != nil {
		t.Fatal(err)
	}
	tr.activeStreams.Store(1)
	// The transport dials, and so writes its preface, on its first CONNECT.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	go tr.openReserved(ctx, "example.com:443")

	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c2, preface); err != nil {
		t.Fatal(err)
	}
	fr := http2.NewFramer(io.Discard, c2)
	for perStream == 0 || perConn == 0 {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if v, ok := f.Value(http2.SettingInitialWindowSize); ok {
				perStream = v
			}
		case *http2.WindowUpdateFrame:
			if f.StreamID == 0 {
				perConn = f.Increment
			}
		}
	}
	return perStream, perConn
}

// TestReceiveWindowsAdvertised: the client tells the server the windows it
// was configured with, which bound how much the server queues on a
// connection ahead of what the client has read.
func TestReceiveWindowsAdvertised(t *testing.T) {
	stream, conn := advertisedWindows(t, receiveWindows{perStream: 300 << 10, perConn: 1200 << 10})
	if stream != 300<<10 || conn != 1200<<10 {
		t.Fatalf("advertised stream=%d conn=%d, want %d and %d", stream, conn, 300<<10, 1200<<10)
	}
}

// TestReceiveWindowDefaults: a client configured with no windows gets
// samizdat's defaults, not x/net's 4MiB per stream and 1GiB per connection.
func TestReceiveWindowDefaults(t *testing.T) {
	var cfg ClientConfig
	cfg.applyDefaults()
	if cfg.MaxReceiveBufferPerStream != 512<<10 || cfg.MaxReceiveBufferPerConn != 2<<20 {
		t.Fatalf("defaults are %d and %d", cfg.MaxReceiveBufferPerStream, cfg.MaxReceiveBufferPerConn)
	}
	stream, conn := advertisedWindows(t, receiveWindows{
		perStream: cfg.MaxReceiveBufferPerStream,
		perConn:   cfg.MaxReceiveBufferPerConn,
	})
	if stream != 512<<10 || conn != 2<<20 {
		t.Fatalf("advertised stream=%d conn=%d", stream, conn)
	}
}

// TestFailedConnectLogged: a failed CONNECT is logged with what tells a
// silent connection from a busy one, and never with its destination,
// including one whose encoding fails and whose error would quote it.
func TestFailedConnectLogged(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	go io.Copy(io.Discard, c2)
	tr, err := newH2Transport(c1, "example.com:443", 10, receiveWindows{})
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	tr.logger = slog.New(slog.NewTextHandler(&logs, nil))

	tr.activeStreams.Store(1)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if _, err := tr.openReserved(ctx, "secret.example:443"); err == nil {
		t.Fatal("CONNECT to a server that never answers succeeded")
	}
	tr.activeStreams.Store(1)
	if _, err := tr.openReserved(context.Background(), "ü.xn--99999999999999.example:443"); err == nil {
		t.Fatal("CONNECT to an unencodable destination succeeded")
	}

	out := logs.String()
	if !strings.Contains(out, "samizdat CONNECT failed") || !strings.Contains(out, "read_while_waiting=false") {
		t.Errorf("logs lack the failed CONNECT:\n%s", out)
	}
	for _, leak := range []string{"secret", "99999999999999", "ü"} {
		if strings.Contains(out, leak) {
			t.Errorf("logs name a destination (%q):\n%s", leak, out)
		}
	}
}
