package samizdat

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
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
	if cfg.MaxReceiveBufferPerStream != 512<<10 || cfg.MaxReceiveBufferPerConn != 8<<20 {
		t.Fatalf("defaults are %d and %d", cfg.MaxReceiveBufferPerStream, cfg.MaxReceiveBufferPerConn)
	}
	stream, conn := advertisedWindows(t, receiveWindows{
		perStream: cfg.MaxReceiveBufferPerStream,
		perConn:   cfg.MaxReceiveBufferPerConn,
	})
	if stream != 512<<10 || conn != 8<<20 {
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

// TestStuckTunnelsLeaveOthersFlowing: tunnels whose readers have stopped
// keep their windows full, and must not use up the connection's window
// before the rest of its tunnels can get data.
func TestStuckTunnelsLeaveOthersFlowing(t *testing.T) {
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr: "127.0.0.1:0",
		PrivateKey: serverPriv,
		ShortIDs:   [][8]byte{shortID},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
			if destination == "hello.example:443" {
				conn.Write([]byte("hello"))
				return
			}
			zeros := make([]byte, 32<<10)
			for {
				if _, err := conn.Write(zeros); err != nil {
					return
				}
			}
		},
	})
	client, err := NewClient(ClientConfig{
		ServerAddr: ln.Addr().String(),
		ServerName: "test.example.com",
		PublicKey:  serverPub,
		ShortID:    shortID,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Eight tunnels that never read: 4MiB of their windows at the defaults.
	for range 8 {
		c, err := client.DialContext(context.Background(), "tcp", "flood.example:443")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	time.Sleep(500 * time.Millisecond) // for their windows to fill

	c, err := client.DialContext(context.Background(), "tcp", "hello.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(c, got); err != nil || string(got) != "hello" {
		t.Fatalf("a tunnel beside stuck ones read %q, %v", got, err)
	}
}

// TestStalledUploadsLeaveOthersFlowing: tunnels whose destinations have
// stopped reading keep the server's windows full, and must not use up the
// connection's window before the rest of its tunnels can send.
func TestStalledUploadsLeaveOthersFlowing(t *testing.T) {
	t.Run("xnet", func(t *testing.T) { testStalledUploads(t, false) })
	t.Run("lean", func(t *testing.T) { testStalledUploads(t, true) })
}

func testStalledUploads(t *testing.T, lean bool) {
	stop := make(chan struct{})
	defer close(stop)
	client, _, _ := startShapingPairWith(t, lean, true, true, func(ctx context.Context, conn net.Conn, destination string) {
		defer conn.Close()
		if destination == "stalled.example:443" {
			<-stop // a destination that has stopped reading
			return
		}
		io.Copy(conn, conn)
	})

	// Uploads the server can't pass on, holding all but one tunnel's worth of
	// the connection's window.
	stalled := serverConnRecvWindow/serverStreamRecvWindow - 1
	filled := make(chan struct{}, stalled)
	for range stalled {
		c, err := client.DialContext(context.Background(), "tcp", "stalled.example:443")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		go func() {
			buf := make([]byte, 64<<10)
			for written := 0; written < 2*serverStreamRecvWindow; {
				n, err := c.Write(buf)
				if written < serverStreamRecvWindow && written+n >= serverStreamRecvWindow {
					filled <- struct{}{}
				}
				written += n
				if err != nil {
					return
				}
			}
		}()
	}
	for range stalled {
		waitFor(t, filled, "a stalled upload to write a full window")
	}

	c, err := client.DialContext(context.Background(), "tcp", "echo.example:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	// More than the window left, so the server has to return what the echo
	// reads as it goes. In a goroutine: a Write held up by flow control
	// ignores the deadline.
	msg := bytes.Repeat([]byte("samizdat"), 2*serverStreamRecvWindow/8)
	go c.Write(msg)
	got := make([]byte, len(msg))
	if n, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("a tunnel beside stalled uploads echoed %d of %d bytes: %v", n, len(msg), err)
	}
}

// TestReceiveWindowRange: windows x/net would silently replace with its own
// defaults are refused.
func TestReceiveWindowRange(t *testing.T) {
	_, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, cfg := range []ClientConfig{
		{MaxReceiveBufferPerStream: -1},
		{MaxReceiveBufferPerConn: 1000},
		{MaxReceiveBufferPerConn: -5},
		{MaxReceiveBufferPerConn: maxConnWindow + 1},
	} {
		cfg.ServerAddr, cfg.ServerName, cfg.PublicKey = "example.com:443", "example.com", pub
		if _, err := NewClient(cfg); err == nil {
			t.Errorf("NewClient accepted stream=%d conn=%d", cfg.MaxReceiveBufferPerStream, cfg.MaxReceiveBufferPerConn)
		}
	}
	for _, cfg := range []ClientConfig{
		{MaxReceiveBufferPerStream: 1, MaxReceiveBufferPerConn: 65535},
		{MaxReceiveBufferPerStream: math.MaxInt32, MaxReceiveBufferPerConn: maxConnWindow},
	} {
		cfg.ServerAddr, cfg.ServerName, cfg.PublicKey = "example.com:443", "example.com", pub
		c, err := NewClient(cfg)
		if err != nil {
			t.Errorf("NewClient refused stream=%d conn=%d: %v", cfg.MaxReceiveBufferPerStream, cfg.MaxReceiveBufferPerConn, err)
			continue
		}
		c.Close()
	}
}

// TestRefusedConnectLogged: a CONNECT the server answers with an error status
// is logged with that status, and without its destination.
func TestRefusedConnectLogged(t *testing.T) {
	tr := newTestTransport(roundTripperFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusForbidden, Body: io.NopCloser(strings.NewReader(""))}, nil
	}))
	var logs bytes.Buffer
	tr.logger = slog.New(slog.NewTextHandler(&logs, nil))
	tr.activeStreams.Store(1)
	if _, err := tr.openReserved(context.Background(), "secret.example:443"); err == nil {
		t.Fatal("a refused CONNECT succeeded")
	}
	out := logs.String()
	if !strings.Contains(out, "samizdat CONNECT refused") || !strings.Contains(out, "status=403") {
		t.Errorf("logs lack the refusal:\n%s", out)
	}
	if strings.Contains(out, "secret") {
		t.Errorf("logs name the destination:\n%s", out)
	}
}
