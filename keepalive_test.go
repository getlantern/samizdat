package samizdat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// serveQuietH2 is an HTTP/2 server for one connection that sends nothing
// after its SETTINGS except, if asked, a 200 for each CONNECT and replies to
// pings.
func serveQuietH2(conn net.Conn, answerConnects, ackPings bool) {
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(conn, preface); err != nil {
		return
	}
	fr := http2.NewFramer(conn, conn)
	if err := fr.WriteSettings(); err != nil {
		return
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if !f.IsAck() {
				err = fr.WriteSettingsAck()
			}
		case *http2.HeadersFrame:
			if !answerConnects {
				continue
			}
			var block bytes.Buffer
			hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			err = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      f.StreamID,
				BlockFragment: block.Bytes(),
				EndHeaders:    true,
			})
		case *http2.PingFrame:
			if ackPings && !f.IsAck() {
				err = fr.WritePing(true, f.Data)
			}
		}
		if err != nil {
			return
		}
	}
}

// tcpPair returns the two ends of a loopback TCP connection.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := ln.Accept()
		accepted <- c
	}()
	c1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c2 := <-accepted
	if c2 == nil {
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { c1.Close(); c2.Close() })
	return c1, c2
}

// openQuietTunnel opens a tunnel on a new transport whose server is
// serveQuietH2.
func openQuietTunnel(t *testing.T, ka keepAlive, ackPings bool) (*h2Transport, net.Conn) {
	t.Helper()
	// A TCP pair, not net.Pipe: both ends write their SETTINGS before
	// reading, which deadlocks on an unbuffered pipe.
	c1, c2 := tcpPair(t)
	go serveQuietH2(c2, true, ackPings)

	tr, err := newH2Transport(c1, "example.com:443", 10, receiveWindows{}, ka)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tr.close() })
	if !tr.tryReserve() {
		t.Fatal("new transport has no stream slot")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tunnel, err := tr.openReserved(ctx, "example.org:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tunnel.Close() })
	return tr, tunnel
}

// TestKeepAliveClosesSilentConnection: a connection whose server stops
// answering must be closed by an unanswered ping, failing its tunnels and
// taking no new ones, instead of looking alive until TCP gives up.
func TestKeepAliveClosesSilentConnection(t *testing.T) {
	ka := keepAlive{interval: 50 * time.Millisecond, timeout: 50 * time.Millisecond}
	tr, tunnel := openQuietTunnel(t, ka, false)

	readErr := make(chan error, 1)
	go func() {
		_, err := tunnel.Read(make([]byte, 1))
		readErr <- err
	}()
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read on a silent connection returned data")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel still open long after the ping went unanswered")
	}

	// x/net fails the streams just before it closes the connection.
	deadline := time.Now().Add(5 * time.Second)
	for !tr.conn.closed.Load() {
		if time.Now().After(deadline) {
			t.Fatal("connection still open after the ping went unanswered")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if tr.tryReserve() {
		t.Fatal("transport with a closed connection still takes new streams")
	}
}

// TestDialContextRetriesAfterLostPing: a CONNECT still waiting when its
// connection's ping goes unanswered must be retried on a new connection.
func TestDialContextRetriesAfterLostPing(t *testing.T) {
	dead1, dead2 := tcpPair(t)
	go serveQuietH2(dead2, false, false)
	live1, live2 := tcpPair(t)
	go serveQuietH2(live2, true, true)

	ka := keepAlive{interval: 20 * time.Millisecond, timeout: 20 * time.Millisecond}
	var transports []*h2Transport
	for _, c := range []net.Conn{dead1, live1} {
		tr, err := newH2Transport(c, "example.com:443", 10, receiveWindows{}, ka)
		if err != nil {
			t.Fatal(err)
		}
		transports = append(transports, tr)
	}
	created := 0
	pool := newConnPool(10, time.Hour, func(context.Context) (*h2Transport, error) {
		if created >= len(transports) {
			return nil, fmt.Errorf("no transport left")
		}
		created++
		return transports[created-1], nil
	})
	defer pool.close()
	c := &Client{pool: pool}

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := c.DialContext(dialCtx, "tcp", "example.org:443")
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	conn.Close()
	if created != 2 {
		t.Errorf("created %d transports, want 2", created)
	}
}

// TestKeepAliveKeepsAnsweringConnection: a quiet connection whose server
// answers pings stays open.
func TestKeepAliveKeepsAnsweringConnection(t *testing.T) {
	// The wait is several ping timeouts long, so the connection would close
	// in it if the replies didn't count.
	ka := keepAlive{interval: 20 * time.Millisecond, timeout: 100 * time.Millisecond}
	tr, _ := openQuietTunnel(t, ka, true)
	// The server sends nothing after the CONNECT reply but ping acks.
	before := tr.conn.bytesRead.Load()

	time.Sleep(500 * time.Millisecond)
	if tr.conn.closed.Load() {
		t.Fatal("connection closed though its pings were answered")
	}
	if tr.conn.bytesRead.Load() == before {
		t.Fatal("no ping was answered")
	}
}

// TestNoKeepAliveLeavesSilentConnection: with pings off, nothing is sent on a
// quiet connection and it stays open.
func TestNoKeepAliveLeavesSilentConnection(t *testing.T) {
	tr, _ := openQuietTunnel(t, keepAlive{}, false)

	time.Sleep(200 * time.Millisecond)
	if tr.conn.closed.Load() {
		t.Fatal("connection closed with keepalive off")
	}
}

// TestPoolDropsTransportWithClosedConnection: cleanup retires a transport
// whose connection was closed under it, and removes it once it has no stream.
func TestPoolDropsTransportWithClosedConnection(t *testing.T) {
	tr, tunnel := openQuietTunnel(t, keepAlive{}, false)
	p := &connPool{idleTimeout: time.Hour, transports: []*h2Transport{tr}}

	tr.conn.Close()
	p.cleanup()
	if !tr.retired.Load() {
		t.Fatal("cleanup didn't retire a transport whose connection closed")
	}
	if len(p.transports) != 1 {
		t.Fatal("cleanup dropped a transport that still has a stream")
	}

	// The tunnel gives back its slot once its read pump has stopped.
	tunnel.Close()
	deadline := time.Now().Add(5 * time.Second)
	for tr.streamCount() > 0 {
		if time.Now().After(deadline) {
			t.Fatal("closed tunnel never released its stream")
		}
		time.Sleep(5 * time.Millisecond)
	}
	p.cleanup()
	if !tr.isClosed() || len(p.transports) != 0 {
		t.Fatalf("transport closed=%v, pool holds %d after its last stream ended", tr.isClosed(), len(p.transports))
	}
}

func TestKeepAliveDefaults(t *testing.T) {
	var c ClientConfig
	c.applyDefaults()
	if c.KeepAliveInterval != 15*time.Second || c.KeepAliveTimeout != 10*time.Second {
		t.Errorf("defaults = %v, %v", c.KeepAliveInterval, c.KeepAliveTimeout)
	}
	off := ClientConfig{KeepAliveInterval: -1}
	off.applyDefaults()
	if off.KeepAliveInterval >= 0 {
		t.Errorf("negative interval became %v", off.KeepAliveInterval)
	}
}

func TestConnFatalErrnos(t *testing.T) {
	for _, errno := range fatalErrnos {
		err := fmt.Errorf("CONNECT: %w", &net.OpError{Op: "read", Err: errno})
		if !connFatal(err) {
			t.Errorf("connFatal(%v) = false", err)
		}
	}
	if connFatal(fmt.Errorf("CONNECT: %w", syscall.EINVAL)) {
		t.Error("connFatal(EINVAL) = true")
	}
}

func TestMarkPingLost(t *testing.T) {
	var tr h2Transport
	lost := errors.New("http2: client connection lost")
	if got := tr.markPingLost(lost); connFatal(got) {
		t.Errorf("without a lost ping, %v is conn-fatal", got)
	}

	tr.pingLost.Store(true)
	if got := tr.markPingLost(lost); !connFatal(got) {
		t.Errorf("after a lost ping, %v is not conn-fatal", got)
	}
	reset := http2.StreamError{StreamID: 3, Code: http2.ErrCodeRefusedStream}
	if got := tr.markPingLost(reset); got != error(reset) {
		t.Errorf("stream reset became %v", got)
	}
	if tr.markPingLost(nil) != nil {
		t.Error("nil error was wrapped")
	}
}

func TestPingJitter(t *testing.T) {
	const d = 15 * time.Second
	seen := map[time.Duration]bool{}
	for range 1000 {
		got := pingJitter(d)
		if got < d*3/4 || got > d*5/4 {
			t.Fatalf("pingJitter(%v) = %v, outside a quarter either way", d, got)
		}
		seen[got] = true
	}
	if len(seen) < 2 {
		t.Error("pingJitter returned the same interval every time")
	}
	for _, d := range []time.Duration{0, -1} {
		if got := pingJitter(d); got != d {
			t.Errorf("pingJitter(%v) = %v, want it unchanged", d, got)
		}
	}
}
