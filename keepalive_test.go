package samizdat

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// quietH2 is an HTTP/2 server for one connection that sends nothing after
// its SETTINGS except what it's asked to: a 200 for each CONNECT, replies to
// pings, and each DATA frame back on its stream.
type quietH2 struct {
	answerConnects, ackPings, echo bool
	// pings counts the pings it has received.
	pings atomic.Int32
}

func (q *quietH2) serve(conn net.Conn) {
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
			if !q.answerConnects {
				continue
			}
			var block bytes.Buffer
			hpack.NewEncoder(&block).WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
			err = fr.WriteHeaders(http2.HeadersFrameParam{
				StreamID:      f.StreamID,
				BlockFragment: block.Bytes(),
				EndHeaders:    true,
			})
		case *http2.DataFrame:
			if q.echo && len(f.Data()) > 0 {
				err = fr.WriteData(f.StreamID, false, bytes.Clone(f.Data()))
			}
		case *http2.PingFrame:
			if f.IsAck() {
				continue
			}
			q.pings.Add(1)
			if q.ackPings {
				err = fr.WritePing(true, f.Data)
			}
		}
		if err != nil {
			return
		}
	}
}

// serveQuietH2 serves one connection with a quietH2 that answers CONNECTs as
// asked and acks pings as asked.
func serveQuietH2(conn net.Conn, answerConnects, ackPings bool) {
	(&quietH2{answerConnects: answerConnects, ackPings: ackPings}).serve(conn)
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

// openQuietTunnel opens a tunnel on a new transport whose server answers
// CONNECTs and acks pings if asked.
func openQuietTunnel(t *testing.T, ka keepAlive, ackPings bool) (*h2Transport, net.Conn) {
	t.Helper()
	return openTunnelOn(t, ka, &quietH2{answerConnects: true, ackPings: ackPings})
}

// openTunnelOn opens a tunnel on a new transport served by q.
func openTunnelOn(t *testing.T, ka keepAlive, q *quietH2) (*h2Transport, net.Conn) {
	t.Helper()
	// A TCP pair, not net.Pipe: both ends write their SETTINGS before
	// reading, which deadlocks on an unbuffered pipe.
	c1, c2 := tcpPair(t)
	go q.serve(c2)

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

// waitUntil polls cond until it holds or 5 seconds pass.
func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal(what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestQuietConnectionIsNotPinged: a connection carrying a tunnel that sends
// nothing is never pinged, however long it stays quiet. Pings on a clock
// would keep a phone's radio awake and repeat at a fixed interval on an
// otherwise silent connection.
func TestQuietConnectionIsNotPinged(t *testing.T) {
	ka := keepAlive{interval: 20 * time.Millisecond, timeout: 100 * time.Millisecond}
	q := &quietH2{answerConnects: true, ackPings: true}
	tr, _ := openTunnelOn(t, ka, q)

	time.Sleep(300 * time.Millisecond) // fifteen intervals
	if n := q.pings.Load(); n != 0 {
		t.Fatalf("quiet connection was pinged %d times", n)
	}
	if tr.conn.closed.Load() {
		t.Fatal("quiet connection was closed")
	}
}

// TestAnsweredWriteIsNotPinged: a tunnel write that something is read after,
// within the interval, starts no ping.
func TestAnsweredWriteIsNotPinged(t *testing.T) {
	ka := keepAlive{interval: 200 * time.Millisecond, timeout: time.Second}
	q := &quietH2{answerConnects: true, ackPings: true, echo: true}
	_, tunnel := openTunnelOn(t, ka, q)

	for range 3 {
		if _, err := tunnel.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(tunnel, make([]byte, 5)); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(400 * time.Millisecond) // two intervals
	if n := q.pings.Load(); n != 0 {
		t.Fatalf("answered writes started %d pings", n)
	}
}

// TestUnansweredWriteIsPingedOnce: a tunnel write with nothing read after it
// starts one ping; its reply keeps the connection open and nothing follows
// it until the next write.
func TestUnansweredWriteIsPingedOnce(t *testing.T) {
	ka := keepAlive{interval: 20 * time.Millisecond, timeout: 500 * time.Millisecond}
	q := &quietH2{answerConnects: true, ackPings: true}
	tr, tunnel := openTunnelOn(t, ka, q)

	if _, err := tunnel.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "unanswered write never started a ping", func() bool { return q.pings.Load() > 0 })
	time.Sleep(200 * time.Millisecond) // ten intervals
	if n := q.pings.Load(); n != 1 {
		t.Fatalf("one unanswered write started %d pings", n)
	}
	if tr.conn.closed.Load() {
		t.Fatal("connection closed though its ping was answered")
	}

	// The next unanswered write starts the next ping.
	if _, err := tunnel.Write([]byte("again")); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "second unanswered write never started a ping", func() bool { return q.pings.Load() == 2 })
}

// TestUnansweredPingClosesConnection: when a tunnel's write and the ping
// after it both go unanswered, the connection is closed: its tunnels fail,
// it takes no new ones, and what fails on it is marked conn-fatal so the
// dial retries elsewhere, instead of looking alive until TCP gives up.
func TestUnansweredPingClosesConnection(t *testing.T) {
	ka := keepAlive{interval: 20 * time.Millisecond, timeout: 50 * time.Millisecond}
	q := &quietH2{answerConnects: true}
	tr, tunnel := openTunnelOn(t, ka, q)

	readErr := make(chan error, 1)
	go func() {
		_, err := tunnel.Read(make([]byte, 1))
		readErr <- err
	}()
	if _, err := tunnel.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-readErr:
		if err == nil {
			t.Fatal("read on a dead connection returned data")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel still open long after its ping went unanswered")
	}
	waitUntil(t, "connection still open after its ping went unanswered", tr.conn.closed.Load)
	if !tr.pingLost.Load() {
		t.Fatal("closed over an unanswered ping without marking it lost")
	}
	if tr.tryReserve() {
		t.Fatal("transport with a closed connection still takes new streams")
	}
	if q.pings.Load() != 1 {
		t.Fatalf("server saw %d pings, want 1", q.pings.Load())
	}
}

// TestNoKeepAliveLeavesUnansweredWrite: with pings off, an unanswered write
// starts nothing and the connection stays open.
func TestNoKeepAliveLeavesUnansweredWrite(t *testing.T) {
	q := &quietH2{answerConnects: true, ackPings: true}
	tr, tunnel := openTunnelOn(t, keepAlive{}, q)
	if _, err := tunnel.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}

	time.Sleep(200 * time.Millisecond)
	if tr.conn.closed.Load() {
		t.Fatal("connection closed with keepalive off")
	}
	if n := q.pings.Load(); n != 0 {
		t.Fatalf("keepalive off, but %d pings sent", n)
	}
}

// TestSecondConnectionRefused: once x/net won't open streams on the
// connection, the pool refuses instead of handing x/net a second one.
func TestSecondConnectionRefused(t *testing.T) {
	tr, _ := openQuietTunnel(t, keepAlive{}, true)
	cc := tr.pool.clientConn()
	if cc == nil {
		t.Fatal("no ClientConn after a CONNECT")
	}
	cc.SetDoNotReuse()
	if _, err := tr.pool.GetClientConn(nil, "example.com:443"); !errors.Is(err, errSecondDial) {
		t.Fatalf("GetClientConn on a spent connection = %v, want errSecondDial", err)
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
	if c.KeepAliveInterval != 5*time.Second || c.KeepAliveTimeout != 10*time.Second {
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
