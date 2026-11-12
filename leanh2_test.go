package samizdat

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// h2Peer is a hand-driven HTTP/2 client on a plain TCP connection to one of
// the two servers, serveH2 (x/net) or serveLeanH2, run without TLS.
type h2Peer struct {
	conn net.Conn
	// served is closed when the server's handler for the connection
	// returns.
	served chan struct{}
	fr     *http2.Framer
	enc    *hpack.Encoder
	hbuf   bytes.Buffer
}

// startH2Pair serves one connection with the chosen implementation and
// returns a client connected to it.
func startH2Pair(t *testing.T, lean bool, handler ConnHandler) *h2Peer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{config: ServerConfig{MaxConcurrentStreams: 4, Handler: handler}}
	served := make(chan struct{})
	go func() {
		defer close(served)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if lean {
			bc := &batchConn{Conn: conn}
			s.serveLeanH2(bc, bc, conn, [8]byte{})
		} else {
			s.serveH2(conn, conn, [8]byte{})
		}
	}()
	conn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	p := &h2Peer{conn: conn, fr: http2.NewFramer(conn, conn), served: served}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	p.enc = hpack.NewEncoder(&p.hbuf)
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	return p
}

// handshake sends what x/net's Transport sends first.
func (p *h2Peer) handshake(t *testing.T) {
	t.Helper()
	if _, err := p.conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	if err := p.fr.WriteSettings(
		http2.Setting{ID: http2.SettingEnablePush, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20},
		http2.Setting{ID: http2.SettingMaxHeaderListSize, Val: 10 << 20},
	); err != nil {
		t.Fatal(err)
	}
	if err := p.fr.WriteWindowUpdate(0, 1<<30); err != nil {
		t.Fatal(err)
	}
}

func (p *h2Peer) request(t *testing.T, id uint32, method, authority string, endStream bool, extra ...hpack.HeaderField) {
	t.Helper()
	p.hbuf.Reset()
	p.enc.WriteField(hpack.HeaderField{Name: ":method", Value: method})
	p.enc.WriteField(hpack.HeaderField{Name: ":authority", Value: authority})
	for _, f := range extra {
		p.enc.WriteField(f)
	}
	// Large blocks go out as HEADERS plus CONTINUATIONs of at most the
	// default frame size.
	block := p.hbuf.Bytes()
	const chunk = 16384
	first := block[:min(len(block), chunk)]
	if err := p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: id, BlockFragment: first, EndHeaders: len(block) <= chunk, EndStream: endStream,
	}); err != nil {
		t.Fatal(err)
	}
	for rest := block[len(first):]; len(rest) > 0; {
		n := min(len(rest), chunk)
		if err := p.fr.WriteContinuation(id, n == len(rest), rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
}

// describe renders a frame for comparison, leaving out what varies between
// runs (the date header's value).
func describe(f http2.Frame) string {
	h := f.Header()
	s := fmt.Sprintf("%v flags=%v stream=%d", h.Type, h.Flags, h.StreamID)
	switch f := f.(type) {
	case *http2.SettingsFrame:
		f.ForeachSetting(func(st http2.Setting) error {
			s += fmt.Sprintf(" %v=%d", st.ID, st.Val)
			return nil
		})
	case *http2.WindowUpdateFrame:
		s += fmt.Sprintf(" incr=%d", f.Increment)
	case *http2.MetaHeadersFrame:
		for _, hf := range f.Fields {
			if hf.Name == "date" {
				s += " date"
			} else {
				s += fmt.Sprintf(" %s=%s", hf.Name, hf.Value)
			}
		}
	case *http2.DataFrame:
		s += fmt.Sprintf(" len=%d", len(f.Data()))
	case *http2.RSTStreamFrame:
		s += fmt.Sprintf(" code=%v", f.ErrCode)
	case *http2.GoAwayFrame:
		s += fmt.Sprintf(" last=%d code=%v", f.LastStreamID, f.ErrCode)
	}
	return s
}

// transcript drives one exchange and returns the frames the server sent.
func transcript(t *testing.T, lean bool, method, authority string, extra ...hpack.HeaderField) []string {
	p := startH2Pair(t, lean, func(ctx context.Context, conn net.Conn, dest string) {
		conn.Write([]byte("hello"))
	})
	p.handshake(t)
	p.request(t, 1, method, authority, true, extra...)
	var out []string
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			if len(out) > 0 && strings.HasPrefix(out[len(out)-1], "GOAWAY") {
				return out // the server ended the connection, as expected
			}
			t.Fatalf("lean=%v: %v (so far %q)", lean, err, out)
		}
		out = append(out, describe(f))
		h := f.Header()
		if h.StreamID == 1 && (h.Flags.Has(http2.FlagDataEndStream) || h.Type == http2.FrameRSTStream) {
			return out
		}
	}
}

// canonical renders a transcript for comparison. x/net's writer sends its
// connection WINDOW_UPDATE and its SETTINGS ACK in either order from run to
// run, so the connection-level frames after the first SETTINGS are compared
// as a set; stream frames keep their order.
func canonical(frames []string) string {
	var conn, stream []string
	for i, f := range frames {
		if i > 0 && strings.Contains(f, " stream=0") {
			conn = append(conn, f)
		} else {
			stream = append(stream, f)
		}
	}
	slices.Sort(conn)
	return fmt.Sprintf("%q then %q", conn, stream)
}

// TestLeanH2MatchesXNet checks that a client sees the same frames from the
// lean server as from x/net's: settings, window, response headers, data and
// stream end.
func TestLeanH2MatchesXNet(t *testing.T) {
	path := []hpack.HeaderField{{Name: ":scheme", Value: "https"}, {Name: ":path", Value: "/"}}
	for _, c := range []struct {
		name, method, authority string
		extra                   []hpack.HeaderField
	}{
		{"connect", "CONNECT", "example.com:443", nil},
		{"connect without authority", "CONNECT", "", nil},
		{"connect with path", "CONNECT", "example.com:443", path},
		{"connect with only scheme", "CONNECT", "example.com:443", path[:1]},
		{"extended connect", "CONNECT", "example.com:443", append(slices.Clone(path), hpack.HeaderField{Name: ":protocol", Value: "websocket"})},
		{"connect with protocol only", "CONNECT", "example.com:443", []hpack.HeaderField{{Name: ":protocol", Value: "websocket"}}},
		{"get with ftp scheme", "GET", "example.com", []hpack.HeaderField{{Name: ":scheme", Value: "ftp"}, {Name: ":path", Value: "/"}}},
		{"get", "GET", "example.com", path},
		{"head", "HEAD", "example.com", path},
		{"head with header list too large", "HEAD", "example.com", append(slices.Clone(path), manyHeaders(70, 16<<10)...)},
		{"get without path", "GET", "example.com", nil},
		{"no method", "", "example.com", path},
		{"header field too large", "CONNECT", "example.com:443", []hpack.HeaderField{{Name: "x-big", Value: strings.Repeat("a", 1100<<10)}}},
		{"header list too large", "CONNECT", "example.com:443", manyHeaders(70, 16<<10)},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := canonical(transcript(t, false, c.method, c.authority, c.extra...))
			got := canonical(transcript(t, true, c.method, c.authority, c.extra...))
			if got != want {
				t.Errorf("lean server frames differ\nx/net: %s\nlean:  %s", want, got)
			}
		})
	}
}

// startLeanPair runs a real samizdat client against a lean server whose
// handler is handler.
func startLeanPair(t *testing.T, handler ConnHandler) *Client {
	t.Helper()
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
		Handler:    handler,
		LeanH2:     true,
	})
	client, err := NewClient(ClientConfig{
		ServerAddr: ln.Addr().String(), ServerName: "test.example.com",
		PublicKey: pub, ShortID: sid,
		Jitter: false, TCPFragmentation: false, RecordFragmentation: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client
}

// TestLeanH2LargeTransfers moves several times the 1 MiB flow-control
// windows both ways on concurrent streams and checks every byte.
func TestLeanH2LargeTransfers(t *testing.T) {
	const streams, size = 8, 6 << 20
	client := startLeanPair(t, func(ctx context.Context, conn net.Conn, dest string) {
		defer conn.Close()
		// Echo, hashing nothing: the client checks the bytes.
		io.Copy(conn, conn)
	})
	var wg sync.WaitGroup
	for i := 0; i < streams; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "echo:1")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			payload := make([]byte, size)
			rand.Read(payload)
			want := sha256.Sum256(payload)
			go func() {
				conn.Write(payload)
				conn.(interface{ CloseWrite() error }).CloseWrite()
			}()
			h := sha256.New()
			n, err := io.Copy(h, conn)
			if err != nil || n != size {
				t.Errorf("echoed %d of %d bytes: %v", n, size, err)
				return
			}
			if !bytes.Equal(h.Sum(nil), want[:]) {
				t.Error("echoed bytes differ")
			}
		}()
	}
	wg.Wait()
}

// TestLeanH2ResetEndsOnlyThatStream cancels one download mid-stream: its
// handler's writes must fail and its context end, while a second stream on
// the same connection carries on.
func TestLeanH2ResetEndsOnlyThatStream(t *testing.T) {
	handlerErr := make(chan error, 1)
	ctxDone := make(chan struct{})
	client := startLeanPair(t, func(ctx context.Context, conn net.Conn, dest string) {
		defer conn.Close()
		buf := make([]byte, 32<<10)
		if dest == "endless:1" {
			for {
				if _, err := conn.Write(buf); err != nil {
					handlerErr <- err
					<-ctx.Done()
					close(ctxDone)
					return
				}
			}
		}
		conn.Write([]byte("still here"))
	})

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	victim, err := client.DialContext(ctx, "tcp", "endless:1")
	if err != nil {
		t.Fatal(err)
	}
	io.CopyN(io.Discard, victim, 4<<20)

	// Abort the stream the way the client does when a read stalls: it
	// closes the response body, which sends RST_STREAM.
	sc := victim.(*streamConn)
	sc.rwc.(*h2StreamRWC).abort()
	select {
	case err := <-handlerErr:
		if !errors.Is(err, errLeanStreamReset) {
			t.Errorf("handler write error = %v, want a stream reset", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("handler kept writing after the client reset the stream")
	}
	select {
	case <-ctxDone:
	case <-time.After(5 * time.Second):
		t.Fatal("handler context didn't end on reset")
	}

	other, err := client.DialContext(ctx, "tcp", "plain:1")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.(interface{ CloseWrite() error }).CloseWrite()
	got, err := io.ReadAll(other)
	if err != nil || string(got) != "still here" {
		t.Errorf("second stream got %q, %v", got, err)
	}
}

// TestLeanH2RefusesStreamsOverTheLimit opens more streams than
// MaxConcurrentStreams allows: the extra one is refused, and the connection
// keeps serving.
func TestLeanH2RefusesStreamsOverTheLimit(t *testing.T) {
	release := make(chan struct{})
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {
		<-release
	})
	defer close(release)
	p.handshake(t)
	for id := uint32(1); id <= 9; id += 2 { // five streams; the limit is four
		p.request(t, id, "CONNECT", "example.com:443", false)
	}
	refused := false
	for !refused {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if rst, ok := f.(*http2.RSTStreamFrame); ok {
			if rst.StreamID != 9 || rst.ErrCode != http2.ErrCodeRefusedStream {
				t.Fatalf("got %s, want stream 9 refused", describe(f))
			}
			refused = true
		}
	}
	// A PING still gets its answer.
	if err := p.fr.WritePing(false, [8]byte{1, 2, 3}); err != nil {
		t.Fatal(err)
	}
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if ping, ok := f.(*http2.PingFrame); ok && ping.IsAck() && ping.Data == [8]byte{1, 2, 3} {
			return
		}
	}
}

// TestLeanH2ManyStreams runs many short echo streams at once, the shape of a
// browser's traffic through a proxy, to shake out races.
func TestLeanH2ManyStreams(t *testing.T) {
	var served atomic.Int32
	client := startLeanPair(t, func(ctx context.Context, conn net.Conn, dest string) {
		defer conn.Close()
		served.Add(1)
		io.Copy(conn, conn)
	})
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			conn, err := client.DialContext(ctx, "tcp", "echo:1")
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			msg := bytes.Repeat([]byte{byte(i)}, 1+i*97)
			go func() {
				conn.Write(msg)
				conn.(interface{ CloseWrite() error }).CloseWrite()
			}()
			got, err := io.ReadAll(conn)
			if err != nil || !bytes.Equal(got, msg) {
				t.Errorf("stream %d: got %d bytes, %v", i, len(got), err)
			}
		}(i)
	}
	wg.Wait()
	if served.Load() != 200 {
		t.Errorf("handler ran %d times, want 200", served.Load())
	}
}

// TestLeanH2ClosesOnControlFrameFlood sends PINGs without reading the
// answers. The server must end the connection once more than
// leanMaxQueuedControl answers are queued, rather than queue them without
// bound. It runs over net.Pipe, whose writes block until the other end
// reads: the server's writer blocks on its first answer, so the answers
// back up at once, whatever the kernel's socket buffering.
func TestLeanH2ClosesOnControlFrameFlood(t *testing.T) {
	serverEnd, clientEnd := net.Pipe()
	defer clientEnd.Close()
	s := &Server{config: ServerConfig{MaxConcurrentStreams: 4,
		Handler: func(ctx context.Context, conn net.Conn, dest string) {}}}
	served := make(chan struct{})
	go func() {
		defer close(served)
		bc := &batchConn{Conn: serverEnd}
		s.serveLeanH2(bc, bc, serverEnd, [8]byte{})
	}()

	fr := http2.NewFramer(clientEnd, nil)
	go func() {
		if _, err := clientEnd.Write([]byte(http2.ClientPreface)); err != nil {
			return
		}
		if fr.WriteSettings() != nil {
			return
		}
		for fr.WritePing(false, [8]byte{}) == nil {
		}
	}()
	select {
	case <-served:
	case <-time.After(30 * time.Second):
		buf := make([]byte, 1<<20)
		t.Fatalf("server kept the connection open under a PING flood; goroutines:\n%s", buf[:runtime.Stack(buf, true)])
	}
}

// TestLeanH2HandlerPanicResetsOnlyItsStream: a panicking handler must not
// take the server down; its stream is reset and the next one is served.
func TestLeanH2HandlerPanicResetsOnlyItsStream(t *testing.T) {
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {
		if dest == "boom:1" {
			panic("handler bug")
		}
		conn.Write([]byte("ok"))
	})
	p.handshake(t)
	p.request(t, 1, "CONNECT", "boom:1", true)
	p.request(t, 3, "CONNECT", "fine:1", true)
	reset, served := false, false
	for !reset || !served {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatalf("reset=%v served=%v: %v", reset, served, err)
		}
		switch f := f.(type) {
		case *http2.RSTStreamFrame:
			if f.StreamID == 1 && f.ErrCode == http2.ErrCodeInternal {
				reset = true
			}
		case *http2.DataFrame:
			if f.StreamID == 3 && string(f.Data()) == "ok" {
				served = true
			}
		}
	}
}

// TestLeanH2ResetFreesItsSlot: a stream the client reset stops counting
// against MaxConcurrentStreams even while its handler hasn't returned, as
// with x/net's server, so a new stream is accepted rather than refused.
func TestLeanH2ResetFreesItsSlot(t *testing.T) {
	release := make(chan struct{})
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {
		if dest == "new:1" {
			conn.Write([]byte("ok"))
			return
		}
		<-release // ignores its context, like a handler stuck dialing
	})
	defer close(release)
	p.handshake(t)
	for id := uint32(1); id <= 7; id += 2 { // the limit is four
		p.request(t, id, "CONNECT", "stuck:1", false)
	}
	if err := p.fr.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	p.request(t, 9, "CONNECT", "new:1", true)
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if rst, ok := f.(*http2.RSTStreamFrame); ok && rst.StreamID == 9 {
			t.Fatalf("stream 9 refused: %v", rst.ErrCode)
		}
		if d, ok := f.(*http2.DataFrame); ok && d.StreamID == 9 && string(d.Data()) == "ok" {
			return
		}
	}
}

// TestLeanH2UnreadUploadDoesNotStallTheConnection: a handler that returns
// without reading its upload must not leave the shared connection window
// spent, or every other upload on the connection stalls until the drain
// times out.
func TestLeanH2UnreadUploadDoesNotStallTheConnection(t *testing.T) {
	client := startLeanPair(t, func(ctx context.Context, conn net.Conn, dest string) {
		if dest == "ignore:1" {
			// Read nothing while the upload fills the stream's and the
			// connection's windows, then return without closing the conn.
			time.Sleep(500 * time.Millisecond)
			return
		}
		defer conn.Close()
		n, _ := io.Copy(io.Discard, conn)
		conn.Write([]byte(strconv.FormatInt(n, 10)))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	ignored, err := client.DialContext(ctx, "tcp", "ignore:1")
	if err != nil {
		t.Fatal(err)
	}
	defer ignored.Close()
	go ignored.Write(make([]byte, 4<<20))

	time.Sleep(time.Second)
	start := time.Now()
	counted, err := client.DialContext(ctx, "tcp", "count:1")
	if err != nil {
		t.Fatal(err)
	}
	defer counted.Close()
	const size = 3 << 20
	go func() {
		counted.Write(make([]byte, size))
		counted.(interface{ CloseWrite() error }).CloseWrite()
	}()
	got, err := io.ReadAll(counted)
	if err != nil || string(got) != strconv.Itoa(size) {
		t.Fatalf("second upload: got %q, %v", got, err)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("second upload took %v; the ignored stream held up the connection", d)
	}
}

// TestConnFatalSecondDial: a refused second dial means x/net's pool has given
// up on the connection, so the transport must be retired.
func TestConnFatalSecondDial(t *testing.T) {
	if !connFatal(fmt.Errorf("CONNECT: %w", errSecondDial)) {
		t.Error("connFatal(errSecondDial) = false")
	}
}

// TestLeanH2ClosesOnRapidReset opens streams and resets each once its
// handler is running, with handlers that never return. Reset streams free
// their MaxConcurrentStreams slots, so only the cap on running handlers stops
// the client from piling them up; past it the server must close the
// connection.
func TestLeanH2ClosesOnRapidReset(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {
		<-release
	})
	p.handshake(t)
	limit := leanMaxHandlersFactor * 4 // startH2Pair's MaxConcurrentStreams is 4
	for id := uint32(1); id < uint32(4*limit); id += 2 {
		p.request(t, id, "CONNECT", "stuck:1", false)
		// Wait for the 200: the handler is running.
		for {
			f, err := p.fr.ReadFrame()
			if err != nil {
				if id/2 < uint32(limit) {
					t.Fatalf("connection closed after only %d streams: %v", id/2, err)
				}
				return // closed past the cap
			}
			if h, ok := f.(*http2.MetaHeadersFrame); ok && h.StreamID == id {
				break
			}
		}
		if err := p.fr.WriteRSTStream(id, http2.ErrCodeCancel); err != nil {
			return
		}
	}
	t.Fatal("server kept the connection open under rapid reset")
}

// TestRetiredTransportKeepsItsStreams: when x/net's Transport stops using the
// connection for new streams (errSecondDial), the transport must stop taking
// new tunnels but keep the ones it carries, and close once the last ends.
func TestRetiredTransportKeepsItsStreams(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	tr, err := newH2Transport(c1, "example.com:443", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.activeStreams.Store(1)
	tr.retire()
	if tr.isClosed() {
		t.Fatal("retiring closed a transport that still carries a stream")
	}
	if tr.tryReserve() {
		t.Fatal("a retired transport still takes new streams")
	}
	pr, pw := io.Pipe()
	defer pr.Close()
	rwc := &h2StreamRWC{reader: io.NopCloser(strings.NewReader("")), writer: pw, transport: tr}
	rwc.Close()
	if !tr.isClosed() {
		t.Fatal("retired transport stayed open after its last stream ended")
	}
}

// TestLeanH2HonorsClientHeaderTableSize: a client that advertises a 0-byte
// HPACK table must get responses it can decode with one, so the encoder may
// not index the date header across responses.
func TestLeanH2HonorsClientHeaderTableSize(t *testing.T) {
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {})
	p.fr.ReadMetaHeaders = hpack.NewDecoder(0, nil)
	if _, err := p.conn.Write([]byte(http2.ClientPreface)); err != nil {
		t.Fatal(err)
	}
	if err := p.fr.WriteSettings(
		http2.Setting{ID: http2.SettingHeaderTableSize, Val: 0},
		http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4 << 20},
	); err != nil {
		t.Fatal(err)
	}
	// Wait for the server's ack, so the setting applies to the responses.
	for acked := false; !acked; {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if sf, ok := f.(*http2.SettingsFrame); ok && sf.IsAck() {
			acked = true
		}
	}
	for id := uint32(1); id <= 5; id += 2 {
		p.request(t, id, "CONNECT", "example.com:443", true)
	}
	responses := 0
	for responses < 3 {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatalf("after %d responses: %v", responses, err)
		}
		if _, ok := f.(*http2.MetaHeadersFrame); ok {
			responses++
		}
	}
}

// TestLeanH2LingeringWriteIsNotTruncated: a handler that returns while a
// Write it started is still in progress (here, blocked on flow control
// because the client isn't reading yet) must not have that write cut short
// when the client's END_STREAM arrives, as serverStreamConn.shutdown waits
// for an in-flight write.
func TestLeanH2LingeringWriteIsNotTruncated(t *testing.T) {
	const size = 16 << 20
	client := startLeanPair(t, func(ctx context.Context, conn net.Conn, dest string) {
		go conn.Write(make([]byte, size))
		// Return only once the Write is in progress (blocked on flow
		// control, since the client isn't reading yet).
		st := conn.(*leanStreamConn).st
		for {
			st.c.mu.Lock()
			writing := st.writing > 0
			st.c.mu.Unlock()
			if writing {
				return
			}
			time.Sleep(time.Millisecond)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "dl:1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(interface{ CloseWrite() error }).CloseWrite()
	time.Sleep(300 * time.Millisecond) // let the handler return first
	n, err := io.Copy(io.Discard, conn)
	if n != size {
		t.Fatalf("got %d of %d bytes: %v", n, size, err)
	}
}

// TestLeanH2ResetReleasesUnreadUpload: data buffered for a stream the client
// resets must go back to the shared connection window at once, even while
// its handler is stuck, or sibling uploads stall.
func TestLeanH2ResetReleasesUnreadUpload(t *testing.T) {
	release := make(chan struct{})
	defer close(release)
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {
		if dest == "stuck:1" {
			<-release // reads nothing and ignores its context
			return
		}
		n, _ := io.Copy(io.Discard, conn)
		conn.Write([]byte(strconv.FormatInt(n, 10)))
	})
	p.handshake(t)
	go func() {
		for {
			if _, err := p.fr.ReadFrame(); err != nil {
				return
			}
		}
	}()
	// Fill the connection window (1 MiB) on stream 1, then reset it.
	p.request(t, 1, "CONNECT", "stuck:1", false)
	chunk := make([]byte, 16384)
	for sent := 0; sent < 1<<20-16384; sent += len(chunk) {
		if err := p.fr.WriteData(1, false, chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.fr.WriteRSTStream(1, http2.ErrCodeCancel); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	// The server has credited the connection window back only if it
	// released stream 1's buffered data: probe by checking the server
	// accepts 1 MiB more on another stream without a FLOW_CONTROL error.
	p.request(t, 3, "CONNECT", "count:1", false)
	for sent := 0; sent < 1<<20-16384; sent += len(chunk) {
		if err := p.fr.WriteData(3, false, chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := p.fr.WriteData(3, true, nil); err != nil {
		t.Fatal(err)
	}
	// A server that kept stream 1's bytes would see stream 3 overrun the
	// connection window and drop the connection.
	time.Sleep(300 * time.Millisecond)
	if err := p.fr.WritePing(false, [8]byte{}); err != nil {
		t.Fatalf("connection dropped: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	if err := p.fr.WritePing(false, [8]byte{}); err != nil {
		t.Fatalf("connection dropped: %v", err)
	}
}

// TestRetiredTransportWaitsForOpeningStream: a transport retired while a
// CONNECT is still waiting for its response must stay open for it.
func TestRetiredTransportWaitsForOpeningStream(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	tr, err := newH2Transport(c1, "example.com:443", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	tr.activeStreams.Add(1) // the slot reserved before RoundTrip
	tr.retire()
	if tr.isClosed() {
		t.Fatal("retiring closed a transport with a CONNECT in flight")
	}
	tr.releaseStream()
	if !tr.isClosed() {
		t.Fatal("retired transport stayed open after its last stream ended")
	}
}

// manyHeaders returns n distinct fields of size bytes each.
func manyHeaders(n, size int) []hpack.HeaderField {
	fs := make([]hpack.HeaderField, n)
	for i := range fs {
		fs[i] = hpack.HeaderField{Name: fmt.Sprintf("x-h%d", i), Value: strings.Repeat("a", size)}
	}
	return fs
}

// TestLeanH2AcceptsTrailers: HEADERS with END_STREAM on an open stream are
// trailers, which x/net's server accepts; they must end the client's side of
// that stream, not the connection.
func TestLeanH2AcceptsTrailers(t *testing.T) {
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {
		n, _ := io.Copy(io.Discard, conn)
		conn.Write([]byte(strconv.FormatInt(n, 10)))
	})
	p.handshake(t)
	p.request(t, 1, "CONNECT", "example.com:443", false)
	if err := p.fr.WriteData(1, false, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	p.hbuf.Reset()
	p.enc.WriteField(hpack.HeaderField{Name: "x-trailer", Value: "1"})
	if err := p.fr.WriteHeaders(http2.HeadersFrameParam{
		StreamID: 1, BlockFragment: p.hbuf.Bytes(), EndHeaders: true, EndStream: true,
	}); err != nil {
		t.Fatal(err)
	}
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if g, ok := f.(*http2.GoAwayFrame); ok {
			t.Fatalf("connection ended: %v", g.ErrCode)
		}
		if d, ok := f.(*http2.DataFrame); ok && d.StreamID == 1 && string(d.Data()) == "5" {
			return
		}
	}
}

// TestLeanH2BoundsStartup: a client that never sends its preface is dropped
// after leanPrefaceTimeout, as with x/net's server.
func TestLeanH2BoundsStartup(t *testing.T) {
	old := leanPrefaceTimeout
	leanPrefaceTimeout = 200 * time.Millisecond
	defer func() { leanPrefaceTimeout = old }()
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {})
	select {
	case <-p.served:
	case <-time.After(5 * time.Second):
		t.Fatal("server kept a connection that never sent its preface")
	}
}

// TestLeanH2SerializesWritesOnAStream: two goroutines writing to the same
// stream must not have their bytes interleaved, even when a Write waits for
// flow-control credit partway through, as serverStreamConn serializes them.
func TestLeanH2SerializesWritesOnAStream(t *testing.T) {
	const size = 3 << 20
	client := startLeanPair(t, func(ctx context.Context, conn net.Conn, dest string) {
		var wg sync.WaitGroup
		for _, b := range []byte{'a', 'b'} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn.Write(bytes.Repeat([]byte{b}, size))
			}()
		}
		wg.Wait()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "dl:1")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.(interface{ CloseWrite() error }).CloseWrite()
	got, err := io.ReadAll(conn)
	if err != nil || len(got) != 2*size {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
	if got[0] == got[size] || bytes.Count(got[:size], got[:1]) != size {
		t.Fatal("the two writes were interleaved")
	}
}

// TestLeanH2EndsStreamWithNegativeWindow: a client that shrinks
// INITIAL_WINDOW_SIZE after data went out leaves the stream's send window
// negative. Ending the stream needs no credit and must still work, rather
// than computing a negative frame length.
func TestLeanH2EndsStreamWithNegativeWindow(t *testing.T) {
	shrunk := make(chan struct{})
	p := startH2Pair(t, true, func(ctx context.Context, conn net.Conn, dest string) {
		conn.Write(make([]byte, 100))
		<-shrunk
	})
	p.handshake(t)
	p.request(t, 1, "CONNECT", "example.com:443", false)
	for got := false; !got; {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := f.(*http2.DataFrame); ok && d.StreamID == 1 && len(d.Data()) > 0 {
			got = true
		}
	}
	// 100 bytes sent; a 0 window leaves the stream at -100.
	if err := p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatal(err)
	}
	if err := p.fr.WriteData(1, true, nil); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond) // the SETTINGS is applied
	close(shrunk)
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := f.(*http2.DataFrame); ok && d.StreamID == 1 && d.StreamEnded() {
			return
		}
		if r, ok := f.(*http2.RSTStreamFrame); ok && r.StreamID == 1 {
			t.Fatalf("stream reset with %v instead of ending", r.ErrCode)
		}
	}
}

// TestLeanH2MatchesXNetOnBadPeers runs misbehaving clients against both
// servers and compares the frames each sends back before ending the
// connection.
func TestLeanH2MatchesXNetOnBadPeers(t *testing.T) {
	// settle lets a stream's response HEADERS go out first: x/net's server
	// writes them from another goroutine, so they could otherwise follow the
	// frames under test.
	settle := func() { time.Sleep(200 * time.Millisecond) }
	// idleData ends a script whose server would otherwise keep the
	// connection open: DATA on a stream never opened is a connection error.
	idleData := func(p *h2Peer) {
		settle()
		p.fr.WriteData(99, false, []byte("x"))
	}
	trailers := func(p *h2Peer, fields ...hpack.HeaderField) {
		p.hbuf.Reset()
		for _, f := range fields {
			p.enc.WriteField(f)
		}
		p.fr.WriteHeaders(http2.HeadersFrameParam{StreamID: 1, BlockFragment: p.hbuf.Bytes(), EndHeaders: true, EndStream: true})
	}
	cases := []struct {
		name   string
		hold   bool // the handler runs until its stream ends
		script func(t *testing.T, p *h2Peer)
	}{
		{"no settings after the preface", false, func(t *testing.T, p *h2Peer) {
			p.conn.Write([]byte(http2.ClientPreface))
			p.fr.WritePing(false, [8]byte{})
		}},
		{"frame too large", false, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.fr.WriteRawFrame(http2.FrameData, 0, 1, make([]byte, leanMaxReadFrameSize+1))
		}},
		{"headers for a gone stream", false, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.request(t, 1, "CONNECT", "example.com:443", true)
			time.Sleep(300 * time.Millisecond) // the stream finishes
			p.request(t, 1, "CONNECT", "example.com:443", true)
		}},
		{"data on an idle stream", false, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.fr.WriteData(3, false, []byte("x"))
		}},
		{"window update on an idle stream", false, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.fr.WriteWindowUpdate(3, 1)
		}},
		{"rst_stream on an idle stream", false, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.fr.WriteRSTStream(3, http2.ErrCodeCancel)
		}},
		{"data after end_stream", true, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.request(t, 1, "CONNECT", "example.com:443", true)
			settle()
			p.fr.WriteData(1, false, []byte("x"))
			idleData(p)
		}},
		{"trailers with a pseudo-header", true, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.request(t, 1, "CONNECT", "example.com:443", false)
			settle()
			trailers(p, hpack.HeaderField{Name: ":path", Value: "/"})
			idleData(p)
		}},
		{"stream window overflow", true, func(t *testing.T, p *h2Peer) {
			p.handshake(t)
			p.request(t, 1, "CONNECT", "example.com:443", false)
			settle()
			p.fr.WriteWindowUpdate(1, 1<<31-1)
			idleData(p)
		}},
		{"connection window overflow", false, func(t *testing.T, p *h2Peer) {
			p.handshake(t) // the connection window is now 1<<30 + 65535
			p.fr.WriteWindowUpdate(0, 1<<30)
		}},
		{"initial window size overflow", true, func(t *testing.T, p *h2Peer) {
			p.handshake(t) // initial window 4 MiB
			p.request(t, 1, "CONNECT", "example.com:443", false)
			settle()
			p.fr.WriteWindowUpdate(1, 1<<31-1-4<<20)
			p.fr.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 4<<20 + 1})
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			run := func(lean bool) string {
				p := startH2Pair(t, lean, func(ctx context.Context, conn net.Conn, dest string) {
					if c.hold {
						<-ctx.Done()
					}
				})
				go c.script(t, p)
				var out []string
				for {
					f, err := p.fr.ReadFrame()
					if err != nil {
						return canonical(out)
					}
					out = append(out, describe(f))
				}
			}
			if want, got := run(false), run(true); got != want {
				t.Errorf("lean server frames differ\nx/net: %s\nlean:  %s", want, got)
			}
		})
	}
}

// TestPoolClosedWhileDialing: a transport whose dial finishes after the pool
// closed must be closed, not added to the closed pool and leaked.
func TestPoolClosedWhileDialing(t *testing.T) {
	var pool *connPool
	var created *h2Transport
	pool = newConnPool(10, time.Minute, func(ctx context.Context) (*h2Transport, error) {
		pool.close()
		c1, c2 := net.Pipe()
		t.Cleanup(func() { c2.Close() })
		tr, err := newH2Transport(c1, "example.com:443", 10, nil)
		created = tr
		return tr, err
	})
	if _, err := pool.getTransport(context.Background()); err == nil {
		t.Fatal("getTransport succeeded on a pool closed during the dial")
	}
	if !created.isClosed() {
		t.Fatal("the transport dialed for a closed pool was left open")
	}
}

// TestLeanChunk: the writer's chunks are whole frames, as few as reach
// leanWriteChunk.
func TestLeanChunk(t *testing.T) {
	var b []byte
	for range 10 {
		b = appendFrameHeader(b, 16384, http2.FrameData, 0, 1)
		b = append(b, make([]byte, 16384)...)
	}
	const frame = leanFrameHeaderLen + 16384
	if got, want := len(leanChunk(b)), 4*frame; got != want {
		t.Errorf("chunk of ten frames = %d bytes, want %d", got, want)
	}
	if got := len(leanChunk(b[:2*frame])); got != 2*frame {
		t.Errorf("chunk of two frames = %d bytes, want %d", got, 2*frame)
	}
	if got := len(leanChunk(nil)); got != 0 {
		t.Errorf("chunk of nothing = %d bytes", got)
	}
}

// TestLeanH2ControlFramesPassQueuedData: a control frame queued while the
// writer is sending a full buffer of DATA to a slow client must go out after
// the chunk in flight, not after the whole buffer.
func TestLeanH2ControlFramesPassQueuedData(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	bc := &batchConn{Conn: c1}
	c := &leanConn{conn: bc, bc: bc, cancel: func() {}, writerDone: make(chan struct{})}
	c.wcond = sync.NewCond(&c.mu)
	const frames = 24 // 384 KiB of DATA, several chunks
	for range frames {
		c.wbuf = appendFrameHeader(c.wbuf, 16384, http2.FrameData, 0, 1)
		c.wbuf = append(c.wbuf, make([]byte, 16384)...)
	}
	go c.writeLoop()
	defer c.close()

	c2.SetDeadline(time.Now().Add(10 * time.Second))
	fr := http2.NewFramer(nil, c2)
	// The writer is now blocked sending its first chunk: the pipe hands over
	// only what is read.
	if _, err := fr.ReadFrame(); err != nil {
		t.Fatal(err)
	}
	c.mu.Lock()
	c.cbuf = appendFrameHeader(c.cbuf, 8, http2.FramePing, http2.FlagPingAck, 0)
	c.cbuf = append(c.cbuf, make([]byte, 8)...)
	c.queued()
	c.mu.Unlock()

	data := 1
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			t.Fatalf("after %d DATA frames: %v", data, err)
		}
		if f.Header().Type == http2.FramePing {
			break
		}
		data++
	}
	if most := leanWriteChunk/16384 + 1; data > most {
		t.Errorf("PING ACK followed %d DATA frames, want at most %d (one chunk)", data, most)
	}
	// The rest of the buffer still arrives, in order.
	for ; data < frames; data++ {
		if f, err := fr.ReadFrame(); err != nil || f.Header().Type != http2.FrameData {
			t.Fatalf("DATA frame %d: %v, %v", data, f, err)
		}
	}
}

// TestLeanH2ConnWindowUpdateWakesOnlyWaiters: a connection WINDOW_UPDATE
// wakes the streams waiting for connection credit, and no others.
func TestLeanH2ConnWindowUpdateWakesOnlyWaiters(t *testing.T) {
	c := &leanConn{streams: make(map[uint32]*leanStream), connSendWin: 0}
	c.wcond = sync.NewCond(&c.mu)
	waiter := &leanStream{c: c, id: 1, cond: sync.NewCond(&c.mu)}
	other := &leanStream{c: c, id: 3, cond: sync.NewCond(&c.mu)}
	c.streams[1], c.streams[3] = waiter, other

	woke := make(chan struct{})
	c.mu.Lock()
	go func() {
		c.mu.Lock()
		waiter.awaitCreditLocked()
		c.mu.Unlock()
		close(woke)
	}()
	c.mu.Unlock()
	for {
		c.mu.Lock()
		registered := waiter.waitingConn
		c.mu.Unlock()
		if registered {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if other.waitingConn || len(c.connWaiters) != 1 {
		t.Fatalf("connWaiters = %d streams, want only the waiting one", len(c.connWaiters))
	}
	if err := c.handleWindowUpdate(&http2.WindowUpdateFrame{Increment: 100}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-woke:
	case <-time.After(5 * time.Second):
		t.Fatal("the waiting stream was not woken")
	}
}

// TestFailedOpenLeavesIdleSince: a CONNECT that produces no tunnel gives its
// slot back without making the transport look recently used, so one whose
// CONNECTs keep failing still idles out.
func TestFailedOpenLeavesIdleSince(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()
	tr, err := newH2Transport(c1, "example.com:443", 10, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tr.close()
	old := time.Now().Add(-time.Hour).UnixNano()
	tr.idleSince.Store(old)
	if !tr.tryReserve() {
		t.Fatal("tryReserve failed on an empty transport")
	}
	tr.releaseReserved()
	if got := tr.idleSince.Load(); got != old {
		t.Errorf("a failed open moved idleSince by %v", time.Duration(got-old))
	}
	if !tr.tryReserve() {
		t.Fatal("tryReserve failed on an empty transport")
	}
	tr.releaseStream()
	if tr.idleSince.Load() == old {
		t.Error("a stream ending left idleSince unchanged")
	}
}
