package samizdat

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	mrand "math/rand/v2"
	"net"
	"os"
	"slices"
	"sync"
	"testing"
	"time"
)

func fixedEKM(seed byte) func(string, []byte, int) ([]byte, error) {
	return func(label string, _ []byte, n int) ([]byte, error) {
		b := bytes.Repeat([]byte{seed}, n)
		copy(b, label)
		return b, nil
	}
}

// TestShapingScheduleDeterministic: the same keying material gives both ends
// the same schedule and marker, different material a different schedule,
// and every schedule fits the framing and starts with the client.
func TestShapingScheduleDeterministic(t *testing.T) {
	a, ma, err := shapingSchedule(fixedEKM(1))
	if err != nil {
		t.Fatal(err)
	}
	b, mb, _ := shapingSchedule(fixedEKM(1))
	if !slices.Equal(a, b) || ma != mb {
		t.Fatalf("same keying material, different schedules: %v / %v", a, b)
	}
	if len(a) != shapingRecords {
		t.Fatalf("schedule of %d records, want %d", len(a), shapingRecords)
	}
	differ := false
	for seed := byte(2); seed < 200; seed++ {
		s, _, err := shapingSchedule(fixedEKM(seed))
		if err != nil {
			t.Fatal(err)
		}
		if !shapingScheduleFits(s) {
			t.Fatalf("seed %d: schedule %v doesn't fit the framing", seed, s)
		}
		if !slices.Equal(s, a) {
			differ = true
		}
	}
	if !differ {
		t.Fatal("every seed gave the same schedule")
	}
}

// shapedPipe runs a client and server shapedConn on a schedule over a pipe.
func shapedPipe(t *testing.T, sched []int) (client, server *shapedConn) {
	t.Helper()
	cc, sc := net.Pipe()
	marker := [shapingMarkerLen]byte{1, 2, 3, 4, 5, 6, 7, 8}
	client = newShapedConn(cc, sched, true, marker, false)
	server = newShapedConn(sc, sched, false, marker, false)
	t.Cleanup(func() { client.Close(); server.Close() })
	return client, server
}

// TestShapedConnCarriesDataBothWays: data written before and during the
// schedule arrives intact in both directions, as does bulk data after it,
// and the schedule runs whether or not either side has anything to send.
func TestShapedConnCarriesDataBothWays(t *testing.T) {
	for _, sched := range [][]int{
		{300, -1400, -1400, 100, -24, 24, -500, 1448, -31, 60},
		{32, 24, 24, 24, 24, 24, 24, 24, 24, 24},
		{40, -24, -24, -24, -24, -24, -24, -24, -24, -24},
	} {
		client, server := shapedPipe(t, sched)
		up := make([]byte, 200<<10)
		down := make([]byte, 300<<10)
		rand.Read(up)
		rand.Read(down)
		var wg sync.WaitGroup
		check := func(name string, w, r *shapedConn, want []byte) {
			defer wg.Done()
			go w.Write(want)
			got := make([]byte, len(want))
			if _, err := io.ReadFull(r, got); err != nil {
				t.Errorf("%v %s: %v", sched, name, err)
				return
			}
			if !bytes.Equal(got, want) {
				t.Errorf("%v %s: data differs", sched, name)
			}
		}
		wg.Add(2)
		go check("upload", client, server, up)
		go check("download", server, client, down)
		wg.Wait()
	}
}

// TestShapedConnIdleScheduleCompletes: with nothing to send, the schedule
// still runs to the end on padding alone and the connection passes data
// afterwards.
func TestShapedConnIdleScheduleCompletes(t *testing.T) {
	client, server := shapedPipe(t, []int{100, -200, 300, -400, 50, -60, 70, -80, 90, -100})
	deadline := time.Now().Add(5 * time.Second)
	for {
		client.mu.Lock()
		cs := client.shaping
		client.mu.Unlock()
		server.mu.Lock()
		ss := server.shaping
		server.mu.Unlock()
		if !cs && !ss {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("an idle schedule didn't finish")
		}
		time.Sleep(time.Millisecond)
	}
	go client.Write([]byte("after"))
	buf := make([]byte, 5)
	if _, err := io.ReadFull(server, buf); err != nil || string(buf) != "after" {
		t.Fatalf("after the schedule: %q, %v", buf, err)
	}
}

// TestShapedConnRejectsWrongMarker: a client record that doesn't start with
// the marker fails the connection rather than being read as data.
func TestShapedConnRejectsWrongMarker(t *testing.T) {
	cc, sc := net.Pipe()
	sched := []int{100, -100, 100, -100, 100, -100, 100, -100, 100, -100}
	client := newShapedConn(cc, sched, true, [shapingMarkerLen]byte{1}, false)
	server := newShapedConn(sc, sched, false, [shapingMarkerLen]byte{2}, false)
	defer client.Close()
	defer server.Close()
	_, err := server.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("wrong marker accepted")
	}
}

// startShapingPair starts a server and client, either of which may shape,
// over the chosen HTTP/2 server, with an echo handler, recording what each
// side writes.
func startShapingPair(t *testing.T, lean, serverShapes, clientShapes bool) (*Client, *writeRecorder, *writeRecorder) {
	t.Helper()
	return startShapingPairWith(t, lean, serverShapes, clientShapes, func(ctx context.Context, conn net.Conn, dest string) {
		defer conn.Close()
		io.Copy(conn, conn)
	})
}

func startShapingPairWith(t *testing.T, lean, serverShapes, clientShapes bool, handler ConnHandler) (*Client, *writeRecorder, *writeRecorder) {
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
	server, err := NewServer(ServerConfig{
		PrivateKey:     priv,
		ShortIDs:       [][8]byte{sid},
		CertPEM:        certPEM,
		KeyPEM:         keyPEM,
		LeanH2:         lean,
		DisableShaping: !serverShapes,
		Handler:        handler,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fromServer, fromClient := &writeRecorder{}, &writeRecorder{}
	go server.Serve(&recordedListener{Listener: ln, r: fromServer})
	t.Cleanup(func() { server.Close() })
	// These tests choose whether the client shapes; SAMIZDAT_TEST_LEGACY_CLIENTS
	// mustn't override that.
	legacy := testLegacyClients
	testLegacyClients = false
	defer func() { testLegacyClients = legacy }()
	client, err := NewClient(ClientConfig{
		ServerAddr:     ln.Addr().String(),
		ServerName:     "test.example.com",
		PublicKey:      pub,
		ShortID:        sid,
		DisableShaping: !clientShapes,
		ConnectTimeout: 5 * time.Second,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &recordedConn{Conn: c, r: fromClient}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })
	return client, fromServer, fromClient
}

func echoThrough(t *testing.T, client *Client, size int) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	payload := make([]byte, size)
	rand.Read(payload)
	go conn.Write(payload)
	got := make([]byte, size)
	if _, err := io.ReadFull(conn, got); err != nil {
		return err
	}
	if !bytes.Equal(got, payload) {
		return errors.New("echoed bytes differ")
	}
	return nil
}

// containsRun reports whether want appears in order, contiguously, in got.
func containsRun(got, want []int) bool {
	for i := 0; i+len(want) <= len(got); i++ {
		if slices.Equal(got[i:i+len(want)], want) {
			return true
		}
	}
	return false
}

// TestShapingEndToEnd: a shaping client and server move data both ways on
// either HTTP/2 server, and each side's TLS records include its part of the
// schedule, in order and at the scheduled sizes.
func TestShapingEndToEnd(t *testing.T) {
	for _, lean := range []bool{false, true} {
		name := map[bool]string{false: "xnet", true: "lean"}[lean]
		t.Run(name, func(t *testing.T) {
			var mu sync.Mutex
			scheds := map[bool][]int{}
			shapingScheduled = func(client bool, sched []int) {
				mu.Lock()
				scheds[client] = sched
				mu.Unlock()
			}
			defer func() { shapingScheduled = nil }()

			client, fromServer, fromClient := startShapingPair(t, lean, true, true)
			if err := echoThrough(t, client, 256<<10); err != nil {
				t.Fatal(err)
			}
			mu.Lock()
			defer mu.Unlock()
			if !slices.Equal(scheds[true], scheds[false]) || len(scheds[true]) != shapingRecords {
				t.Fatalf("client schedule %v, server %v", scheds[true], scheds[false])
			}
			var mine = map[bool][]int{}
			for _, s := range scheds[true] {
				mine[s > 0] = append(mine[s > 0], abs(s))
			}
			if got := appDataRecordSizes(t, fromClient.bytes()); !containsRun(got, mine[true]) {
				t.Errorf("client records %v don't include its schedule %v", got[:min(len(got), 20)], mine[true])
			}
			if got := appDataRecordSizes(t, fromServer.bytes()); !containsRun(got, mine[false]) {
				t.Errorf("server records %v don't include its schedule %v", got[:min(len(got), 20)], mine[false])
			}
		})
	}
}

// TestShapingServerAcceptsClientsThatDontShape: a server that accepts
// shaping serves clients without it as before.
func TestShapingServerAcceptsClientsThatDontShape(t *testing.T) {
	for _, lean := range []bool{false, true} {
		client, _, _ := startShapingPair(t, lean, true, false)
		if err := echoThrough(t, client, 64<<10); err != nil {
			t.Fatalf("lean=%v: %v", lean, err)
		}
	}
}

// TestShapingClientFailsOnServerWithout: a shaping client against a server
// that doesn't accept shaping fails promptly instead of hanging.
func TestShapingClientFailsOnServerWithout(t *testing.T) {
	client, _, _ := startShapingPair(t, false, false, true)
	start := time.Now()
	if err := echoThrough(t, client, 1024); err == nil {
		t.Fatal("shaping client worked against a server without shaping")
	}
	if d := time.Since(start); d > 9*time.Second {
		t.Fatalf("failed only after %v", d)
	}
}

// shapingModelGolden is cmd/shapingmodel's output for its tiny test profile
// (goldenHex in cmd/shapingmodel/main_test.go): position 0 is a client
// packet of 100 bytes (weight 3) or a server packet of 200 (weight 1); at
// position 1, after a client packet under 150 bytes comes a server packet
// of 777, and after a server packet of 150 or more a client packet of 100.
const shapingModelGolden = "535a534d0102000100ff00000200c80055556480ffff00000000012c01000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000000000000000000000000000000000000000000000000000000" +
	"0000000000000001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000100010001000100010001" +
	"0001000100010001000100010001000100010001000200020064000100000078" +
	"00000000000100090305000000020000010001000080ffff01000001000100ff" +
	"ff01000080ffff01000100ffff"

// TestShapingModelGolden: the runtime reads the generator's format, follows
// each position's conditional rows, draws sizes from the bins, falls back on
// direction when the previous packet has no row, and weights outcomes.
func TestShapingModelGolden(t *testing.T) {
	raw, err := hex.DecodeString(shapingModelGolden)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseShapingModel(raw)
	if err != nil {
		t.Fatal(err)
	}
	rng := mrand.New(mrand.NewChaCha8([32]byte{}))
	counts := map[string]int{}
	for range 4000 {
		s := m.schedule(rng, 10, false)
		counts[fmt.Sprint(s)]++
	}
	if len(counts) != 2 || counts["[100 -777]"] < 2800 || counts["[100 -777]"] > 3200 || counts["[-200 100]"] < 800 {
		t.Fatalf("schedules %v, want [100 -777] about 3 times as often as [-200 100] and nothing else", counts)
	}
	for range 100 {
		if s := m.schedule(rng, 10, true); !slices.Equal(s, []int{100, -777}) {
			t.Fatalf("client-first schedule %v, want [100 -777]", s)
		}
	}
	// Without its row, a client packet falls back to what follows client
	// packets in general.
	clear(m.positions[1].rows)
	if s := m.schedule(rng, 10, true); !slices.Equal(s, []int{100, -777}) {
		t.Fatalf("fallback schedule %v, want [100 -777]", s)
	}
}

// TestShapingLeanEarlyBulkDownload: a download that fills the shaping queue
// while the schedule still runs completes on the lean server, whose batching
// would otherwise hold the schedule's own records behind a blocked Write.
func TestShapingLeanEarlyBulkDownload(t *testing.T) {
	const size = 4 << 20
	// Each client turn after the CONNECT waits out a long grace period, so
	// the handler fills the server's queue while server records remain.
	old := shapingGrace
	shapingGrace = 300 * time.Millisecond
	shapingScheduleOverride = []int{400, -100, 400, -100, 100, -100, 100, -100, 100, -100}
	defer func() { shapingGrace, shapingScheduleOverride = old, nil }()
	client, _, _ := startShapingPairWith(t, true, true, true, func(ctx context.Context, conn net.Conn, dest string) {
		defer conn.Close()
		conn.Write(make([]byte, size))
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	if n, err := io.CopyN(io.Discard, conn, size); err != nil {
		t.Fatalf("downloaded %d of %d bytes: %v", n, size, err)
	}
}

// TestShapedConnZeroGraceIdleSchedules: with a grace period that expires at
// once, idle schedules still run to the end, time after time.
func TestShapedConnZeroGraceIdleSchedules(t *testing.T) {
	old := shapingGrace
	shapingGrace = time.Nanosecond
	defer func() { shapingGrace = old }()
	for i := range 50 {
		client, server := shapedPipe(t, []int{60, -70, 80, -90, 100, -110, 120, -130, 140, -150})
		go client.Write([]byte("x"))
		buf := make([]byte, 1)
		server.SetReadDeadline(time.Now().Add(5 * time.Second))
		if _, err := io.ReadFull(server, buf); err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
	}
}

// TestShapedConnHonorsDeadlines: while the schedule is stuck (its peer never
// reads), Read and a Write that must wait for queue room return at their
// deadlines.
func TestShapedConnHonorsDeadlines(t *testing.T) {
	cc, sc := net.Pipe()
	defer sc.Close()
	c := newShapedConn(cc, []int{100, -100, 100, -100, 100, -100, 100, -100, 100, -100}, true, [shapingMarkerLen]byte{}, false)
	defer c.Close()

	c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	start := time.Now()
	if _, err := c.Read(make([]byte, 1)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read: %v, want a deadline error", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Read returned after %v", d)
	}

	// An expired write deadline fails even a Write the queue has room for.
	c.SetWriteDeadline(time.Now().Add(-time.Second))
	if _, err := c.Write([]byte("x")); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("short Write past its deadline: %v, want a deadline error", err)
	}

	c.SetWriteDeadline(time.Now().Add(100 * time.Millisecond))
	start = time.Now()
	if _, err := c.Write(make([]byte, 2*shapingMaxQueued)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Write: %v, want a deadline error", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("Write returned after %v", d)
	}
}

// TestShapedConnRejectsOversizedLength: a record whose length field runs
// past its end fails the connection instead of panicking.
func TestShapedConnRejectsOversizedLength(t *testing.T) {
	cc, sc := net.Pipe()
	defer cc.Close()
	sched := []int{100, -100, 100, -100, 100, -100, 100, -100, 100, -100}
	server := newShapedConn(sc, sched, false, [shapingMarkerLen]byte{}, true)
	defer server.Close()
	rec := make([]byte, 100-tls13RecordOverhead-shapingMarkerLen)
	rec[0], rec[1] = 0xff, 0xff
	go cc.Write(rec)
	server.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err := server.Read(make([]byte, 1))
	if err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read: %v, want the connection failed", err)
	}
}

// TestShapingServerDropsSilentClient: an authenticated client that never
// sends anything is dropped once shapingPeekTimeout passes.
func TestShapingServerDropsSilentClient(t *testing.T) {
	old := shapingPeekTimeout
	shapingPeekTimeout = 200 * time.Millisecond
	defer func() { shapingPeekTimeout = old }()
	client, _, _ := startShapingPair(t, false, true, false)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	uc, err := client.dialConn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer uc.Close()
	uc.SetReadDeadline(time.Now().Add(5 * time.Second))
	start := time.Now()
	_, err = uc.Read(make([]byte, 1))
	if errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatal("server kept a silent client past shapingPeekTimeout")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("dropped only after %v", d)
	}
}

// TestShapedConnScheduleTimesOut: a peer that stops reading partway leaves
// the schedule blocked writing; shapingTimeout fails the connection.
func TestShapedConnScheduleTimesOut(t *testing.T) {
	old := shapingTimeout
	shapingTimeout = 100 * time.Millisecond
	defer func() { shapingTimeout = old }()
	cc, sc := net.Pipe()
	defer sc.Close()
	c := newShapedConn(cc, []int{100, -100, 100, -100, 100, -100, 100, -100, 100, -100}, true, [shapingMarkerLen]byte{}, false)
	defer c.Close()
	start := time.Now()
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("Read succeeded on a stuck schedule")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("failed after %v", d)
	}
}

// failingConn fails every Write after the first n, slowly, so a Read can
// get into the connection before the failure.
type failingConn struct {
	net.Conn
	mu sync.Mutex
	n  int
}

func (c *failingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == 0 {
		time.Sleep(200 * time.Millisecond)
		return 0, errors.New("write failed")
	}
	c.n--
	return c.Conn.Write(b)
}

// TestShapedConnFlushFailureWakesReader: when the flush of what was queued
// during the schedule fails, a Read already waiting on the connection
// returns instead of hanging.
func TestShapedConnFlushFailureWakesReader(t *testing.T) {
	sched := []int{100, -100, 100, -100, 100, -100, 100, -100, 100, -100}
	cc, sc := net.Pipe()
	// The client's five records go through; the flush after them fails.
	client := newShapedConn(&failingConn{Conn: cc, n: 5}, sched, true, [shapingMarkerLen]byte{}, false)
	server := newShapedConn(sc, sched, false, [shapingMarkerLen]byte{}, false)
	defer client.Close()
	defer server.Close()
	// More than the schedule's records carry, so some is left to flush.
	client.Write(make([]byte, 10<<10))
	go io.Copy(io.Discard, server)
	done := make(chan error, 1)
	go func() {
		_, err := client.Read(make([]byte, 1))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("Read succeeded after the flush failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read still blocked after the flush failed")
	}
}

// TestShapingParseRejectsBadBins: a model whose outcomes refer to bins it
// doesn't have is refused at load, not left to panic while sampling.
func TestShapingParseRejectsBadBins(t *testing.T) {
	raw, err := hex.DecodeString(shapingModelGolden)
	if err != nil {
		t.Fatal(err)
	}
	m, err := parseShapingModel(raw)
	if err != nil {
		t.Fatal(err)
	}
	p := &m.positions[1]
	lookup := p.lookup
	p.lookup = nil
	if p.validate() == nil {
		t.Fatal("empty size lookup accepted")
	}
	p.lookup = lookup
	p.fallback[0].outs[0].value = uint16(len(p.bins))
	if p.validate() == nil {
		t.Fatal("outcome past the last bin accepted")
	}
}

// TestShapingParseRejectsMissingFirstRow: a model with nothing to draw the
// first record from is refused at load, not left to panic while sampling.
func TestShapingParseRejectsMissingFirstRow(t *testing.T) {
	raw, err := hex.DecodeString(shapingModelGolden)
	if err != nil {
		t.Fatal(err)
	}
	// Position 0's row count is the uint16 right after the 6-byte header and
	// its size kind; the row follows.
	bad := append([]byte(nil), raw[:7]...)
	bad = append(bad, 0, 0)
	rowLen := 1 + 2 + 2 + 2*4 // prefix dir, prefix value, count, two outcomes
	bad = append(bad, raw[9+rowLen:]...)
	if _, err := parseShapingModel(bad); err == nil {
		t.Fatal("model without a first row accepted")
	}
}
