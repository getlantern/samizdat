package samizdat

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"io"
	"net"
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
		PrivateKey:   priv,
		ShortIDs:     [][8]byte{sid},
		CertPEM:      certPEM,
		KeyPEM:       keyPEM,
		LeanH2:       lean,
		ShapeTraffic: serverShapes,
		Handler: func(ctx context.Context, conn net.Conn, dest string) {
			defer conn.Close()
			io.Copy(conn, conn)
		},
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
	client, err := NewClient(ClientConfig{
		ServerAddr:     ln.Addr().String(),
		ServerName:     "test.example.com",
		PublicKey:      pub,
		ShortID:        sid,
		ShapeTraffic:   clientShapes,
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
