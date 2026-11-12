package samizdat

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"net"
	"sync"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestReplayFilterSeen(t *testing.T) {
	f := newReplayFilter(time.Hour, 1000)
	a, b := []byte("session-a"), []byte("session-b")
	if f.seen(a) {
		t.Fatal("first use of a reported as seen")
	}
	if !f.seen(a) {
		t.Fatal("second use of a not reported as seen")
	}
	if f.seen(b) {
		t.Fatal("first use of b reported as seen")
	}
}

func TestReplayFilterWindow(t *testing.T) {
	now := time.Unix(0, 0)
	f := newReplayFilter(time.Hour, 1000)
	f.now = func() time.Time { return now }
	f.rotatedAt = now

	key := []byte("session")
	f.seen(key)

	// Rotated once: still in the previous generation.
	now = now.Add(time.Hour)
	if !f.seen(key) {
		t.Fatal("forgotten after one window, want remembered for at least one")
	}

	// Rotated twice: gone.
	now = now.Add(time.Hour)
	if f.seen(key) {
		t.Fatal("remembered after two windows")
	}
}

func TestReplayFilterForgetsAfterIdle(t *testing.T) {
	now := time.Unix(0, 0)
	f := newReplayFilter(time.Hour, 1000)
	f.now = func() time.Time { return now }
	f.rotatedAt = now

	key := []byte("session")
	f.seen(key)

	// No lookups for three windows: the next one must not find key in a
	// generation that was never rotated out.
	now = now.Add(3 * time.Hour)
	if f.seen(key) {
		t.Fatal("remembered after three idle windows")
	}
}

func TestReplayFilterRetentionStaysOnWindowBoundary(t *testing.T) {
	now := time.Unix(0, 0)
	f := newReplayFilter(time.Hour, 1000)
	f.now = func() time.Time { return now }
	f.rotatedAt = now

	key := []byte("session")
	f.seen(key)

	// A late lookup rotates; the window still began at the hour.
	now = now.Add(90 * time.Minute)
	f.seen([]byte("other"))
	now = now.Add(45 * time.Minute) // 2h15m after key was added
	if f.seen(key) {
		t.Fatal("remembered more than two windows after it was added")
	}
}

func TestReplayFilterSmallCapacity(t *testing.T) {
	f := newReplayFilter(time.Hour, 1)
	if f.cur.m < 1024*28 {
		t.Fatalf("capacity 1 sized to %d bits, want at least the minimum capacity's", f.cur.m)
	}
}

func TestServerReplayConfig(t *testing.T) {
	priv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	base := ServerConfig{
		PrivateKey: priv,
		ShortIDs:   [][8]byte{{1}},
		Handler:    func(ctx context.Context, conn net.Conn, destination string) {},
	}

	c := base
	c.ReplayWindow, c.ReplayCapacity = 2*time.Hour, 500
	s, err := NewServer(c)
	if err != nil {
		t.Fatal(err)
	}
	if s.replay == nil || s.replay.window != 2*time.Hour || s.replay.capacity != 500 {
		t.Fatalf("replay filter = %+v, want window 2h and capacity 500", s.replay)
	}

	c = base
	c.ReplayWindow = -1
	if s, err = NewServer(c); err != nil {
		t.Fatal(err)
	}
	if s.replay != nil {
		t.Fatal("negative ReplayWindow left replay protection on")
	}

	c = base
	c.ReplayCapacity = -1
	if _, err := NewServer(c); err == nil {
		t.Fatal("negative ReplayCapacity accepted")
	}
}

func TestReplayFilterRotatesAtCapacity(t *testing.T) {
	f := newReplayFilter(time.Hour, 100)
	first := []byte("first")
	f.seen(first)
	for i := range 99 {
		f.seen(binary.BigEndian.AppendUint64(nil, uint64(i)))
	}
	// The current generation is full: the next key starts a new one, and
	// first is still remembered in the previous.
	f.seen([]byte("rotate"))
	if f.cur.n != 1 {
		t.Fatalf("current generation holds %d keys, want 1 after rotating", f.cur.n)
	}
	if !f.seen(first) {
		t.Fatal("first forgotten after one rotation")
	}
}

func TestReplayFilterFalsePositives(t *testing.T) {
	const capacity = 100_000
	f := newReplayFilter(time.Hour, capacity)
	key := make([]byte, 16)
	for range capacity - 1 {
		rand.Read(key)
		f.seen(key)
	}
	// At 1e-6 per lookup, 100,000 fresh keys against a full filter give 0.1
	// on average; more than 5 happens by chance about once in 10^9 runs.
	fp := 0
	for range 100_000 {
		rand.Read(key)
		if f.cur.has(f.cur.hash(key)) {
			fp++
		}
	}
	if fp > 5 {
		t.Fatalf("%d false positives in 100,000 lookups", fp)
	}
}

// TestReplayedSessionIDGetsMasquerade copies the SessionID from a real
// client's ClientHello into a new ClientHello with its own key share, as a
// censor that observed the client could. The server must treat it as a probe
// and pass it to the cover site, not complete the handshake with its own
// certificate.
func TestReplayedSessionIDGetsMasquerade(t *testing.T) {
	t.Run("protected", func(t *testing.T) { testReplayedSessionID(t, 0, true) })
	// Without the filter the copy gets the server's own certificate: the
	// attack the filter is there for.
	t.Run("unprotected", func(t *testing.T) { testReplayedSessionID(t, -1, false) })
}

func testReplayedSessionID(t *testing.T, replayWindow time.Duration, wantCover bool) {
	coverCertPEM, coverKeyPEM := generateSelfSignedCert(t)
	coverCert, err := tls.X509KeyPair(coverCertPEM, coverKeyPEM)
	if err != nil {
		t.Fatal(err)
	}
	coverLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{coverCert}})
	if err != nil {
		t.Fatal(err)
	}
	defer coverLn.Close()
	go func() {
		for {
			c, err := coverLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				c.(*tls.Conn).Handshake()
			}()
		}
	}()

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
		ListenAddr:       "127.0.0.1:0",
		PrivateKey:       serverPriv,
		ShortIDs:         [][8]byte{shortID},
		CertPEM:          certPEM,
		KeyPEM:           keyPEM,
		MasqueradeDomain: "cover.example.com",
		MasqueradeAddr:   coverLn.Addr().String(),
		ReplayWindow:     replayWindow,
		Handler:          func(ctx context.Context, conn net.Conn, destination string) { conn.Close() },
	})
	serverAddr := ln.Addr().String()

	// The real client's connection, recording what it sends.
	rec := &recordingDialer{}
	client, err := NewClient(ClientConfig{
		ServerAddr: serverAddr,
		ServerName: "cover.example.com",
		PublicKey:  serverPub,
		ShortID:    shortID,
		Dialer:     rec.dial,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	uc, err := client.dialConn(ctx)
	if err != nil {
		t.Fatalf("real client: %v", err)
	}
	if got := peerCert(t, uc); !got.Equal(leafOf(t, certPEM)) {
		t.Fatal("real client didn't get the server's certificate")
	}
	uc.Close()

	sessionID, err := ExtractSessionID(rec.firstWrite()[5:])
	if err != nil {
		t.Fatal(err)
	}

	// The censor's connection: same SessionID, fresh ClientHello.
	tcp, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	probe := utls.UClient(tcp, &utls.Config{
		ServerName:         "cover.example.com",
		InsecureSkipVerify: true,
		NextProtos:         []string{"h2"},
	}, utls.HelloChrome_Auto)
	defer probe.Close()
	if err := client.applyAuthToClientHello(probe, sessionID); err != nil {
		t.Fatal(err)
	}
	if err := probe.HandshakeContext(ctx); err != nil {
		t.Fatalf("probe handshake: %v", err)
	}
	gotCover := peerCert(t, probe).Equal(leafOf(t, coverCertPEM))
	switch {
	case wantCover && !gotCover:
		t.Fatal("replayed SessionID completed the handshake with the server's own certificate, want the cover site's")
	case !wantCover && gotCover:
		t.Fatal("replayed SessionID reached the cover site with replay protection off; the test no longer exercises the attack")
	}
}

type recordingDialer struct {
	mu     sync.Mutex
	writes [][]byte
}

func (d *recordingDialer) dial(ctx context.Context, network, addr string) (net.Conn, error) {
	c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	return &recordingConn{Conn: c, d: d}, nil
}

func (d *recordingDialer) firstWrite() []byte {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.writes[0]
}

type recordingConn struct {
	net.Conn
	d *recordingDialer
}

func (c *recordingConn) Write(b []byte) (int, error) {
	c.d.mu.Lock()
	c.d.writes = append(c.d.writes, append([]byte(nil), b...))
	c.d.mu.Unlock()
	return c.Conn.Write(b)
}

func peerCert(t *testing.T, c *utls.UConn) *x509.Certificate {
	t.Helper()
	certs := c.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		t.Fatal("no peer certificate")
	}
	return certs[0]
}

func leafOf(t *testing.T, certPEM []byte) *x509.Certificate {
	t.Helper()
	block, _ := pem.Decode(certPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return leaf
}
