package samizdat

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"
)

// buildTestHello returns a ClientHello handshake message with a zero
// 32-byte SessionID and one key_share entry per (group, key).
func buildTestHello(t *testing.T, shares map[uint16][]byte) []byte {
	t.Helper()
	var body []byte
	body = append(body, 3, 3) // legacy_version
	random := make([]byte, 32)
	rand.Read(random)
	body = append(body, random...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0, 2, 0x13, 0x01) // cipher suites
	body = append(body, 1, 0)             // compression
	var ks []byte
	for _, g := range []uint16{groupX25519MLKEM768, groupX25519} {
		key, ok := shares[g]
		if !ok {
			continue
		}
		ks = binary.BigEndian.AppendUint16(ks, g)
		ks = binary.BigEndian.AppendUint16(ks, uint16(len(key)))
		ks = append(ks, key...)
	}
	var ext []byte
	ext = binary.BigEndian.AppendUint16(ext, extKeyShare)
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(ks)+2))
	ext = binary.BigEndian.AppendUint16(ext, uint16(len(ks)))
	ext = append(ext, ks...)
	body = binary.BigEndian.AppendUint16(body, uint16(len(ext)))
	body = append(body, ext...)
	msg := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(msg, body...)
}

// sealTestHello seals a version 2 SessionID into hello for the client key
// priv, as the client does.
func sealTestHello(t *testing.T, hello []byte, priv *ecdh.PrivateKey, serverPub []byte, id [8]byte, now time.Time) []byte {
	t.Helper()
	pub, err := ecdh.X25519().NewPublicKey(serverPub)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		t.Fatal(err)
	}
	sid, err := sealSessionIDv2(shared, hello, id, now)
	if err != nil {
		t.Fatal(err)
	}
	out := bytes.Clone(hello)
	copy(out[sessionIDOffset:], sid[:])
	return out
}

func authenticateAt(msg, priv []byte, ids [][8]byte, now time.Time) ([8]byte, bool) {
	old := authNow
	authNow = func() time.Time { return now }
	defer func() { authNow = old }()
	return AuthenticateClientHello(msg, priv, ids, DefaultMaxClockSkew)
}

func TestAuthV2SealAndVerify(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	id, _ := GenerateShortID()
	ids := [][8]byte{id}
	clientKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	hello := buildTestHello(t, map[uint16][]byte{groupX25519: clientKey.PublicKey().Bytes()})
	msg := sealTestHello(t, hello, clientKey, serverPub, id, now)

	if got, ok := authenticateAt(msg, serverPriv, ids, now); !ok || got != id {
		t.Fatalf("authenticate = %x, %v; want %x, true", got, ok, id)
	}
	if bytes.HasPrefix(msg[sessionIDOffset:], id[:]) {
		t.Fatal("version 2 SessionID starts with the shortID in the clear")
	}

	// Within the clock skew either way, and not past it.
	for _, d := range []time.Duration{-11 * time.Hour, 11 * time.Hour} {
		if _, ok := authenticateAt(msg, serverPriv, ids, now.Add(d)); !ok {
			t.Errorf("refused at a skew of %v", d)
		}
	}
	for _, d := range []time.Duration{-13 * time.Hour, 13 * time.Hour} {
		if _, ok := authenticateAt(msg, serverPriv, ids, now.Add(d)); ok {
			t.Errorf("accepted at a skew of %v", d)
		}
	}

	// Every other byte of the ClientHello is bound in, not only the key
	// share: change a cipher suite's and it fails.
	tampered := bytes.Clone(msg)
	tampered[sessionIDOffset+sessionIDLen+3] ^= 1
	if _, ok := authenticateAt(tampered, serverPriv, ids, now); ok {
		t.Fatal("accepted a ClientHello changed after sealing")
	}
	// The wrong server key or shortID fails.
	otherPriv, _, _ := GenerateKeyPair()
	if _, ok := authenticateAt(msg, otherPriv, ids, now); ok {
		t.Fatal("accepted under another server key")
	}
	other, _ := GenerateShortID()
	if _, ok := authenticateAt(msg, serverPriv, [][8]byte{other}, now); ok {
		t.Fatal("accepted a shortID the server doesn't allow")
	}
}

// TestAuthV2HybridOnly: with no X25519 share, the X25519 half of the
// X25519MLKEM768 share carries the auth.
func TestAuthV2HybridOnly(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	id, _ := GenerateShortID()
	clientKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	hybrid := append(make([]byte, 1184), clientKey.PublicKey().Bytes()...)
	hello := buildTestHello(t, map[uint16][]byte{groupX25519MLKEM768: hybrid})
	now := time.Unix(1_800_000_000, 0)
	msg := sealTestHello(t, hello, clientKey, serverPub, id, now)
	if _, ok := authenticateAt(msg, serverPriv, [][8]byte{id}, now); !ok {
		t.Fatal("hybrid-only ClientHello refused")
	}
}

// TestParseClientHelloRejectsTruncation: truncated ClientHellos are refused,
// not read past their end.
func TestParseClientHelloRejectsTruncation(t *testing.T) {
	clientKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	hello := buildTestHello(t, map[uint16][]byte{groupX25519: clientKey.PublicKey().Bytes()})
	for n := range len(hello) {
		if ch, err := parseClientHello(hello[:n]); err == nil && ch.x25519 != nil {
			t.Fatalf("truncated to %d of %d bytes, still found the key share", n, len(hello))
		}
	}
}

// echoPair starts a server and returns a client with cfg's settings over
// it, the server echoing every tunnel.
func echoPair(t *testing.T, cfg ClientConfig) (*Client, *writeRecorder) {
	t.Helper()
	priv, pub, _ := GenerateKeyPair()
	id, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	_, ln := startTestServer(t, ServerConfig{
		ListenAddr: "127.0.0.1:0", PrivateKey: priv, ShortIDs: [][8]byte{id}, CertPEM: certPEM, KeyPEM: keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, dest string) {
			defer conn.Close()
			io.Copy(conn, conn)
		},
	})
	rec := &writeRecorder{}
	cfg.ServerAddr, cfg.ServerName, cfg.PublicKey, cfg.ShortID = ln.Addr().String(), "test.example.com", pub, id
	cfg.Dialer = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return &recordedConn{Conn: c, r: rec}, nil
	}
	// These tests choose the client's auth version;
	// SAMIZDAT_TEST_LEGACY_CLIENTS mustn't override it.
	legacy := testLegacyClients
	testLegacyClients = false
	defer func() { testLegacyClients = legacy }()
	c, err := NewClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c, rec
}

// TestAuthEndToEnd: version 2 works with each fingerprint, whose key shares
// differ, and version 1 clients keep working against the same server.
func TestAuthEndToEnd(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  ClientConfig
	}{
		{"v2 chrome", ClientConfig{Fingerprint: "chrome"}},
		{"v2 firefox", ClientConfig{Fingerprint: "firefox"}},
		{"v2 safari", ClientConfig{Fingerprint: "safari"}},
		{"v1", ClientConfig{LegacyAuth: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, _ := echoPair(t, tc.cfg)
			if err := echoThrough(t, c, 32<<10); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestAuthV2SessionIDsDontRepeat: no part of a version 2 SessionID repeats
// from one connection to the next, where version 1's starts with the
// shortID every time.
func TestAuthV2SessionIDsDontRepeat(t *testing.T) {
	c, rec := echoPair(t, ClientConfig{})
	sids := make([][]byte, 0, 3)
	for range 3 {
		before := len(rec.bytes())
		uc, err := c.dialConn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		uc.Close()
		hello := rec.bytes()[before:]
		sid, err := ExtractSessionID(hello[5:])
		if err != nil {
			t.Fatal(err)
		}
		sids = append(sids, sid)
	}
	for i := range sids {
		if bytes.HasPrefix(sids[i], c.config.ShortID[:]) {
			t.Fatal("version 2 SessionID starts with the shortID")
		}
		for j := range i {
			if bytes.Equal(sids[i][:8], sids[j][:8]) {
				t.Fatalf("SessionIDs %d and %d share their first 8 bytes", i, j)
			}
		}
	}
}

// TestAuthV1SplitClientHello: a version 1 ClientHello split across TLS
// records still authenticates from its first record, which holds the
// SessionID, as it did before version 2.
func TestAuthV1SplitClientHello(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	id, _ := GenerateShortID()
	sid, err := BuildSessionID(serverPub, id)
	if err != nil {
		t.Fatal(err)
	}
	hello := buildTestHello(t, map[uint16][]byte{groupX25519: make([]byte, 32)})
	copy(hello[sessionIDOffset:], sid[:])
	first := hello[:sessionIDOffset+sessionIDLen+4]
	if got, ok := AuthenticateClientHello(first, serverPriv, [][8]byte{id}, DefaultMaxClockSkew); !ok || got != id {
		t.Fatal("version 1 SessionID in a split ClientHello refused")
	}
}

func TestNewServerRejectsNegativeClockSkew(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	_, err := NewServer(ServerConfig{
		PrivateKey:   priv,
		ShortIDs:     [][8]byte{{1}},
		Handler:      func(ctx context.Context, conn net.Conn, dest string) {},
		MaxClockSkew: -time.Second,
	})
	if err == nil {
		t.Fatal("negative MaxClockSkew accepted")
	}
}

// TestAuthenticateClientHelloZeroSkew: a caller that leaves maxSkew zero gets
// the default, as ServerConfig's zero value does, not a tolerance of nothing.
func TestAuthenticateClientHelloZeroSkew(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	id, _ := GenerateShortID()
	clientKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	now := time.Unix(1_800_000_000, 0)
	hello := buildTestHello(t, map[uint16][]byte{groupX25519: clientKey.PublicKey().Bytes()})
	msg := sealTestHello(t, hello, clientKey, serverPub, id, now)

	old := authNow
	defer func() { authNow = old }()
	authNow = func() time.Time { return now.Add(time.Hour) }
	if got, ok := AuthenticateClientHello(msg, serverPriv, [][8]byte{id}, 0); !ok || got != id {
		t.Fatal("zero maxSkew refused a SessionID an hour old")
	}
	authNow = func() time.Time { return now.Add(DefaultMaxClockSkew + time.Hour) }
	if _, ok := AuthenticateClientHello(msg, serverPriv, [][8]byte{id}, 0); ok {
		t.Fatal("zero maxSkew accepted a SessionID past the default skew")
	}
}

// TestRequireAuthV2: with v2Only, a version 1 SessionID is refused and a
// version 2 one still authenticates.
func TestRequireAuthV2(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	id, _ := GenerateShortID()
	ids := [][8]byte{id}
	now := authNow()

	sid, err := BuildSessionID(serverPub, id)
	if err != nil {
		t.Fatal(err)
	}
	v1 := buildTestHello(t, map[uint16][]byte{groupX25519: make([]byte, 32)})
	copy(v1[sessionIDOffset:], sid[:])
	if _, ok := authenticateClientHello(v1, serverPriv, serverPub, ids, DefaultMaxClockSkew, false); !ok {
		t.Fatal("version 1 refused by a server that accepts it")
	}
	if _, ok := authenticateClientHello(v1, serverPriv, serverPub, ids, DefaultMaxClockSkew, true); ok {
		t.Fatal("version 1 accepted with RequireAuthV2")
	}

	clientKey, _ := ecdh.X25519().GenerateKey(rand.Reader)
	hello := buildTestHello(t, map[uint16][]byte{groupX25519: clientKey.PublicKey().Bytes()})
	v2 := sealTestHello(t, hello, clientKey, serverPub, id, now)
	if got, ok := authenticateClientHello(v2, serverPriv, serverPub, ids, DefaultMaxClockSkew, true); !ok || got != id {
		t.Fatal("version 2 refused with RequireAuthV2")
	}
}

// TestRequireAuthV2EndToEnd: a server with RequireAuthV2 serves a version 2
// client and not a version 1 one.
func TestRequireAuthV2EndToEnd(t *testing.T) {
	if testLegacyClients {
		t.Skip("every client sends version 1 in this mode")
	}
	for _, legacy := range []bool{false, true} {
		priv, pub, _ := GenerateKeyPair()
		id, _ := GenerateShortID()
		certPEM, keyPEM := generateSelfSignedCert(t)
		_, ln := startTestServer(t, ServerConfig{
			ListenAddr:    "127.0.0.1:0",
			PrivateKey:    priv,
			ShortIDs:      [][8]byte{id},
			CertPEM:       certPEM,
			KeyPEM:        keyPEM,
			RequireAuthV2: true,
			Handler: func(ctx context.Context, conn net.Conn, dest string) {
				defer conn.Close()
				io.Copy(conn, conn)
			},
		})
		client, err := NewClient(ClientConfig{
			PublicKey:  pub,
			ShortID:    id,
			ServerAddr: ln.Addr().String(),
			ServerName: "example.com",
			LegacyAuth: legacy,
		})
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := client.DialContext(ctx, "tcp", "example.com:443")
		if err == nil {
			conn.Close()
		}
		cancel()
		client.Close()
		if legacy && err == nil {
			t.Error("version 1 client served by a server with RequireAuthV2")
		}
		if !legacy && err != nil {
			t.Errorf("version 2 client refused by a server with RequireAuthV2: %v", err)
		}
	}
}

// TestReplayWindowCoversClockSkew: the replay filter has to remember a
// version 2 ClientHello for as long as it stays valid, so MaxClockSkew
// defaults to no more than half of ReplayWindow and an explicit one past
// that is refused. With the filter off, any skew is allowed.
func TestReplayWindowCoversClockSkew(t *testing.T) {
	priv, _, _ := GenerateKeyPair()
	base := ServerConfig{
		PrivateKey: priv,
		ShortIDs:   [][8]byte{{1}},
		Handler:    func(ctx context.Context, conn net.Conn, dest string) {},
	}
	c := base
	if s, err := NewServer(c); err != nil || s.config.MaxClockSkew != DefaultMaxClockSkew {
		t.Fatalf("defaults: %v", err)
	}
	c = base
	c.ReplayWindow = 2 * time.Hour
	if s, err := NewServer(c); err != nil || s.config.MaxClockSkew != time.Hour {
		t.Fatalf("ReplayWindow of 2h: err %v, want a MaxClockSkew of 1h", err)
	}
	c.MaxClockSkew = 90 * time.Minute
	if _, err := NewServer(c); err == nil {
		t.Fatal("a ReplayWindow shorter than twice MaxClockSkew was accepted")
	}
	c.ReplayWindow = -1
	if _, err := NewServer(c); err != nil {
		t.Fatalf("replay protection off: %v", err)
	}
}
