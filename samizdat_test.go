package samizdat

import (
	"bytes"
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// --- Auth tests ---

func TestGenerateKeyPair(t *testing.T) {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair failed: %v", err)
	}
	if len(priv) != 32 {
		t.Errorf("private key length = %d, want 32", len(priv))
	}
	if len(pub) != 32 {
		t.Errorf("public key length = %d, want 32", len(pub))
	}
	// Ensure keys are different
	if bytes.Equal(priv, pub) {
		t.Error("private and public keys should be different")
	}
}

func TestGenerateShortID(t *testing.T) {
	id, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID failed: %v", err)
	}
	// Ensure it's not all zeros
	allZero := true
	for _, b := range id {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("short ID should not be all zeros")
	}
}

func TestAuthRoundTrip(t *testing.T) {
	// Generate server keypair
	_, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}

	// Build session ID with auth tag (client uses server's public key)
	sessionID, err := BuildSessionID(serverPub, shortID)
	if err != nil {
		t.Fatalf("BuildSessionID: %v", err)
	}

	// Verify from server side (server also uses its own public key)
	gotShortID, ok, err := VerifySessionID(sessionID[:], serverPub, [][8]byte{shortID})
	if err != nil {
		t.Fatalf("VerifySessionID: %v", err)
	}
	if !ok {
		t.Fatal("VerifySessionID returned false, want true")
	}
	if gotShortID != shortID {
		t.Errorf("short ID mismatch: got %x, want %x", gotShortID, shortID)
	}
}

func TestAuthWrongKey(t *testing.T) {
	_, serverPub, _ := GenerateKeyPair()
	_, wrongPub, _ := GenerateKeyPair() // Different server key
	shortID, _ := GenerateShortID()

	// Build with correct server pub key
	sessionID, err := BuildSessionID(serverPub, shortID)
	if err != nil {
		t.Fatalf("BuildSessionID: %v", err)
	}

	// Try to verify with wrong server pub key
	_, ok, err := VerifySessionID(sessionID[:], wrongPub, [][8]byte{shortID})
	if err != nil {
		t.Fatalf("VerifySessionID: %v", err)
	}
	if ok {
		t.Fatal("VerifySessionID should return false with wrong key")
	}
}

func TestAuthWrongShortID(t *testing.T) {
	_, serverPub, _ := GenerateKeyPair()
	shortID, _ := GenerateShortID()
	wrongShortID, _ := GenerateShortID()

	sessionID, err := BuildSessionID(serverPub, shortID)
	if err != nil {
		t.Fatalf("BuildSessionID: %v", err)
	}

	// Verify with wrong shortID in allowed list
	_, ok, err := VerifySessionID(sessionID[:], serverPub, [][8]byte{wrongShortID})
	if err != nil {
		t.Fatalf("VerifySessionID: %v", err)
	}
	if ok {
		t.Fatal("VerifySessionID should return false with wrong short ID")
	}
}

// --- Fragmenter tests ---

func TestFragmenterPassthrough(t *testing.T) {
	// Without fragmentation, data should pass through unchanged
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	frag := NewFragmenter(client, false)
	data := []byte("hello world this is a test message")

	go func() {
		frag.Write(data)
	}()

	buf := make([]byte, 1024)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Errorf("data mismatch: got %q, want %q", buf[:n], data)
	}
}

func TestFragmenterFragments(t *testing.T) {
	// With fragmentation enabled, the first write should be split
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	frag := NewFragmenter(client, true)

	// Create a fake ClientHello-like data that's large enough to fragment
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}

	go func() {
		frag.Write(data)
	}()

	// Read all fragments
	var received []byte
	buf := make([]byte, 1024)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	for len(received) < len(data) {
		n, err := server.Read(buf)
		if err != nil {
			break
		}
		received = append(received, buf[:n]...)
	}

	if !bytes.Equal(received, data) {
		t.Errorf("reassembled data mismatch: got %d bytes, want %d bytes", len(received), len(data))
	}
}

// --- Shaper tests ---

func TestShaperNoOp(t *testing.T) {
	shaper := NewShaper(false, false, 30, 14000, "chrome")
	var buf bytes.Buffer
	data := []byte("test data")

	n, err := shaper.Write(&buf, data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("wrote %d bytes, want %d", n, len(data))
	}
	if !bytes.Equal(buf.Bytes(), data) {
		t.Error("data should pass through unchanged when shaping is disabled")
	}
}

func TestShaperPadding(t *testing.T) {
	shaper := NewShaper(true, false, 30, 14000, "chrome")
	var buf bytes.Buffer
	data := []byte("short")

	n, err := shaper.Write(&buf, data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Errorf("reported write = %d, want original length %d", n, len(data))
	}
	if buf.Len() < len(data) {
		t.Errorf("padded size %d should be >= original size %d", buf.Len(), len(data))
	}
}

func TestRecordFragmenter(t *testing.T) {
	rf := NewRecordFragmenter(true)

	data := make([]byte, 256)
	for i := range data {
		data[i] = byte(i)
	}

	fragments := rf.Fragment(data)
	if len(fragments) < 2 {
		t.Errorf("expected at least 2 fragments, got %d", len(fragments))
	}

	// Verify all data is preserved
	var reassembled []byte
	for _, f := range fragments {
		reassembled = append(reassembled, f...)
	}
	if !bytes.Equal(reassembled, data) {
		t.Error("reassembled fragments should equal original data")
	}
}

func TestRecordFragmenterSmallData(t *testing.T) {
	rf := NewRecordFragmenter(true)

	// Data smaller than 64 bytes should not be fragmented
	data := []byte("small")
	fragments := rf.Fragment(data)
	if len(fragments) != 1 {
		t.Errorf("expected 1 fragment for small data, got %d", len(fragments))
	}
}

// --- StreamConn tests ---

func TestStreamConn(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	sc := newStreamConn(
		client,
		&streamAddr{"tcp", "127.0.0.1:1234"},
		&streamAddr{"tcp", "example.com:443"},
		"example.com:443",
		nil,
	)
	defer sc.Close()

	// Test write
	go func() {
		sc.Write([]byte("hello"))
	}()

	buf := make([]byte, 10)
	n, err := server.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello" {
		t.Errorf("got %q, want %q", buf[:n], "hello")
	}

	// Test read
	go func() {
		server.Write([]byte("world"))
	}()

	n, err = sc.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "world" {
		t.Errorf("got %q, want %q", buf[:n], "world")
	}

	// Test addresses
	if sc.LocalAddr().String() != "127.0.0.1:1234" {
		t.Errorf("LocalAddr = %s, want 127.0.0.1:1234", sc.LocalAddr())
	}
	if sc.RemoteAddr().String() != "example.com:443" {
		t.Errorf("RemoteAddr = %s, want example.com:443", sc.RemoteAddr())
	}
}

func TestStreamConnDeadline(t *testing.T) {
	_, client := net.Pipe()
	defer client.Close()

	sc := newStreamConn(
		client,
		&streamAddr{"tcp", "local"},
		&streamAddr{"tcp", "remote"},
		"remote",
		nil,
	)
	defer sc.Close()

	// Set a deadline in the past
	sc.SetReadDeadline(time.Now().Add(-1 * time.Second))

	buf := make([]byte, 10)
	_, err := sc.Read(buf)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
		t.Errorf("expected timeout error, got %v", err)
	}
}

// --- ConnPool tests ---

func TestConnPoolBasic(t *testing.T) {
	createCount := 0
	pool := newConnPool(100, 5*time.Minute, func(ctx context.Context) (*h2Transport, error) {
		createCount++
		server, client := net.Pipe()
		_ = server
		return &h2Transport{
			tlsConn:    client,
			serverAddr: "test:443",
			maxStreams:  100,
			localAddr:  &streamAddr{"tcp", "local"},
			remoteAddr: &streamAddr{"tcp", "remote"},
		}, nil
	})
	defer pool.close()

	_, err := pool.getTransport(ctx(t))
	if err != nil {
		t.Fatalf("getTransport: %v", err)
	}
	if createCount != 1 {
		t.Errorf("createCount = %d, want 1", createCount)
	}

	// Second call should reuse the same transport
	_, err = pool.getTransport(ctx(t))
	if err != nil {
		t.Fatalf("getTransport: %v", err)
	}
	if createCount != 1 {
		t.Errorf("createCount = %d, want 1 (should reuse)", createCount)
	}
}

// --- Config tests ---

func TestClientConfigDefaults(t *testing.T) {
	config := ClientConfig{}
	config.applyDefaults()

	if config.Fingerprint != "chrome" {
		t.Errorf("Fingerprint = %s, want chrome", config.Fingerprint)
	}
	if config.MaxJitterMs != 30 {
		t.Errorf("MaxJitterMs = %d, want 30", config.MaxJitterMs)
	}
	if config.MaxStreamsPerConn != 100 {
		t.Errorf("MaxStreamsPerConn = %d, want 100", config.MaxStreamsPerConn)
	}
	if config.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", config.IdleTimeout)
	}
	if config.ConnectTimeout != 15*time.Second {
		t.Errorf("ConnectTimeout = %v, want 15s", config.ConnectTimeout)
	}
	if config.DataThreshold != 14000 {
		t.Errorf("DataThreshold = %d, want 14000", config.DataThreshold)
	}
}

func TestServerConfigDefaults(t *testing.T) {
	config := ServerConfig{}
	config.applyDefaults()

	if config.MasqueradeIdleTimeout != 5*time.Minute {
		t.Errorf("MasqueradeIdleTimeout = %v, want 5m", config.MasqueradeIdleTimeout)
	}
	if config.MasqueradeMaxDuration != 10*time.Minute {
		t.Errorf("MasqueradeMaxDuration = %v, want 10m", config.MasqueradeMaxDuration)
	}
	if config.MaxConcurrentStreams != 250 {
		t.Errorf("MaxConcurrentStreams = %d, want 250", config.MaxConcurrentStreams)
	}
}

// --- Masquerade tests ---

func TestMasqueradeDefaults(t *testing.T) {
	m := NewMasquerade("ok.ru", "", 0, 0)
	if m.IdleTimeout != 5*time.Minute {
		t.Errorf("IdleTimeout = %v, want 5m", m.IdleTimeout)
	}
	if m.MaxDuration != 10*time.Minute {
		t.Errorf("MaxDuration = %v, want 10m", m.MaxDuration)
	}
	if m.DialTimeout != 10*time.Second {
		t.Errorf("DialTimeout = %v, want 10s", m.DialTimeout)
	}
}

// --- Helper ---

func ctx(t *testing.T) context.Context {
	t.Helper()
	return context.Background()
}

// Suppress unused import
var _ = io.Discard
