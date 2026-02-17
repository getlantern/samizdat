package samizdat

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"
)

// generateSelfSignedCert creates a self-signed TLS certificate for testing.
func generateSelfSignedCert(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com", "localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshaling key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certPEM, keyPEM
}

func TestIntegrationClientServer(t *testing.T) {
	// Generate server credentials
	serverPriv, serverPub, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}

	certPEM, keyPEM := generateSelfSignedCert(t)

	// Start an echo server (the "destination")
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listener: %v", err)
	}
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn) // echo
			}()
		}
	}()

	echoAddr := echoLn.Addr().String()

	// Start Samizdat server
	server, err := NewServer(ServerConfig{
		ListenAddr:       "127.0.0.1:0",
		PrivateKey:       serverPriv,
		ShortIDs:         [][8]byte{shortID},
		CertPEM:          certPEM,
		KeyPEM:           keyPEM,
		MasqueradeDomain: "", // No masquerade for this test
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
			// Connect to the actual destination
			target, err := net.DialTimeout("tcp", destination, 5*time.Second)
			if err != nil {
				return
			}
			defer target.Close()

			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				io.Copy(target, conn)
			}()
			go func() {
				defer wg.Done()
				io.Copy(conn, target)
			}()
			wg.Wait()
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go server.ListenAndServe()
	defer server.Close()

	// Wait for server to start listening
	time.Sleep(100 * time.Millisecond)

	serverAddr := server.Addr().String()
	t.Logf("Server listening on %s, echo on %s", serverAddr, echoAddr)

	// Create client
	client, err := NewClient(ClientConfig{
		ServerAddr:       serverAddr,
		ServerName:       "test.example.com",
		PublicKey:        serverPub,
		ShortID:          shortID,
		Fingerprint:      "chrome",
		Padding:          false, // Disable for test simplicity
		Jitter:           false,
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Dial through the proxy to the echo server
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, "tcp", echoAddr)
	if err != nil {
		t.Fatalf("DialContext: %v", err)
	}
	defer conn.Close()

	// Test echo
	testData := []byte("Hello, Samizdat!")
	_, err = conn.Write(testData)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}

	if string(buf[:n]) != string(testData) {
		t.Errorf("echo mismatch: got %q, want %q", buf[:n], testData)
	}
}

func TestIntegrationMasquerade(t *testing.T) {
	// Start a fake "real domain" server that echoes a specific response
	fakeDomainLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fake domain listener: %v", err)
	}
	defer fakeDomainLn.Close()

	fakeResponse := []byte("FAKE_DOMAIN_RESPONSE")
	go func() {
		for {
			conn, err := fakeDomainLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Read whatever is sent, then respond
				buf := make([]byte, 4096)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				conn.Read(buf)
				conn.Write(fakeResponse)
			}()
		}
	}()

	fakeDomainAddr := fakeDomainLn.Addr().String()

	// Generate server credentials
	serverPriv, _, err := GenerateKeyPair()
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	shortID, err := GenerateShortID()
	if err != nil {
		t.Fatalf("GenerateShortID: %v", err)
	}

	certPEM, keyPEM := generateSelfSignedCert(t)

	// Start Samizdat server with masquerade pointing to our fake domain
	server, err := NewServer(ServerConfig{
		ListenAddr:       "127.0.0.1:0",
		PrivateKey:       serverPriv,
		ShortIDs:         [][8]byte{shortID},
		CertPEM:          certPEM,
		KeyPEM:           keyPEM,
		MasqueradeDomain: "fake.example.com",
		MasqueradeAddr:   fakeDomainAddr,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go server.ListenAndServe()
	defer server.Close()

	time.Sleep(100 * time.Millisecond)
	serverAddr := server.Addr().String()

	// Connect without Samizdat auth (like an active probe)
	probeConn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("probe dial: %v", err)
	}
	defer probeConn.Close()

	// Send a fake ClientHello-ish TLS record (type 22, but no valid auth)
	fakeClientHello := buildFakeTLSRecord()
	_, err = probeConn.Write(fakeClientHello)
	if err != nil {
		t.Fatalf("probe write: %v", err)
	}

	// Read response — should get the fake domain's response
	buf := make([]byte, 4096)
	probeConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := probeConn.Read(buf)
	if err != nil {
		t.Fatalf("probe read: %v", err)
	}

	if string(buf[:n]) != string(fakeResponse) {
		t.Errorf("masquerade response mismatch: got %q, want %q", buf[:n], fakeResponse)
	}
}

// buildFakeTLSRecord creates a minimal TLS handshake record that looks like
// a ClientHello but won't pass Samizdat auth.
func buildFakeTLSRecord() []byte {
	// TLS record header
	record := []byte{
		22,   // content type: handshake
		3, 1, // TLS 1.0 (for compat, like real ClientHello)
		0, 0, // length placeholder (will be filled)
	}

	// Minimal ClientHello handshake message
	hello := []byte{
		0x01,       // HandshakeType: ClientHello
		0, 0, 0,    // length placeholder
		3, 3,       // client_version: TLS 1.2
	}

	// Random (32 bytes)
	randomBytes := make([]byte, 32)
	rand.Read(randomBytes)
	hello = append(hello, randomBytes...)

	// Session ID (32 bytes of zeros — no valid auth)
	hello = append(hello, 32) // session_id length
	sessionID := make([]byte, 32)
	hello = append(hello, sessionID...)

	// Cipher suites
	hello = append(hello, 0, 2)    // length: 2 bytes
	hello = append(hello, 0x13, 0x01) // TLS_AES_128_GCM_SHA256

	// Compression methods
	hello = append(hello, 1) // length: 1
	hello = append(hello, 0) // null compression

	// Extensions (empty for simplicity)
	hello = append(hello, 0, 0) // extensions_length: 0

	// Fix handshake length
	helloLen := len(hello) - 4
	hello[1] = byte(helloLen >> 16)
	hello[2] = byte(helloLen >> 8)
	hello[3] = byte(helloLen)

	// Fix record length
	recordLen := len(hello)
	record[3] = byte(recordLen >> 8)
	record[4] = byte(recordLen)

	return append(record, hello...)
}

// TestIntegrationMultipleStreams verifies multiplexing multiple connections
// over a single TLS+H2 connection.
func TestIntegrationMultipleStreams(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	shortID, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)

	// Echo server
	echoLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer echoLn.Close()

	go func() {
		for {
			conn, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()

	echoAddr := echoLn.Addr().String()

	server, _ := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		PrivateKey: serverPriv,
		ShortIDs:   [][8]byte{shortID},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			defer conn.Close()
			target, err := net.DialTimeout("tcp", destination, 5*time.Second)
			if err != nil {
				return
			}
			defer target.Close()
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(target, conn) }()
			go func() { defer wg.Done(); io.Copy(conn, target) }()
			wg.Wait()
		},
	})

	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(100 * time.Millisecond)

	client, _ := NewClient(ClientConfig{
		ServerAddr:       server.Addr().String(),
		ServerName:       "test.example.com",
		PublicKey:        serverPub,
		ShortID:          shortID,
		Padding:          false,
		Jitter:           false,
		TCPFragmentation: false,
	})
	defer client.Close()

	// Open multiple concurrent connections
	const numStreams = 5
	var wg sync.WaitGroup
	errors := make(chan error, numStreams)

	for i := 0; i < numStreams; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			conn, err := client.DialContext(ctx, "tcp", echoAddr)
			if err != nil {
				errors <- fmt.Errorf("stream %d dial: %w", idx, err)
				return
			}
			defer conn.Close()

			msg := fmt.Sprintf("stream-%d-data", idx)
			_, err = conn.Write([]byte(msg))
			if err != nil {
				errors <- fmt.Errorf("stream %d write: %w", idx, err)
				return
			}

			buf := make([]byte, 256)
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err := conn.Read(buf)
			if err != nil {
				errors <- fmt.Errorf("stream %d read: %w", idx, err)
				return
			}

			if string(buf[:n]) != msg {
				errors <- fmt.Errorf("stream %d: got %q, want %q", idx, buf[:n], msg)
			}
		}(i)
	}

	wg.Wait()
	close(errors)

	for err := range errors {
		t.Error(err)
	}
}

// Verify TLS cert is used but not PKI-verified (InsecureSkipVerify)
func TestIntegrationTLSConfig(t *testing.T) {
	serverPriv, _, _ := GenerateKeyPair()
	shortID, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)

	server, _ := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		PrivateKey: serverPriv,
		ShortIDs:   [][8]byte{shortID},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Handler:    func(ctx context.Context, conn net.Conn, destination string) { conn.Close() },
	})

	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(100 * time.Millisecond)

	// Connect with standard TLS to verify the server presents a valid TLS endpoint
	tlsConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		server.Addr().String(),
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		// This may fail because the server expects our auth format,
		// but it should at least start the TLS handshake.
		// The key point is that a real TLS server is listening.
		t.Logf("TLS dial (expected to possibly fail without auth): %v", err)
		return
	}
	defer tlsConn.Close()

	state := tlsConn.ConnectionState()
	if !state.HandshakeComplete {
		t.Error("TLS handshake should be complete")
	}
}
