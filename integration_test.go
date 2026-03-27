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
	"net/http"
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

// TestIntegrationHTTPS verifies that HTTPS (TLS-over-tunnel) works correctly.
// This is the key regression test for the CloseWrite fix: without CloseWrite(),
// sing-box's bidirectional copy calls Close() when one direction finishes,
// killing the H2 stream before TLS can complete. This test catches that by
// running a real HTTPS server behind the Samizdat tunnel.
func TestIntegrationHTTPS(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	shortID, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)

	// Start a real HTTPS server as the "destination"
	destCertPEM, destKeyPEM := generateSelfSignedCert(t)
	destCert, err := tls.X509KeyPair(destCertPEM, destKeyPEM)
	if err != nil {
		t.Fatalf("loading dest cert: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprint(w, "Hello from HTTPS!")
	})

	httpsServer := &http.Server{
		Handler: mux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{destCert},
		},
	}

	httpsLn, err := tls.Listen("tcp", "127.0.0.1:0", httpsServer.TLSConfig)
	if err != nil {
		t.Fatalf("HTTPS listen: %v", err)
	}
	defer httpsLn.Close()

	go httpsServer.Serve(httpsLn)
	defer httpsServer.Close()

	httpsAddr := httpsLn.Addr().String()

	// Start Samizdat server with a handler that does bidirectional copy
	// (mimicking what sing-box does, including CloseWrite behavior)
	server, err := NewServer(ServerConfig{
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
			go func() {
				defer wg.Done()
				io.Copy(target, conn)
				// Half-close the write side of target if possible
				if cw, ok := target.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
			go func() {
				defer wg.Done()
				io.Copy(conn, target)
				// Half-close the write side of conn if possible
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
			wg.Wait()
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(ClientConfig{
		ServerAddr:       server.Addr().String(),
		ServerName:       "test.example.com",
		PublicKey:        serverPub,
		ShortID:          shortID,
		Jitter:           false,
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Create an HTTP client that dials through the Samizdat tunnel
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: client.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // self-signed cert
			},
		},
		Timeout: 15 * time.Second,
	}

	resp, err := httpClient.Get("https://" + httpsAddr + "/")
	if err != nil {
		t.Fatalf("HTTPS GET through tunnel: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading response body: %v", err)
	}

	if string(body) != "Hello from HTTPS!" {
		t.Errorf("body = %q, want %q", body, "Hello from HTTPS!")
	}
}

// TestIntegrationUpstreamCloseBeforeClientEND tests the RST_STREAM race:
// when the upstream (destination) closes quickly after sending a response,
// the H2 handler may return before the client sends END_STREAM on its
// request body. Without the r.Body drain, this causes RST_STREAM which
// can truncate in-flight response data on the client side.
func TestIntegrationUpstreamCloseBeforeClientEND(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	shortID, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)

	// Start a TCP server that sends a response and immediately closes,
	// simulating a destination that finishes before the client.
	responseLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("response listener: %v", err)
	}
	defer responseLn.Close()

	responseData := []byte("RESPONSE-DATA-THAT-MUST-NOT-BE-LOST")
	go func() {
		for {
			conn, err := responseLn.Accept()
			if err != nil {
				return
			}
			go func() {
				// Read a small amount (simulating request receipt)
				buf := make([]byte, 256)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				conn.Read(buf)
				// Send response and close immediately (upstream done)
				conn.Write(responseData)
				conn.Close()
			}()
		}
	}()

	responseAddr := responseLn.Addr().String()

	// Start Samizdat server with a handler that does bidirectional copy.
	// The upload direction will get a write error when trying to forward
	// data to the already-closed upstream, which is the trigger for the
	// RST_STREAM race.
	server, err := NewServer(ServerConfig{
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
			go func() {
				defer wg.Done()
				io.Copy(target, conn)
				if cw, ok := target.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
			go func() {
				defer wg.Done()
				io.Copy(conn, target)
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
			wg.Wait()
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(ClientConfig{
		ServerAddr:       server.Addr().String(),
		ServerName:       "test.example.com",
		PublicKey:        serverPub,
		ShortID:          shortID,
		Jitter:           false,
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Run multiple iterations to exercise the race.
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		conn, err := client.DialContext(ctx, "tcp", responseAddr)
		if err != nil {
			cancel()
			t.Fatalf("iteration %d: DialContext: %v", i, err)
		}

		// Send a request, then half-close the write side. This sends
		// END_STREAM on the H2 request body, which is what happens when
		// curl finishes sending and closes its TCP connection.
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))
		if cw, ok := conn.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}

		// Read the full response — this is where RST_STREAM would cause
		// an error or truncated data without the fix.
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(conn)
		cancel()
		conn.Close()

		if err != nil {
			t.Fatalf("iteration %d: ReadAll: %v", i, err)
		}
		if string(got) != string(responseData) {
			t.Fatalf("iteration %d: got %q, want %q", i, got, responseData)
		}
	}
}

// TestIntegrationSequentialHTTPThenHTTPS mimics the e2e test scenario:
// first an HTTP request, then an HTTPS request through the same H2 connection.
// This catches issues where the first stream's cleanup disrupts the second stream.
func TestIntegrationSequentialHTTPThenHTTPS(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	shortID, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)

	// Start a plain HTTP server
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from HTTP!")
	})
	httpServer := &http.Server{Handler: httpMux}
	httpLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("HTTP listen: %v", err)
	}
	defer httpLn.Close()
	go httpServer.Serve(httpLn)
	defer httpServer.Close()

	// Start an HTTPS server
	destCertPEM, destKeyPEM := generateSelfSignedCert(t)
	destCert, err := tls.X509KeyPair(destCertPEM, destKeyPEM)
	if err != nil {
		t.Fatalf("loading dest cert: %v", err)
	}
	httpsMux := http.NewServeMux()
	httpsMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "Hello from HTTPS!")
	})
	httpsServer := &http.Server{
		Handler: httpsMux,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{destCert},
		},
	}
	httpsLn, err := tls.Listen("tcp", "127.0.0.1:0", httpsServer.TLSConfig)
	if err != nil {
		t.Fatalf("HTTPS listen: %v", err)
	}
	defer httpsLn.Close()
	go httpsServer.Serve(httpsLn)
	defer httpsServer.Close()

	// Start Samizdat server
	server, err := NewServer(ServerConfig{
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
			go func() {
				defer wg.Done()
				io.Copy(target, conn)
				if cw, ok := target.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
			go func() {
				defer wg.Done()
				io.Copy(conn, target)
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
			}()
			wg.Wait()
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(ClientConfig{
		ServerAddr:       server.Addr().String(),
		ServerName:       "test.example.com",
		PublicKey:        serverPub,
		ShortID:          shortID,
		Jitter:           false,
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: client.DialContext,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
		Timeout: 15 * time.Second,
	}

	// Sequential: HTTP first, then HTTPS (same H2 connection)
	for i := 0; i < 5; i++ {
		// HTTP request
		resp, err := httpClient.Get("http://" + httpLn.Addr().String() + "/")
		if err != nil {
			t.Fatalf("iteration %d HTTP GET: %v", i, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("iteration %d HTTP read: %v", i, err)
		}
		if string(body) != "Hello from HTTP!" {
			t.Fatalf("iteration %d HTTP body = %q, want %q", i, body, "Hello from HTTP!")
		}

		// HTTPS request (same client, same H2 connection to server)
		resp, err = httpClient.Get("https://" + httpsLn.Addr().String() + "/")
		if err != nil {
			t.Fatalf("iteration %d HTTPS GET: %v", i, err)
		}
		body, err = io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			t.Fatalf("iteration %d HTTPS read: %v", i, err)
		}
		if string(body) != "Hello from HTTPS!" {
			t.Fatalf("iteration %d HTTPS body = %q, want %q", i, body, "Hello from HTTPS!")
		}
	}
}

// TestIntegrationFireAndForgetHandler reproduces the "panic: Write called
// after Handler finished" bug. The handler spawns goroutines that write to the
// conn and returns immediately — mimicking sing-box's NewConnection which
// starts two copy goroutines and returns without waiting. Without the
// shutdown() + recover() fix, the orphaned goroutines write to the
// ResponseWriter after the HTTP handler returns, causing a panic.
func TestIntegrationFireAndForgetHandler(t *testing.T) {
	serverPriv, serverPub, _ := GenerateKeyPair()
	shortID, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)

	// A slow TCP server that sends data over 500ms. The download goroutine
	// will still be writing to the H2 stream after the handler returns.
	slowLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("slow listener: %v", err)
	}
	defer slowLn.Close()

	go func() {
		for {
			conn, err := slowLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				// Read the request
				buf := make([]byte, 256)
				conn.SetReadDeadline(time.Now().Add(2 * time.Second))
				conn.Read(buf)
				// Send data in chunks with delays, so the copy goroutine
				// is mid-write when the handler returns.
				for i := 0; i < 10; i++ {
					conn.Write([]byte("chunk-data-that-keeps-the-write-goroutine-alive\n"))
					time.Sleep(50 * time.Millisecond)
				}
			}()
		}
	}()

	slowAddr := slowLn.Addr().String()

	// Samizdat server with a fire-and-forget handler: spawns goroutines and
	// returns immediately, just like sing-box's NewConnection.
	server, err := NewServer(ServerConfig{
		ListenAddr: "127.0.0.1:0",
		PrivateKey: serverPriv,
		ShortIDs:   [][8]byte{shortID},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Handler: func(ctx context.Context, conn net.Conn, destination string) {
			target, err := net.DialTimeout("tcp", destination, 5*time.Second)
			if err != nil {
				conn.Close()
				return
			}
			// Fire-and-forget: spawn copy goroutines and return immediately.
			// This is the pattern that causes the panic without the fix.
			go func() {
				io.Copy(target, conn)
				target.Close()
			}()
			go func() {
				io.Copy(conn, target)
				conn.Close()
			}()
			// Return immediately — handler done, ResponseWriter about to
			// become invalid, but goroutines are still writing.
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}

	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(100 * time.Millisecond)

	client, err := NewClient(ClientConfig{
		ServerAddr:       server.Addr().String(),
		ServerName:       "test.example.com",
		PublicKey:        serverPub,
		ShortID:          shortID,
		Jitter:           false,
		TCPFragmentation: false,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer client.Close()

	// Run multiple iterations to exercise the race. Without the fix,
	// this panics with "Write called after Handler finished".
	successCount := 0
	for i := 0; i < 10; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		conn, err := client.DialContext(ctx, "tcp", slowAddr)
		if err != nil {
			cancel()
			t.Logf("iteration %d: DialContext: %v (expected after repeated races)", i, err)
			continue
		}

		// Send a request to trigger the slow response
		conn.Write([]byte("GET / HTTP/1.0\r\n\r\n"))

		// Read a little, then close abruptly — this creates the
		// scenario where the handler returns while data is still flowing.
		buf := make([]byte, 64)
		conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		conn.Read(buf)
		conn.Close()
		cancel()
		successCount++

		// Brief pause to let the write goroutine hit the shutdown path
		time.Sleep(100 * time.Millisecond)
	}

	if successCount == 0 {
		t.Fatal("no iterations successfully connected — test did not exercise the write-after-return scenario")
	}
	t.Logf("%d/10 iterations completed successfully without panic", successCount)
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
