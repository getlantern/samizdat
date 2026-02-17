// Command samizdat-server runs a standalone Samizdat protocol server.
//
// Usage:
//
//	samizdat-server -listen :8443 -domain ok.ru -cert cert.pem -key key.pem -privkey server.key -shortid <hex>
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	samizdat "github.com/getlantern/samizdat"
)

func main() {
	var (
		listenAddr       = flag.String("listen", ":8443", "Listen address")
		masqueradeDomain = flag.String("domain", "", "Masquerade domain (e.g. ok.ru)")
		masqueradeAddr   = flag.String("domain-addr", "", "Masquerade domain IP:port override")
		certFile         = flag.String("cert", "", "TLS certificate PEM file")
		keyFile          = flag.String("key", "", "TLS key PEM file")
		privKeyHex       = flag.String("privkey", "", "Server X25519 private key (hex)")
		shortIDHex       = flag.String("shortid", "", "Allowed short ID (hex, 16 chars)")
		genKeys          = flag.Bool("genkeys", false, "Generate new server keypair and short ID")
	)
	flag.Parse()

	if *genKeys {
		generateKeys()
		return
	}

	if *certFile == "" || *keyFile == "" {
		log.Fatal("--cert and --key are required")
	}
	if *privKeyHex == "" {
		log.Fatal("--privkey is required (use --genkeys to generate)")
	}
	if *shortIDHex == "" {
		log.Fatal("--shortid is required (use --genkeys to generate)")
	}

	certPEM, err := os.ReadFile(*certFile)
	if err != nil {
		log.Fatalf("reading cert: %v", err)
	}
	keyPEM, err := os.ReadFile(*keyFile)
	if err != nil {
		log.Fatalf("reading key: %v", err)
	}

	privKey, err := hex.DecodeString(*privKeyHex)
	if err != nil || len(privKey) != 32 {
		log.Fatal("--privkey must be 64 hex characters (32 bytes)")
	}

	shortIDBytes, err := hex.DecodeString(*shortIDHex)
	if err != nil || len(shortIDBytes) != 8 {
		log.Fatal("--shortid must be 16 hex characters (8 bytes)")
	}
	var shortID [8]byte
	copy(shortID[:], shortIDBytes)

	config := samizdat.ServerConfig{
		ListenAddr:       *listenAddr,
		PrivateKey:       privKey,
		ShortIDs:         [][8]byte{shortID},
		CertPEM:          certPEM,
		KeyPEM:           keyPEM,
		MasqueradeDomain: *masqueradeDomain,
		MasqueradeAddr:   *masqueradeAddr,
		Handler:          proxyHandler,
	}

	server, err := samizdat.NewServer(config)
	if err != nil {
		log.Fatalf("creating server: %v", err)
	}

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("Shutting down...")
		server.Close()
	}()

	log.Printf("Samizdat server listening on %s (masquerade: %s)", *listenAddr, *masqueradeDomain)
	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func generateKeys() {
	privKey, pubKey, err := samizdat.GenerateKeyPair()
	if err != nil {
		log.Fatalf("generating keypair: %v", err)
	}
	shortID, err := samizdat.GenerateShortID()
	if err != nil {
		log.Fatalf("generating short ID: %v", err)
	}

	fmt.Printf("Private key: %s\n", hex.EncodeToString(privKey))
	fmt.Printf("Public key:  %s\n", hex.EncodeToString(pubKey))
	fmt.Printf("Short ID:    %s\n", hex.EncodeToString(shortID[:]))
}

// proxyHandler is the default handler that dials the destination and proxies
// data bidirectionally.
func proxyHandler(ctx context.Context, conn net.Conn, destination string) {
	defer conn.Close()

	host, port, err := net.SplitHostPort(destination)
	if err != nil {
		host = destination
		port = "443"
	}

	targetConn, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 10*time.Second)
	if err != nil {
		log.Printf("Failed to dial %s: %v", destination, err)
		return
	}
	defer targetConn.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		io.Copy(targetConn, conn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		io.Copy(conn, targetConn)
	}()

	wg.Wait()
}
