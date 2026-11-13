# Samizdat

Samizdat is a censorship-circumvention protocol. It carries proxy traffic over TLS 1.3 connections that, from outside, are a browser talking HTTP/2 to a real website. The server authenticates its own clients inside the TLS handshake; with a cover site configured (`MasqueradeDomain`), it passes every other connection that opens with a TLS handshake record, including active probes, to that real website. By default, the first records of each authenticated connection are shaped to match a model of real TLS traffic.

The name comes from the Russian *самиздат*: banned writing, copied by hand and passed on.

**Website:** [samizdat.lantern.io](https://samizdat.lantern.io), with a sourced comparison to VLESS, XTLS Vision, REALITY, Trojan and NaïveProxy.

## What it's built against

| Technique | Source | Samizdat's answer |
|---|---|---|
| Fingerprinting the start of a connection by packet sizes and directions | CenKL, IEEE S&P 2027 | The first 10 TLS records after the handshake follow sizes and directions drawn from the authors' model of 326.5M real TLS flows; Go's dynamic record sizing is off |
| Active probing, including replaying a captured handshake | Alice et al., IMC 2020; REALITY replay PoC, net4people #576 | Unauthenticated or repeated ClientHellos are forwarded byte for byte to the real cover site; accepted SessionIDs are remembered and refused again. Probes that don't open with a TLS handshake record are closed (see Limits) |
| Copying an authentication tag into another handshake | — | Version 2 tags are bound to the whole ClientHello and the client's key share |
| First-packet entropy and length (Shadowsocks) | Alice et al., IMC 2020 | A standard TLS 1.3 ClientHello from uTLS with Chrome's fingerprint |
| TLS-in-TLS fingerprinting | Xue et al., USENIX Security 2024 | Partial: HTTP/2 multiplexing, which that paper found lowers the attack's TPR by over 70% with two or more concurrent streams (far less with one) |
| SNI extraction from a single packet | Russia's TSPU | Optional, best effort: the ClientHello is written in pieces around the SNI, in the style of Geneva (Bock et al., CCS 2019) |
| Policing the number of TLS connections to an address on port 443 | net4people #546 | Streams share pooled TLS connections, up to 100 each (`MaxStreamsPerConn`) |
| UDP blocking | Russia | TCP only |

Not covered: **timing.** With `Jitter` on, the client delays each tunnel write by 1 to `MaxJitterMs` ms (30 by default), but Xue et al. (NDSS 2025) found that random delays don't defeat cross-layer RTT fingerprinting and can make it easier, and CenKL's timing-aware classifier still reaches about 0.9 recall against shaped traffic. See [Limits](#limits).

## Protocol Design

### One TLS 1.3 connection, HTTP/2 CONNECT inside

```
Client                                       Server
  |  TCP; ClientHello optionally split at SNI  |
  |  TLS 1.3 ClientHello (uTLS, Chrome)  ----> |  SNI = cover site
  |    auth tag in the SessionID               |  verify tag; if it fails or repeats,
  |  <---- ServerHello, server's certificate   |  forward everything to the cover site
  |                                            |
  |  first 10 TLS records: shaped schedule     |  same schedule, from the same TLS secret
  |    (HTTP/2 preface, SETTINGS, CONNECT      |
  |     carried inside, padded to size)        |
  |                                            |
  |  HTTP/2 CONNECT host:port (stream N) ----> |  one tunnel per stream, all on
  |  <---- 200, DATA <----> DATA               |  this one connection
```

### Authentication

The tag goes in the ClientHello's 32-byte SessionID, a field browsers fill with random bytes in every TLS 1.3 ClientHello for middlebox compatibility. Clients send version 2; servers accept version 2 and version 1, for older clients.

- **Pre-shared:** the server's X25519 public key and an 8-byte short ID per client.
- **Version 2** (`authv2.go`): the SessionID is `AES-256-GCM(key, nonce = random[20:32], version(1) || zero(3) || unix time, big-endian(4) || shortID(8))`, with `key = HKDF-SHA256(X25519(client key share, server key), salt = random[:20], "SAMIZDAT-v2")` and the whole ClientHello (SessionID zeroed) as additional data. It is bound to its ClientHello, as in REALITY, and nothing in it repeats between connections. The same ClientHello sent again unchanged still authenticates until its time is more than `MaxClockSkew` (12 hours by default) from the server's, so the server refuses repeats of it too, as for version 1. A client whose clock is further off than that is refused; set `ServerCertSPKISHA256` so it fails instead of completing the cover site's handshake.
- **Version 1** (`auth.go`): `shortID(8) || nonce(8) || HMAC-SHA256(PSK, nonce)[:16]`, with `PSK = HKDF-SHA256(serverPubKey, shortID, "SAMIZDAT")`. It works in any ClientHello, so the server also refuses a SessionID it has already accepted, for 24 to 48 hours by default (`ReplayWindow`; negative turns it off), or less if more than `ReplayCapacity` (1,000,000) SessionIDs authenticate within one window. `RequireAuthV2` makes a server refuse version 1 once its clients have moved. The record is in memory, so a restarted server has forgotten it.
- **If auth fails, or the SessionID repeats:** the server enters masquerade mode (below).

The ClientHello comes from [uTLS](https://github.com/refraction-networking/utls) with Chrome's fingerprint (Firefox and Safari are also available).

### Masquerade (active-probe resistance)

When a connection doesn't authenticate, including an active probe, a server with `MasqueradeDomain` set becomes a **transparent TCP proxy** to the real cover site (without it, the server closes the connection):

```
Active probe                  Samizdat server              Cover site
  |                               |                              |
  |-- ClientHello (no valid tag) ->|                              |
  |                               |-- the same raw ClientHello -->|
  |                               |<-- ServerHello, real cert ----|
  |<-- ServerHello, real cert ----|                              |
  |   (bytes copied both ways until both close, or 10 minutes)   |
```

After reading the ClientHello to check its tag, the server forwards it and everything after without rewriting anything or terminating TLS, so the prober sees the cover site's certificate, TLS stack and HTTP responses. `MasqueradeMaxDuration` (10 minutes by default) bounds the copy. Inspired by [tlsmasq](https://github.com/getlantern/tlsmasq).

### Connection-start shaping

CenKL (Ortwein et al., IEEE S&P 2027) found that every proxy it tested could be told from real TLS within the first few packets after the handshake, and that HTTP/2 tunnels in particular open with a distinctive preface, SETTINGS and CONNECT. Following the authors' ProxyShaper (`shaping.go`, `shapingmodel.go`):

- Both ends export 40 bytes of keying material from the TLS session. 32 bytes seed a ChaCha8 sampler; 8 bytes key an HMAC over the schedule, whose first 8 bytes are the marker.
- The sampler draws 10 records' sizes and directions from the authors' released order-1 Markov model (`shaping_model.bin.gz`), each conditioned on the previous one. Sizes above 1,448 bytes, which a Linux sender with TCP timestamps splits into two packets, are left out.
- During the schedule each side sends exactly its scheduled records: a 2-byte length, queued HTTP/2 bytes, then padding (the client's first record starts with the 8-byte marker). After the 10th record, data passes straight through.
- The server reads the client's first 8 bytes: the marker means a shaping client; an HTTP/2 preface means an older client, served as before. `ClientConfig.DisableShaping` stops a client shaping, which works with any server; `ServerConfig.DisableShaping` stops a server accepting shaping clients, so its clients must disable it too.
- Shaping applies to authenticated HTTP/2 connections; the masquerade path and `SessionHandler` connections aren't shaped.
- Go's dynamic TLS record sizing is off on both ends, and while a server accepts shaping it issues no session tickets: both added tells of their own.

Measured against CenKL's model (first 10 packets, 800 flows, loopback): unshaped samizdat scored 63.0 nats of KL divergence, shaped samizdat 12.4, and real TLS sampled from the model itself 11.3 (the floor for that sample size). See [#29](https://github.com/getlantern/samizdat/pull/29).

### HTTP/2 multiplexing

Every tunnelled connection is an HTTP/2 CONNECT stream on a pooled TLS connection carrying up to `MaxStreamsPerConn` (100) at once. The client reuses pooled connections where it can, so a censor counting TLS connections to the address sees few, though concurrent dials can open more than one. `ServerConfig.LeanH2` serves those streams with samizdat's own HTTP/2 server (`leanh2.go`), which sends the same frames as Go's x/net server but batches them into fewer TLS records and system calls: 66–90% less server CPU per GB downloaded in benchmarks ([#25](https://github.com/getlantern/samizdat/pull/25)).

### Fragmentation and jitter

- **ClientHello fragmentation** (`TCPFragmentation`): the ClientHello is written in pieces split around the SNI field, with a short random delay between them. It's best effort: a split can fall just outside the hostname, and separate writes don't guarantee separate TCP segments.
- **Record fragmentation** (`RecordFragmentation`): not implemented. The option exists in `ClientConfig` but nothing uses it yet.
- **Jitter** (`Jitter`, `MaxJitterMs`, default 30): when on, the client waits 1 to `MaxJitterMs` ms before each tunnel write. As noted above, research suggests this doesn't help against RTT fingerprinting.

## Limits

- **Timing isn't shaped**, beyond the jitter above.
- **Tunnelled TLS is still inside.** Applications using samizdat bring their own TLS. Multiplexing helps most with several concurrent streams.
- **Shaping covers 10 records.** After that, traffic is whatever the tunnelled applications send. The schedule fixes TLS record sizes; TCP can still split or merge them into packets.
- **The model is one network's view:** one regional ISP, late 2025. Its data license is still being settled with the authors.
- **The replay record is in memory and bounded.** A restarted server has forgotten the SessionIDs it accepted, and more than `ReplayCapacity` in one window shortens how long they're remembered.
- **Probes that aren't TLS are closed.** A connection whose first record isn't a TLS handshake record, or is larger than 16 KB, is closed rather than forwarded, so it doesn't see how the cover site would react.
- **Not independently reviewed.** Version 2 auth hasn't had an outside cryptographic review.

## Installation

```bash
go get github.com/getlantern/samizdat
```

## Usage

### Client

```go
import samizdat "github.com/getlantern/samizdat"

client, err := samizdat.NewClient(samizdat.ClientConfig{
    ServerAddr:  "proxy.example.com:443",
    ServerName:  "ok.ru",                    // cover site SNI
    PublicKey:   serverPublicKey,             // 32-byte X25519 public key
    ShortID:     shortID,                    // 8-byte pre-shared identifier
    Fingerprint: "chrome",                   // uTLS fingerprint
    Jitter:      true,                       // timing jitter
    TCPFragmentation: true,                  // Geneva-style fragmentation
})

// Dial through the proxy (multiplexed over pooled TLS+H2 connections)
conn, err := client.DialContext(ctx, "tcp", "example.com:443")
```

### Server

```go
server, err := samizdat.NewServer(samizdat.ServerConfig{
    ListenAddr:       ":443",
    PrivateKey:       serverPrivateKey,       // 32-byte X25519 private key
    ShortIDs:         [][8]byte{shortID},     // allowed client IDs
    CertPEM:          certPEM,                // TLS certificate
    KeyPEM:           keyPEM,
    MasqueradeDomain: "ok.ru",               // real domain for active probes
    Handler: func(ctx context.Context, conn net.Conn, destination string) {
        // Handle proxied connection to destination
    },
})

server.ListenAndServe()
```

### Key Generation

```bash
go run ./cmd/samizdat-server --genkeys
# Output:
# Private key: <hex>
# Public key:  <hex>
# Short ID:    <hex>
```

### Standalone Server

```bash
go run ./cmd/samizdat-server \
    -listen :443 \
    -domain ok.ru \
    -cert cert.pem \
    -key key.pem \
    -privkey <hex private key> \
    -shortid <hex short id>
```

## Architecture

Samizdat is split across two repositories:

### `getlantern/samizdat` (this repo)

The standalone protocol library. Zero sing-box dependencies. Can be integrated into any Go application.

```
samizdat/
├── samizdat.go          # Config types and defaults
├── auth.go              # Version 1 SessionID (HMAC)
├── authv2.go            # Version 2 SessionID (X25519 + AES-GCM, bound to the ClientHello)
├── replay.go            # Refusing SessionIDs already accepted
├── client.go            # Client dialer (uTLS + HTTP/2 CONNECT)
├── server.go            # Server: auth, masquerade, shaping, HTTP/2
├── h2transport.go       # Client HTTP/2 transport
├── leanh2.go            # Lean HTTP/2 server (ServerConfig.LeanH2)
├── streamconn.go        # net.Conn over an HTTP/2 stream
├── connpool.go          # Client connection pool
├── shaping.go           # Connection-start shaping
├── shapingmodel.go      # The shaping model and sampler
├── shaping_model.bin.gz # CenKL's size-and-direction model, pruned
├── fragmenter.go        # ClientHello fragmentation
├── shaper.go            # Jitter (and an unused record fragmenter)
├── masquerade.go        # Transparent proxy to the cover site
├── cmd/samizdat-server/ # Standalone server
└── cmd/shapingmodel/    # Builds shaping_model.bin.gz from CenKL's released model
```

### [`getlantern/lantern-box`](https://github.com/getlantern/lantern-box)

Thin wiring layer that registers samizdat as a sing-box outbound/inbound. Only adapter code — maps sing-box options to samizdat config.

## Dependencies

```
golang.org/x/net/http2                    # HTTP/2 implementation
golang.org/x/crypto/curve25519           # X25519 for key generation
golang.org/x/crypto/hkdf                 # Key derivation
github.com/refraction-networking/utls    # Chrome TLS fingerprint
```

## References

- Aaron Ortwein, Armin Huremagic, Shabbir Hussain, Holly Bergen, Joshua J. Daymude, Diwen Xue, Jedidiah R. Crandall, Roya Ensafi. "[CenKL: Information-Theoretic Visibility into Censorship Circumvention Traffic Patterns](https://aaron-ortwein.github.io/papers/cenkl.pdf)." IEEE S&P 2027. Model: [censoredplanet/obfuscation](https://github.com/censoredplanet/obfuscation).
- Diwen Xue, Michalis Kallitsis, Amir Houmansadr, Roya Ensafi. "[Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting)." USENIX Security 2024.
- Diwen Xue, Robert Stanley, Piyush Kumar, Roya Ensafi. "[The Discriminative Power of Cross-layer RTTs in Fingerprinting Proxy Traffic](https://www.ndss-symposium.org/ndss-paper/the-discriminative-power-of-cross-layer-rtts-in-fingerprinting-proxy-traffic/)." NDSS 2025.
- Alice, Bob, Carol, Jan Beznazwy, Amir Houmansadr. "[How China Detects and Blocks Shadowsocks](https://gfw.report/publications/imc20/en/)." IMC 2020.
- Kevin Bock, George Hughey, Xiao Qiang, Dave Levin. "[Geneva: Evolving Censorship Evasion Strategies](https://geneva.cs.umd.edu/papers/geneva_ccs19.pdf)." ACM CCS 2019.
- XTLS, [REALITY](https://github.com/XTLS/REALITY).
- net4people/bbs [#490](https://github.com/net4people/bbs/issues/490) (Russia freezing TLS connections after about 16 KB), [#546](https://github.com/net4people/bbs/issues/546) (Russia policing TLS connection counts on port 443), [#576](https://github.com/net4people/bbs/issues/576) (REALITY detected by handshake replay).

## Minimal End-to-End Example

The following is a self-contained program that starts a Samizdat server, connects a client through it, and sends data through the tunnel. It generates all credentials and a self-signed certificate on the fly.

```go
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"sync"
	"time"

	samizdat "github.com/getlantern/samizdat"
)

func main() {
	// --- 1. Generate credentials ---

	serverPriv, serverPub, err := samizdat.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	shortID, err := samizdat.GenerateShortID()
	if err != nil {
		log.Fatal(err)
	}
	certPEM, keyPEM := selfSignedCert()

	// --- 2. Start a TCP echo server (the "destination" behind the proxy) ---

	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer echoLn.Close()

	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c) // echo back everything
			}()
		}
	}()

	// --- 3. Start the Samizdat server ---

	server, err := samizdat.NewServer(samizdat.ServerConfig{
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
	if err != nil {
		log.Fatal(err)
	}

	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(100 * time.Millisecond) // wait for listener

	// --- 4. Create a Samizdat client ---

	client, err := samizdat.NewClient(samizdat.ClientConfig{
		ServerAddr:       server.Addr().String(),
		ServerName:       "localhost",
		PublicKey:        serverPub,
		ShortID:          shortID,
		Fingerprint:      "chrome",
		Jitter:           true,
		TCPFragmentation: false, // disabled for localhost test
	})
	if err != nil {
		log.Fatal(err)
	}
	defer client.Close()

	// --- 5. Dial through the tunnel to the echo server ---

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := client.DialContext(ctx, "tcp", echoLn.Addr().String())
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	// --- 6. Send and receive data ---

	msg := []byte("Hello from the other side of the tunnel!")
	if _, err := conn.Write(msg); err != nil {
		log.Fatal(err)
	}

	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Sent:     %s\n", msg)
	fmt.Printf("Received: %s\n", buf[:n])
	// Output:
	// Sent:     Hello from the other side of the tunnel!
	// Received: Hello from the other side of the tunnel!
}

// selfSignedCert generates a self-signed TLS certificate for testing.
func selfSignedCert() (certPEM, keyPEM []byte) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return
}
```

## License

See LICENSE file.
