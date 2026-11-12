package samizdat

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// With dynamic record sizing on, crypto/tls (and uTLS) cap the kth
// application-data record of a connection's first 128 KB at k times the
// payload that fits an assumed 1208-byte TCP segment: with TLS 1.3's 22
// bytes of record overhead (header, AEAD tag, content type), a full record
// is goTLSRecordOverhead + k*goTLSRecordUnit bytes on the wire. A bulk
// transfer then shows a run of records growing by exactly goTLSRecordUnit,
// which no browser or mainstream server produces (CenKL, IEEE S&P 2027).
const (
	goTLSRecordOverhead = 22
	goTLSRecordUnit     = 1208 - goTLSRecordOverhead
)

// goCappedRun reports the first pair of consecutive records whose sizes are
// successive steps of Go's dynamic-sizing cap, past the first step.
func goCappedRun(sizes []int) (int, int, bool) {
	step := func(n int) int {
		if n <= goTLSRecordOverhead || (n-goTLSRecordOverhead)%goTLSRecordUnit != 0 {
			return 0
		}
		return (n - goTLSRecordOverhead) / goTLSRecordUnit
	}
	for i := 1; i < len(sizes); i++ {
		if k := step(sizes[i-1]); k >= 2 && step(sizes[i]) == k+1 {
			return sizes[i-1], sizes[i], true
		}
	}
	return 0, 0, false
}

// writeRecorder keeps a copy of everything written to its connections.
type writeRecorder struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *writeRecorder) bytes() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return bytes.Clone(r.buf.Bytes())
}

type recordedConn struct {
	net.Conn
	r *writeRecorder
}

func (c *recordedConn) Write(b []byte) (int, error) {
	c.r.mu.Lock()
	c.r.buf.Write(b)
	c.r.mu.Unlock()
	return c.Conn.Write(b)
}

type recordedListener struct {
	net.Listener
	r *writeRecorder
}

func (l *recordedListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &recordedConn{Conn: c, r: l.r}, nil
}

// appDataRecordSizes returns the size on the wire, header included, of each
// application-data record in a stream of TLS records.
func appDataRecordSizes(t *testing.T, b []byte) []int {
	t.Helper()
	var sizes []int
	for len(b) >= 5 {
		n := 5 + int(binary.BigEndian.Uint16(b[3:5]))
		if n > len(b) {
			break
		}
		if b[0] == 23 { // application_data
			sizes = append(sizes, n)
		}
		b = b[n:]
	}
	return sizes
}

// TestTLSRecordsNotCappedAtGoMSS: a download and an upload early in a
// connection go out in records larger than Go's dynamic-sizing cap, on both
// the server and the client, with either HTTP/2 server.
func TestTLSRecordsNotCappedAtGoMSS(t *testing.T) {
	for _, lean := range []bool{false, true} {
		name := "xnet"
		if lean {
			name = "lean"
		}
		t.Run(name, func(t *testing.T) { testTLSRecordsNotCapped(t, lean) })
	}
}

func testTLSRecordsNotCapped(t *testing.T, lean bool) {
	const size = 64 << 10
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
		PrivateKey: priv,
		ShortIDs:   [][8]byte{sid},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		LeanH2:     lean,
		Handler: func(ctx context.Context, conn net.Conn, dest string) {
			defer conn.Close()
			// Read the upload, then send the download.
			io.CopyN(io.Discard, conn, size)
			conn.Write(make([]byte, size))
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var fromServer, fromClient writeRecorder
	go server.Serve(&recordedListener{Listener: ln, r: &fromServer})
	t.Cleanup(func() { server.Close() })

	client, err := NewClient(ClientConfig{
		ServerAddr: ln.Addr().String(),
		ServerName: "test.example.com",
		PublicKey:  pub,
		ShortID:    sid,
		Dialer: func(ctx context.Context, network, addr string) (net.Conn, error) {
			c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &recordedConn{Conn: c, r: &fromClient}, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.DialContext(ctx, "tcp", "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if n, err := io.CopyN(io.Discard, conn, size); err != nil {
		t.Fatalf("downloaded %d of %d bytes: %v", n, size, err)
	}

	for _, side := range []struct {
		name string
		r    *writeRecorder
	}{{"server", &fromServer}, {"client", &fromClient}} {
		sizes := appDataRecordSizes(t, side.r.bytes())
		if a, b, ok := goCappedRun(sizes); ok {
			t.Errorf("%s: records of %d then %d bytes, successive steps of Go's dynamic record sizing; first records: %v",
				side.name, a, b, sizes[:min(len(sizes), 16)])
		}
	}
}
