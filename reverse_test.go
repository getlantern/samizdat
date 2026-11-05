package samizdat

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestReversedHTTP2Roles proves a session can carry HTTP/2 with the roles
// reversed: the TLS client runs an http2.Server and the TLS server runs an
// http2.ClientConn, so CONNECT streams flow from the server to the client.
func TestReversedHTTP2Roles(t *testing.T) {
	priv, pub, _ := GenerateKeyPair()
	sid, _ := GenerateShortID()
	certPEM, keyPEM := generateSelfSignedCert(t)
	echo := startEcho(t)
	ccs := make(chan *http2.ClientConn, 1)
	_, ln := startTestServer(t, ServerConfig{
		PrivateKey: priv, ShortIDs: [][8]byte{sid}, CertPEM: certPEM, KeyPEM: keyPEM,
		SessionHandler: func(ctx context.Context, conn net.Conn, _ [8]byte) {
			cc, err := (&http2.Transport{}).NewClientConn(conn)
			if err != nil {
				t.Error(err)
				close(ccs)
				return
			}
			defer cc.Close()
			ccs <- cc
			<-ctx.Done()
		},
	})
	c, err := NewClient(ClientConfig{ServerAddr: ln.Addr().String(), ServerName: "localhost", PublicKey: pub, ShortID: sid})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	conn, err := c.DialSession(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// conn is the *utls.UConn itself. It does not implement crypto/tls's
	// ConnectionState, so ServeConn treats it as prior-knowledge h2.
	go (&http2.Server{}).ServeConn(conn, &http2.ServeConnOpts{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		up, err := net.Dial("tcp", r.Host)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer up.Close()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		go io.Copy(up, r.Body)
		io.Copy(flushEachWrite{w}, up)
	})})

	cc, ok := <-ccs
	if !ok {
		t.Fatal("server side could not start an HTTP/2 client")
	}
	tctx, cancel := context.WithTimeout(ctx(t), 10*time.Second)
	defer cancel()
	if err := cc.Ping(tctx); err != nil {
		t.Fatalf("ping: %v", err)
	}
	pr, pw := io.Pipe()
	defer pw.Close()
	req, _ := http.NewRequestWithContext(tctx, http.MethodConnect, "https://"+echo, pr)
	req.Host = echo
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("connect status = %d", resp.StatusCode)
	}
	if _, err := pw.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(resp.Body, buf); err != nil || string(buf) != "hello" {
		t.Fatalf("echo = %q, %v", buf, err)
	}
}

// flushEachWrite flushes after every write, so tunneled bytes are not held in
// the response buffer. The package's flushWriter does not.
type flushEachWrite struct{ w http.ResponseWriter }

func (f flushEachWrite) Write(p []byte) (int, error) {
	n, err := f.w.Write(p)
	f.w.(http.Flusher).Flush()
	return n, err
}
