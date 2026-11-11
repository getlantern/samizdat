//go:build unix

package samizdat

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// The server benchmarks run the server in a child process, so the CPU time
// they report is the server's alone: the client and the load it generates
// run in the benchmark process. The child prints its listen address and
// credentials and serves. A "mark" line on its stdin, sent as the workload
// starts, records its CPU time so far; when stdin closes it prints the
// user+system CPU time used since the mark, leaving out its startup.
//
// A tunnel's destination names the load: "dl:<bytes>:<chunk>" makes the
// handler write <bytes> to the stream in Write calls of <chunk> bytes, as a
// proxy copying from an upstream connection would; "ul" makes it read the
// stream until EOF.

const benchServerEnv = "SAMIZDAT_BENCH_SERVER"

func TestMain(m *testing.M) {
	if os.Getenv(benchServerEnv) != "" {
		runBenchServer()
		return
	}
	os.Exit(m.Run())
}

func runBenchServer() {
	priv, pub, err := GenerateKeyPair()
	if err != nil {
		fatalf("GenerateKeyPair: %v", err)
	}
	shortID, err := GenerateShortID()
	if err != nil {
		fatalf("GenerateShortID: %v", err)
	}
	certPEM, keyPEM := benchCert()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fatalf("listen: %v", err)
	}
	srv, err := NewServer(ServerConfig{
		PrivateKey: priv,
		ShortIDs:   [][8]byte{shortID},
		CertPEM:    certPEM,
		KeyPEM:     keyPEM,
		Handler:    benchHandler,
		LeanH2:     os.Getenv("SAMIZDAT_BENCH_LEAN") != "",
	})
	if err != nil {
		fatalf("NewServer: %v", err)
	}
	go srv.Serve(ln)
	fmt.Printf("addr=%s pub=%s sid=%s\n", ln.Addr(), hex.EncodeToString(pub), hex.EncodeToString(shortID[:]))
	var mark time.Duration
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		if in.Text() == "mark" {
			mark = cpuTime()
		}
	}
	fmt.Printf("cpu_ns=%d\n", (cpuTime() - mark).Nanoseconds())
	os.Exit(0)
}

// cpuTime is the user+system CPU time this process has used.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &ru)
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}

func benchHandler(ctx context.Context, conn net.Conn, destination string) {
	defer conn.Close()
	parts := strings.Split(destination, ":")
	switch parts[0] {
	case "dl":
		total, _ := strconv.Atoi(parts[1])
		chunk, _ := strconv.Atoi(parts[2])
		buf := make([]byte, chunk)
		for sent := 0; sent < total; sent += chunk {
			if _, err := conn.Write(buf[:min(chunk, total-sent)]); err != nil {
				return
			}
		}
	case "ul":
		io.Copy(io.Discard, conn)
	}
}

func benchCert() (certPEM, keyPEM []byte) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test.example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		fatalf("cert: %v", err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// benchServerProc is a running child server.
type benchServerProc struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	out    *bufio.Scanner
	client *Client
}

func startBenchServer(b *testing.B, env ...string) *benchServerProc {
	b.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), benchServerEnv+"=1")
	cmd.Env = append(cmd.Env, env...)
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		b.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		b.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		b.Fatal(err)
	}
	p := &benchServerProc{cmd: cmd, stdin: stdin, out: bufio.NewScanner(stdout)}
	if !p.out.Scan() {
		b.Fatalf("bench server printed nothing")
	}
	var addr, pubHex, sidHex string
	for _, f := range strings.Fields(p.out.Text()) {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "addr":
			addr = v
		case "pub":
			pubHex = v
		case "sid":
			sidHex = v
		}
	}
	pub, _ := hex.DecodeString(pubHex)
	sidBytes, _ := hex.DecodeString(sidHex)
	var sid [8]byte
	copy(sid[:], sidBytes)
	client, err := NewClient(ClientConfig{
		ServerAddr:          addr,
		ServerName:          "test.example.com",
		PublicKey:           pub,
		ShortID:             sid,
		Jitter:              false,
		TCPFragmentation:    false,
		RecordFragmentation: false,
		MaxStreamsPerConn:   1000,
	})
	if err != nil {
		b.Fatal(err)
	}
	p.client = client
	// If the benchmark fails before stop, the child must still go.
	b.Cleanup(p.kill)
	return p
}

// mark tells the child the workload starts now.
func (p *benchServerProc) mark(b *testing.B) {
	if _, err := io.WriteString(p.stdin, "mark\n"); err != nil {
		b.Fatal(err)
	}
}

// kill ends the child if stop didn't. It is safe to call after stop.
func (p *benchServerProc) kill() {
	p.client.Close()
	p.stdin.Close()
	if p.cmd.ProcessState == nil {
		p.cmd.Process.Kill()
		p.cmd.Wait()
	}
}

// stop ends the child and returns the CPU time it used.
func (p *benchServerProc) stop(b *testing.B) time.Duration {
	b.Helper()
	p.client.Close()
	p.stdin.Close()
	var cpu time.Duration
	for p.out.Scan() {
		if v, ok := strings.CutPrefix(p.out.Text(), "cpu_ns="); ok {
			n, _ := strconv.ParseInt(v, 10, 64)
			cpu = time.Duration(n)
		}
	}
	p.cmd.Wait()
	return cpu
}

// benchDownload pulls b.N rounds of perStream bytes over streams concurrent
// tunnels and reports the server's CPU per GB moved.
func benchDownload(b *testing.B, streams, perStream, chunk int, env ...string) {
	p := startBenchServer(b, env...)
	dest := fmt.Sprintf("dl:%d:%d", perStream, chunk)
	ctx := context.Background()
	b.SetBytes(int64(streams * perStream))
	p.mark(b)
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		errs := make(chan error, streams)
		for s := 0; s < streams; s++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := p.client.DialContext(ctx, "tcp", dest)
				if err != nil {
					errs <- err
					return
				}
				defer conn.Close()
				// End the upload side so the server's handler sees END_STREAM
				// and doesn't wait out its drain timeout.
				if cw, ok := conn.(interface{ CloseWrite() error }); ok {
					cw.CloseWrite()
				}
				n, err := io.Copy(io.Discard, conn)
				if err == nil && n != int64(perStream) {
					err = fmt.Errorf("got %d of %d bytes", n, perStream)
				}
				if err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			b.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	b.StopTimer()
	cpu := p.stop(b)
	gb := float64(b.N) * float64(streams*perStream) / 1e9
	b.ReportMetric(cpu.Seconds()/gb, "server-cpu-s/GB")
	b.ReportMetric(cpu.Seconds()/elapsed.Seconds(), "server-cores")
}

// benchUpload pushes b.N rounds of perStream bytes, in client writes of
// chunk bytes, over streams concurrent tunnels into a handler that discards
// them, and reports the server's CPU per GB moved.
func benchUpload(b *testing.B, streams, perStream, chunk int, env ...string) {
	p := startBenchServer(b, env...)
	ctx := context.Background()
	b.SetBytes(int64(streams * perStream))
	p.mark(b)
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		errs := make(chan error, streams)
		for s := 0; s < streams; s++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				conn, err := p.client.DialContext(ctx, "tcp", "ul")
				if err != nil {
					errs <- err
					return
				}
				defer conn.Close()
				buf := make([]byte, chunk)
				for sent := 0; sent < perStream; sent += chunk {
					if _, err := conn.Write(buf[:min(chunk, perStream-sent)]); err != nil {
						errs <- err
						return
					}
				}
				if err := conn.(interface{ CloseWrite() error }).CloseWrite(); err != nil {
					errs <- err
					return
				}
				if _, err := io.Copy(io.Discard, conn); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			b.Fatal(err)
		}
	}
	elapsed := time.Since(start)
	b.StopTimer()
	cpu := p.stop(b)
	gb := float64(b.N) * float64(streams*perStream) / 1e9
	b.ReportMetric(cpu.Seconds()/gb, "server-cpu-s/GB")
	b.ReportMetric(cpu.Seconds()/elapsed.Seconds(), "server-cores")
}

func BenchmarkServerUpload(b *testing.B) {
	for _, impl := range benchImpls {
		for _, c := range []struct{ streams, chunk int }{{16, 16384}, {16, 1400}} {
			b.Run(fmt.Sprintf("%s/streams=%d/chunk=%d", impl.name, c.streams, c.chunk), func(b *testing.B) {
				benchUpload(b, c.streams, 4<<20, c.chunk, impl.env...)
			})
		}
	}
}

func BenchmarkServerDownload(b *testing.B) {
	for _, impl := range benchImpls {
		for _, c := range []struct{ streams, chunk int }{{1, 16384}, {16, 16384}, {16, 1400}, {64, 4096}} {
			b.Run(fmt.Sprintf("%s/streams=%d/chunk=%d", impl.name, c.streams, c.chunk), func(b *testing.B) {
				benchDownload(b, c.streams, 8<<20, c.chunk, impl.env...)
			})
		}
	}
}

// benchImpls are the server implementations the benchmarks compare, selected
// in the child by its environment.
var benchImpls = []struct {
	name string
	env  []string
}{
	{"xnet", nil},
	{"lean", []string{"SAMIZDAT_BENCH_LEAN=1"}},
}
