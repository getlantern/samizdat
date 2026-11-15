//go:build linux || darwin

package samizdat

import (
	"context"
	"io"
	"net"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

// startSmallBufferH2Pair is startH2Pair on the lean server with small
// socket buffers at both ends, so what the server has queued stays in its
// own write queue, where its scheduling decides the order, rather than in
// the kernel.
func startSmallBufferH2Pair(t *testing.T, handler ConnHandler) (*h2Peer, <-chan net.Conn) {
	t.Helper()
	// Set before the connection exists: TCP sizes its window when it's set
	// up, and doesn't shrink it after.
	small := func(opt int) func(string, string, syscall.RawConn) error {
		return func(_, _ string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, opt, 16<<10)
			})
		}
	}
	ln, err := (&net.ListenConfig{Control: small(syscall.SO_SNDBUF)}).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	s := &Server{config: ServerConfig{MaxConcurrentStreams: 4, Handler: handler}}
	served := make(chan struct{})
	accepted := make(chan net.Conn, 1)
	go func() {
		defer close(served)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		accepted <- conn
		bc := &batchConn{Conn: conn}
		s.serveLeanH2(bc, bc, conn, [8]byte{})
	}()
	conn, err := (&net.Dialer{Control: small(syscall.SO_RCVBUF)}).Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	p := &h2Peer{conn: conn, fr: http2.NewFramer(conn, conn), served: served}
	p.fr.ReadMetaHeaders = hpack.NewDecoder(4096, nil)
	p.enc = hpack.NewEncoder(&p.hbuf)
	conn.SetDeadline(time.Now().Add(20 * time.Second))
	return p, accepted
}

// kernelHeld returns what the kernel holds of the server's data: unsent at
// the server and unread at the client. Some systems keep loopback buffers
// larger than asked.
func kernelHeld(client, server net.Conn) int {
	return sockQueued(client, true) + sockQueued(server, false)
}

// TestLeanNewStreamNotBehindDownload: a stream opened while another has a
// download's worth of data queued gets its response out after at most about
// a chunk of the download, not after everything the download has queued.
func TestLeanNewStreamNotBehindDownload(t *testing.T) {
	p, accepted := startSmallBufferH2Pair(t, func(ctx context.Context, conn net.Conn, dest string) {
		if dest == "small.example:443" {
			conn.Write([]byte("hello"))
			io.Copy(io.Discard, conn)
			return
		}
		buf := make([]byte, 32<<10)
		for {
			if _, err := conn.Write(buf); err != nil {
				return
			}
		}
	})
	p.handshake(t)
	server := <-accepted
	p.request(t, 1, "CONNECT", "bulk.example:443", false)

	// Read until the download is flowing, then stop so the server's queue
	// fills.
	for started := false; !started; {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if d, ok := f.(*http2.DataFrame); ok && d.StreamID == 1 {
			started = true
		}
	}
	time.Sleep(300 * time.Millisecond)

	inKernel := kernelHeld(p.conn, server)
	p.request(t, 3, "CONNECT", "small.example:443", false)
	var bulkBefore int
	for {
		f, err := p.fr.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		d, ok := f.(*http2.DataFrame)
		if !ok {
			continue
		}
		if d.StreamID == 1 {
			bulkBefore += len(d.Data())
			continue
		}
		if d.StreamID == 3 && string(d.Data()) == "hello" {
			break
		}
	}
	// One chunk the writer may be sending and one turn of the download,
	// beyond what the kernel held when the stream opened.
	if limit := 2*leanWriteChunk + 32<<10; bulkBefore-inKernel > limit {
		t.Fatalf("the new stream's response came after %d bytes of the download, %d of them held by the kernel; want at most %d more",
			bulkBefore, inKernel, limit)
	}
}
