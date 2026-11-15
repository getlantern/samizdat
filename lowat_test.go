//go:build linux || darwin

package samizdat

import (
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestNotSentLowat: the server's default bound on unsent data is set on a
// connection's socket.
func TestNotSentLowat(t *testing.T) {
	var cfg ServerConfig
	cfg.applyDefaults()
	if cfg.NotSentLowat != 16<<10 {
		t.Fatalf("default NotSentLowat %d, want %d", cfg.NotSentLowat, 16<<10)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			defer c.Close()
			c.Read(make([]byte, 1))
		}
	}()
	conn, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	setNotSentLowat(conn, cfg.NotSentLowat)
	raw, err := conn.(*net.TCPConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var got int
	raw.Control(func(fd uintptr) {
		got, err = unix.GetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT)
	})
	if err != nil || got != cfg.NotSentLowat {
		t.Fatalf("TCP_NOTSENT_LOWAT is %d (%v), want %d", got, err, cfg.NotSentLowat)
	}
}
