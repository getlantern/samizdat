//go:build linux || darwin

package samizdat

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

// setNotSentLowat sets TCP_NOTSENT_LOWAT on conn, if it's a TCP connection
// the kernel can be asked about.
func setNotSentLowat(conn net.Conn, n int) {
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return
	}
	raw.Control(func(fd uintptr) {
		unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NOTSENT_LOWAT, n)
	})
}
