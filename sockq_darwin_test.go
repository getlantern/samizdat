package samizdat

import (
	"net"
	"syscall"
)

// sockQueued returns what c's socket holds unread, or unsent: SO_NREAD and
// SO_NWRITE.
func sockQueued(c net.Conn, unread bool) int {
	opt := 0x1024
	if unread {
		opt = 0x1020
	}
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		return 0
	}
	n := 0
	raw.Control(func(fd uintptr) { n, _ = syscall.GetsockoptInt(int(fd), syscall.SOL_SOCKET, opt) })
	return n
}
