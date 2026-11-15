package samizdat

import (
	"net"

	"golang.org/x/sys/unix"
)

// sockQueued returns what c's socket holds unread, or unsent: SIOCINQ and
// SIOCOUTQ.
func sockQueued(c net.Conn, unread bool) int {
	req := uint(unix.SIOCOUTQ)
	if unread {
		req = unix.SIOCINQ
	}
	raw, err := c.(*net.TCPConn).SyscallConn()
	if err != nil {
		return 0
	}
	n := 0
	raw.Control(func(fd uintptr) { n, _ = unix.IoctlGetInt(int(fd), req) })
	return n
}
