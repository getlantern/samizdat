package samizdat

import "syscall"

// Winsock reports a dead connection with its own codes, which don't match
// syscall.ECONNRESET and the like.
const (
	wsaeconnaborted syscall.Errno = 10053
	wsaeconnreset   syscall.Errno = 10054
	wsaetimedout    syscall.Errno = 10060
)

// fatalErrnos are the socket errors that mean a connection is dead.
var fatalErrnos = []syscall.Errno{
	wsaeconnaborted,
	wsaeconnreset,
	wsaetimedout,
}
