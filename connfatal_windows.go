package samizdat

import (
	"syscall"

	"golang.org/x/sys/windows"
)

// fatalErrnos are the socket errors that mean a connection is dead. Winsock
// has its own codes for these, which don't match syscall.ECONNRESET and the
// like, and a read on a reset connection can also fail with
// ERROR_NETNAME_DELETED.
var fatalErrnos = []syscall.Errno{
	windows.WSAECONNABORTED,
	windows.WSAECONNRESET,
	windows.WSAETIMEDOUT,
	windows.ERROR_NETNAME_DELETED,
}
