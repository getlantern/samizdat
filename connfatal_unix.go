//go:build !windows

package samizdat

import "syscall"

// fatalErrnos are the socket errors that mean a connection is dead.
var fatalErrnos = []syscall.Errno{
	syscall.ECONNRESET,
	syscall.EPIPE,
	syscall.ETIMEDOUT,
}
