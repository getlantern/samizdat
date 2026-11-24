//go:build !windows

package samizdat

import "syscall"

// fatalErrnos are the socket errors that mean a connection is dead.
// ECONNABORTED is what a socket gets when the system destroys it, as Android
// does to sockets on a network that has gone away.
var fatalErrnos = []syscall.Errno{
	syscall.ECONNABORTED,
	syscall.ECONNRESET,
	syscall.EPIPE,
	syscall.ETIMEDOUT,
}
