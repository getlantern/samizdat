//go:build !linux && !darwin

package samizdat

import "net"

func setNotSentLowat(net.Conn, int) {}
