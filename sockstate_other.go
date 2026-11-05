//go:build !linux

package httpproxy

import "net"

const idleDetection = false

// readSockState is only implemented on Linux.
func readSockState(net.Conn) (sockState, bool) {
	return sockState{}, false
}
