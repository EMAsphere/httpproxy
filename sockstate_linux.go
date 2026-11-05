//go:build linux

package httpproxy

import (
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const idleDetection = true

// readSockState reads TCP_INFO and the receive queue length of a TCP socket.
// ok is false when the connection is not a TCP socket or is already closed.
func readSockState(c net.Conn) (st sockState, ok bool) {
	sc, isSyscallConn := c.(syscall.Conn)
	if !isSyscallConn {
		return st, false
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return st, false
	}
	var info *unix.TCPInfo
	var unread int
	var infoErr, unreadErr error
	err = raw.Control(func(fd uintptr) {
		info, infoErr = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
		unread, unreadErr = unix.IoctlGetInt(int(fd), unix.SIOCINQ)
	})
	if err != nil || infoErr != nil || unreadErr != nil || info == nil {
		return st, false
	}
	st.sinceRecv = time.Duration(info.Last_data_recv) * time.Millisecond
	st.sinceSent = time.Duration(info.Last_data_sent) * time.Millisecond
	st.inFlight = info.Unacked > 0 || info.Notsent_bytes > 0 || unread > 0
	return st, true
}
