package httpproxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel is a client connection hijacked by the proxy after a CONNECT
// request: a pass-through TCP tunnel (ConnectProxy) or a MITM session
// (ConnectMitm). The proxy tracks tunnels so that, when it drains, it can
// close them at a safe point instead of dropping them when the process exits.
type Tunnel struct {
	// Host is the CONNECT target (host:port).
	Host string
	// Action is how the tunnel is handled.
	Action ConnectAction
	// Start is when the tunnel was established.
	Start time.Time

	client net.Conn
	remote net.Conn // nil for MITM sessions

	closedByProxy atomic.Bool
	closeOnce     sync.Once
}

// TunnelInfo describes a tunnel closed by the proxy.
type TunnelInfo struct {
	Host   string
	Action ConnectAction
	Age    time.Duration
	// Idle is the time since data last went through the tunnel, in either
	// direction. It is only known where the kernel exposes it (Linux).
	Idle      time.Duration
	IdleKnown bool
}

// ClosedByProxy reports whether the proxy closed the tunnel itself, in which
// case the resulting I/O errors are expected and must not be reported.
func (t *Tunnel) ClosedByProxy() bool {
	return t.closedByProxy.Load()
}

func (t *Tunnel) close() {
	t.closeOnce.Do(func() {
		t.closedByProxy.Store(true)
		t.client.Close()
		if t.remote != nil {
			t.remote.Close()
		}
	})
}

func (t *Tunnel) info(now time.Time) TunnelInfo {
	ti := TunnelInfo{Host: t.Host, Action: t.Action, Age: now.Sub(t.Start)}
	if st, ok := readSockState(t.client); ok {
		ti.Idle, ti.IdleKnown = st.idle(), true
	}
	return ti
}

// sockState is what the kernel reports about one TCP socket of a tunnel.
type sockState struct {
	sinceRecv time.Duration // since data was last received on the socket
	sinceSent time.Duration // since data was last sent on the socket
	inFlight  bool          // bytes are still unsent, unacknowledged or unread
}

func (s sockState) idle() time.Duration {
	if s.sinceSent < s.sinceRecv {
		return s.sinceSent
	}
	return s.sinceRecv
}

// idleBetweenRequests reports whether the tunnel looks idle between two
// requests, which is the only point where closing it is clean: the client
// notices the closed connection when it reuses it and opens a new one. The
// proxy cannot see requests inside an encrypted tunnel, so it relies on what
// the kernel reports about the sockets:
//   - nothing went through the tunnel, in either direction, for minIdle;
//   - the last data went to the client, so the last response was delivered.
//     When the last data came from the client, a request is waiting for its
//     response and the tunnel must be left alone. The kernel timestamps have
//     a resolution of a few milliseconds: when both fall in the same tick,
//     the order is unknown and the tunnel is left alone too;
//   - no byte is still queued, unacknowledged or unread on either socket.
func (t *Tunnel) idleBetweenRequests(minIdle time.Duration) bool {
	c, ok := readSockState(t.client)
	if !ok || c.inFlight || c.idle() < minIdle || c.sinceSent >= c.sinceRecv {
		return false
	}
	if t.remote != nil {
		r, ok := readSockState(t.remote)
		if !ok || r.inFlight {
			return false
		}
	}
	return true
}

type tunnelRegistry struct {
	mu      sync.Mutex
	tunnels map[*Tunnel]struct{}
}

func (r *tunnelRegistry) add(t *Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tunnels == nil {
		r.tunnels = make(map[*Tunnel]struct{})
	}
	r.tunnels[t] = struct{}{}
}

func (r *tunnelRegistry) remove(t *Tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tunnels, t)
}

func (r *tunnelRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tunnels)
}

func (r *tunnelRegistry) list() []*Tunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts := make([]*Tunnel, 0, len(r.tunnels))
	for t := range r.tunnels {
		ts = append(ts, t)
	}
	return ts
}

func (prx *Proxy) trackTunnel(host string, action ConnectAction, client, remote net.Conn) *Tunnel {
	t := &Tunnel{Host: host, Action: action, Start: time.Now(), client: client, remote: remote}
	prx.tunnels.add(t)
	return t
}

func (prx *Proxy) untrackTunnel(t *Tunnel) {
	prx.tunnels.remove(t)
}

// ActiveTunnels returns the number of open tunnels.
func (prx *Proxy) ActiveTunnels() int {
	return prx.tunnels.count()
}

// SetDraining switches draining mode on or off. While draining, MITM sessions
// answer with "Connection: close" and end after the current response, so that
// clients open their next connection elsewhere. Pass-through tunnels are not
// affected: close them with CloseIdleTunnels and CloseAllTunnels.
func (prx *Proxy) SetDraining(draining bool) {
	prx.draining.Store(draining)
}

// Draining reports whether draining mode is on.
func (prx *Proxy) Draining() bool {
	return prx.draining.Load()
}

// IdleDetectionSupported reports whether CloseIdleTunnels can find idle
// tunnels on this platform. It needs Linux TCP_INFO: elsewhere no tunnel is
// ever considered idle.
func IdleDetectionSupported() bool {
	return idleDetection
}

// CloseIdleTunnels closes the tunnels that have been idle between two requests
// for at least minIdle, and returns them.
func (prx *Proxy) CloseIdleTunnels(minIdle time.Duration) []TunnelInfo {
	var closed []TunnelInfo
	now := time.Now()
	for _, t := range prx.tunnels.list() {
		if t.ClosedByProxy() || !t.idleBetweenRequests(minIdle) {
			continue
		}
		ti := t.info(now)
		t.close()
		closed = append(closed, ti)
	}
	return closed
}

// CloseAllTunnels closes every open tunnel, whatever it is doing, and returns
// them.
func (prx *Proxy) CloseAllTunnels() []TunnelInfo {
	var closed []TunnelInfo
	now := time.Now()
	for _, t := range prx.tunnels.list() {
		if t.ClosedByProxy() {
			continue
		}
		ti := t.info(now)
		t.close()
		closed = append(closed, ti)
	}
	return closed
}
