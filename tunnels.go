package httpproxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel is a client connection hijacked by the proxy after a CONNECT
// request: a pass-through TCP tunnel (ConnectProxy) or a MITM session
// (ConnectMitm). It is tracked from the moment the connection is hijacked,
// including while the proxy dials the remote host or negotiates TLS, so that
// a draining proxy knows what is still in progress.
//
// The proxy never closes a pass-through tunnel early on its own: the tunnel
// is encrypted end to end, so nothing tells the proxy whether a response is
// complete or the server is pausing in the middle of it. A draining proxy
// waits for the tunnels to end, and cuts the remaining ones with
// CloseAllTunnels at its deadline.
type Tunnel struct {
	// Host is the CONNECT target (host:port).
	Host string
	// Action is how the tunnel is handled.
	Action ConnectAction
	// Start is when the connection was hijacked.
	Start time.Time

	mu     sync.Mutex
	client net.Conn
	remote net.Conn // pass-through tunnels, once dialed
	closed bool

	closedByProxy atomic.Bool
}

// TunnelInfo describes a tunnel closed by the proxy.
type TunnelInfo struct {
	Host   string
	Action ConnectAction
	Age    time.Duration
}

// ClosedByProxy reports whether the proxy closed the tunnel itself, in which
// case the resulting I/O errors are expected and must not be reported.
func (t *Tunnel) ClosedByProxy() bool {
	return t.closedByProxy.Load()
}

// setRemote attaches the remote connection of a pass-through tunnel. It
// returns false when the proxy closed the tunnel meanwhile: the caller then
// still owns remote and must close it.
func (t *Tunnel) setRemote(remote net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.remote = remote
	return true
}

// close closes both connections of the tunnel. It returns false when the
// proxy had already closed it.
func (t *Tunnel) close() bool {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return false
	}
	t.closed = true
	t.closedByProxy.Store(true)
	client, remote := t.client, t.remote
	t.mu.Unlock()
	client.Close()
	if remote != nil {
		remote.Close()
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

func (prx *Proxy) trackTunnel(host string, action ConnectAction, client net.Conn) *Tunnel {
	t := &Tunnel{Host: host, Action: action, Start: time.Now(), client: client}
	prx.tunnels.add(t)
	return t
}

func (prx *Proxy) untrackTunnel(t *Tunnel) {
	prx.tunnels.remove(t)
}

// ActiveTunnels returns the number of open tunnels, including the ones still
// being set up (dial, TLS handshake).
func (prx *Proxy) ActiveTunnels() int {
	return prx.tunnels.count()
}

// SetDraining switches draining mode on or off. While draining, MITM sessions
// answer with "Connection: close" and end after the response, so that
// clients open their next connection elsewhere. This is decided right before
// each response's headers are sent: a response whose headers were already
// sent keeps its session, and the next response closes it. Pass-through
// tunnels are not affected: wait for them with ActiveTunnels and cut the
// remaining ones with CloseAllTunnels.
func (prx *Proxy) SetDraining(draining bool) {
	prx.draining.Store(draining)
}

// Draining reports whether draining mode is on.
func (prx *Proxy) Draining() bool {
	return prx.draining.Load()
}

// CloseAllTunnels closes every open tunnel, whatever it is doing, and returns
// them. Use it at a deadline: it cuts the requests in progress.
func (prx *Proxy) CloseAllTunnels() []TunnelInfo {
	var closed []TunnelInfo
	now := time.Now()
	for _, t := range prx.tunnels.list() {
		if t.close() {
			closed = append(closed, TunnelInfo{Host: t.Host, Action: t.Action, Age: now.Sub(t.Start)})
		}
	}
	return closed
}
