package httpproxy

import (
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel is a CONNECT request whose client connection the proxy hijacks: a
// pass-through TCP tunnel (ConnectProxy) or a MITM session (ConnectMitm). It
// is tracked from right before the hijack, so that a draining proxy sees it at
// every step: while OnConnect runs, while the proxy dials the remote host or
// negotiates TLS, and while data flows. Until the hijack, http.Server counts
// the connection as active: there is no moment when neither of them tracks
// it.
//
// The proxy never closes a pass-through tunnel early on its own: the tunnel
// is encrypted end to end, so nothing tells the proxy whether a response is
// complete or the server is pausing in the middle of it. A draining proxy
// waits for the tunnels to end, and cuts the remaining ones with
// CloseAllTunnels at its deadline.
type Tunnel struct {
	start time.Time // when the tunnel was tracked, right before the hijack

	mu     sync.Mutex
	host   string        // CONNECT target (host:port), as rewritten by OnConnect
	action ConnectAction // ConnectNone until OnConnect decides
	client net.Conn      // nil until the connection is hijacked
	remote net.Conn      // pass-through tunnels, once dialed
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

// setClient attaches the hijacked client connection. It returns false when
// the proxy closed the tunnel before the hijack: the caller then still owns
// client and must close it.
func (t *Tunnel) setClient(client net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.client = client
	return true
}

// setTarget records the host and action decided by OnConnect. It returns
// false when the proxy closed the tunnel while OnConnect ran.
func (t *Tunnel) setTarget(host string, action ConnectAction) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	t.host, t.action = host, action
	return true
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
	if client != nil {
		client.Close()
	}
	if remote != nil {
		remote.Close()
	}
	return true
}

func (t *Tunnel) info(now time.Time) TunnelInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TunnelInfo{Host: t.host, Action: t.action, Age: now.Sub(t.start)}
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

// trackTunnel tracks a CONNECT request to host before its connection is
// hijacked. Attach the connection with setClient.
func (prx *Proxy) trackTunnel(host string) *Tunnel {
	t := &Tunnel{start: time.Now(), host: host}
	prx.tunnels.add(t)
	return t
}

func (prx *Proxy) untrackTunnel(t *Tunnel) {
	prx.tunnels.remove(t)
}

// ActiveTunnels returns the number of open tunnels, including the ones still
// being set up (OnConnect, dial, TLS handshake).
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
			closed = append(closed, t.info(now))
		}
	}
	return closed
}
