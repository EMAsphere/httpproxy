package httpproxy

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// tunnel is a CONNECT request whose client connection the proxy hijacks: a
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
type tunnel struct {
	start time.Time // when the tunnel was tracked, right before the hijack
	// ctx is cancelled when the tunnel is closed or untracked. The dial of a
	// pass-through tunnel and the upstream calls of a MITM session use it,
	// so that closing the tunnel aborts them.
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex    // guards the fields below, and the setting of closed
	host   string        // CONNECT target (host:port), as rewritten by OnConnect
	action ConnectAction // ConnectNone until OnConnect decides
	client net.Conn      // nil until the connection is hijacked
	remote net.Conn      // pass-through tunnels, once dialed
	// closed reports that the proxy closed the tunnel. It is read without mu
	// to recognize the resulting I/O errors, which must not be reported.
	closed atomic.Bool
}

// TunnelInfo describes a tunnel closed by the proxy.
type TunnelInfo struct {
	Host   string
	Action ConnectAction
	Age    time.Duration
}

// closedByProxy reports whether the proxy closed the tunnel itself, in which
// case the resulting I/O errors are expected and must not be reported.
func (t *tunnel) closedByProxy() bool {
	return t.closed.Load()
}

// setClient attaches the hijacked client connection. It returns false when
// the proxy closed the tunnel before the hijack: the caller then still owns
// client and must close it.
func (t *tunnel) setClient(client net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return false
	}
	t.client = client
	return true
}

// setTarget records the host and action decided by OnConnect. It returns
// false when the proxy closed the tunnel while OnConnect ran.
func (t *tunnel) setTarget(host string, action ConnectAction) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return false
	}
	t.host, t.action = host, action
	return true
}

// setRemote attaches the remote connection of a pass-through tunnel. It
// returns false when the proxy closed the tunnel meanwhile: the caller then
// still owns remote and must close it.
func (t *tunnel) setRemote(remote net.Conn) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed.Load() {
		return false
	}
	t.remote = remote
	return true
}

// close closes both connections of the tunnel and aborts the dial or the
// upstream call in progress. It returns false when the proxy had already
// closed it.
func (t *tunnel) close() bool {
	t.mu.Lock()
	if t.closed.Load() {
		t.mu.Unlock()
		return false
	}
	t.closed.Store(true)
	client, remote := t.client, t.remote
	t.mu.Unlock()
	t.cancel()
	if client != nil {
		client.Close()
	}
	if remote != nil {
		remote.Close()
	}
	return true
}

func (t *tunnel) info(now time.Time) TunnelInfo {
	t.mu.Lock()
	defer t.mu.Unlock()
	return TunnelInfo{Host: t.host, Action: t.action, Age: now.Sub(t.start)}
}

type tunnelRegistry struct {
	mu      sync.Mutex
	tunnels map[*tunnel]struct{}
}

func (r *tunnelRegistry) add(t *tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tunnels == nil {
		r.tunnels = make(map[*tunnel]struct{})
	}
	r.tunnels[t] = struct{}{}
}

func (r *tunnelRegistry) remove(t *tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tunnels, t)
}

func (r *tunnelRegistry) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.tunnels)
}

func (r *tunnelRegistry) list() []*tunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	ts := make([]*tunnel, 0, len(r.tunnels))
	for t := range r.tunnels {
		ts = append(ts, t)
	}
	return ts
}

// trackTunnel tracks a CONNECT request to host before its connection is
// hijacked. Attach the connection with setClient. The tunnel's context
// derives from parent, the context of the CONNECT request.
func (prx *Proxy) trackTunnel(parent context.Context, host string) *tunnel {
	ctx, cancel := context.WithCancel(parent)
	t := &tunnel{start: time.Now(), ctx: ctx, cancel: cancel, host: host}
	prx.tunnels.add(t)
	return t
}

// untrackTunnel forgets a tunnel once its CONNECT request is over.
func (prx *Proxy) untrackTunnel(t *tunnel) {
	prx.tunnels.remove(t)
	t.cancel()
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
// sent keeps its session, and the next response closes it.
//
// Draining closes nothing by itself. A MITM session waiting for its next
// request stays open until that request is answered, its client closes it or
// CloseAllTunnels cuts it: closing it earlier could race with a request the
// client is sending. Pass-through tunnels are not affected either: wait for
// them with ActiveTunnels and cut the remaining ones with CloseAllTunnels.
func (prx *Proxy) SetDraining(draining bool) {
	prx.draining.Store(draining)
}

// Draining reports whether draining mode is on.
func (prx *Proxy) Draining() bool {
	return prx.draining.Load()
}

// CloseAllTunnels closes the tunnels open at the time of the call, whatever
// they are doing, and returns them. It cuts the requests in progress, and
// aborts the dials and the upstream calls of MITM requests. Use it at a
// deadline, once the server no longer accepts connections. Requests still in
// OnAccept or OnAuth are not tunnels yet: http.Server.Close closes their
// connections.
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
