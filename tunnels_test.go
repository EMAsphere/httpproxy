package httpproxy

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// errRecorder collects the errors reported by the proxy.
type errRecorder struct {
	mu   sync.Mutex
	errs []string
}

func (r *errRecorder) record(ctx *Context, where string, err *Error, opErr error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.errs = append(r.errs, fmt.Sprintf("%s: %v: %v", where, err, opErr))
}

func (r *errRecorder) list() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.errs...)
}

func (r *errRecorder) expectNone(t *testing.T) {
	t.Helper()
	if errs := r.list(); len(errs) > 0 {
		t.Fatalf("unexpected proxy errors: %v", errs)
	}
}

// testCA returns a self-signed ECDSA P-256 CA, like the one cert-manager
// issues for cproxy: SignHosts signs with ECDSAWithSHA256, so MITM does not
// work with the RSA default CA.
func testCA(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "httpproxy test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// startProxy starts a proxy that handles every CONNECT with action.
func startProxy(t *testing.T, action ConnectAction) (*Proxy, string, *errRecorder) {
	t.Helper()
	return startProxyOnConnect(t, func(ctx *Context, host string) (ConnectAction, string) {
		return action, host
	})
}

func startProxyOnConnect(t *testing.T, onConnect func(ctx *Context, host string) (ConnectAction, string)) (*Proxy, string, *errRecorder) {
	t.Helper()
	prx, err := NewProxyCert(testCA(t))
	if err != nil {
		t.Fatal(err)
	}
	prx.OnConnect = onConnect
	// MITM tests talk to httptest TLS servers.
	prx.Rt = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	rec := &errRecorder{}
	prx.OnError = rec.record
	srv := httptest.NewServer(prx)
	t.Cleanup(srv.Close)
	return prx, srv.Listener.Addr().String(), rec
}

// startUpstream starts a TCP server that runs handle on each connection.
func startUpstream(t *testing.T, handle func(net.Conn)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				handle(c)
			}()
		}
	}()
	return ln.Addr().String()
}

// dialTunnel opens a CONNECT tunnel to target through the proxy.
func dialTunnel(t *testing.T, proxyAddr, target string) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	want := "HTTP/1.1 200 OK\r\n\r\n"
	got := make([]byte, len(want))
	if _, err := io.ReadFull(c, got); err != nil || string(got) != want {
		t.Fatalf("CONNECT %s: got %q, %v", target, got, err)
	}
	return c
}

// pingPong answers "pong\n" to each line, after delay.
func pingPong(delay time.Duration) func(net.Conn) {
	return func(c net.Conn) {
		br := bufio.NewReader(c)
		for {
			if _, err := br.ReadString('\n'); err != nil {
				return
			}
			time.Sleep(delay)
			if _, err := io.WriteString(c, "pong\n"); err != nil {
				return
			}
		}
	}
}

func ping(t *testing.T, c net.Conn) {
	t.Helper()
	if _, err := io.WriteString(c, "ping\n"); err != nil {
		t.Fatal(err)
	}
	expectPong(t, c)
}

func expectPong(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.SetReadDeadline(time.Time{})
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "pong\n" {
		t.Fatalf("got %q, %v", buf, err)
	}
}

// expectEOF checks that the tunnel was closed cleanly.
func expectEOF(t *testing.T, c net.Conn) {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := c.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("want EOF, got %d bytes, %v", n, err)
	}
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// mitmSession opens a MITM session through the proxy: one TLS connection,
// so that the tests control exactly which session carries each request (an
// http.Client may open another connection or replay a request on its own).
func mitmSession(t *testing.T, proxyAddr, target string) (*tls.Conn, *bufio.Reader) {
	t.Helper()
	tc := tls.Client(dialTunnel(t, proxyAddr, target), &tls.Config{InsecureSkipVerify: true})
	tc.SetDeadline(time.Now().Add(15 * time.Second))
	if err := tc.Handshake(); err != nil {
		t.Fatal(err)
	}
	return tc, bufio.NewReader(tc)
}

// mitmGet sends a keep-alive GET on the session and returns the response,
// which must be "ok", with its body read.
func mitmGet(t *testing.T, tc *tls.Conn, br *bufio.Reader, target string) *http.Response {
	t.Helper()
	sendMitmGet(t, tc, target)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(body) != "ok" {
		t.Fatalf("got %q, %v", body, err)
	}
	return resp
}

func sendMitmGet(t *testing.T, tc *tls.Conn, target string) {
	t.Helper()
	if _, err := fmt.Fprintf(tc, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: keep-alive\r\n\r\n", target); err != nil {
		t.Fatal(err)
	}
}

// expectSessionEnd checks that the proxy ended the MITM session.
func expectSessionEnd(t *testing.T, br *bufio.Reader) {
	t.Helper()
	if n, err := br.Read(make([]byte, 1)); n != 0 || err != io.EOF {
		t.Fatalf("want the session to end, got %d bytes, %v", n, err)
	}
}

// startOKServer starts a TLS server that answers "ok" after delay.
func startOKServer(t *testing.T, delay time.Duration) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(delay)
		io.WriteString(w, "ok")
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestTunnelForwardsDataAndIsTracked(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectProxy)
	c := dialTunnel(t, addr, startUpstream(t, func(c net.Conn) { io.Copy(c, c) }))
	waitFor(t, "the tunnel to be tracked", func() bool { return prx.ActiveTunnels() == 1 })

	payload := make([]byte, 8<<20)
	rand.Read(payload)
	go c.Write(payload)
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("data corrupted through the tunnel")
	}

	c.Close()
	waitFor(t, "the tunnel to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

func TestTunnelForwardsEndOfStream(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectProxy)
	c := dialTunnel(t, addr, startUpstream(t, func(c net.Conn) { io.WriteString(c, "hello") }))

	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	got, err := io.ReadAll(c)
	if err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}

	c.Close()
	waitFor(t, "the tunnel to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

func TestCloseAllTunnels(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectProxy)
	up := startUpstream(t, func(c net.Conn) { io.Copy(io.Discard, c) })
	var conns []net.Conn
	for i := 0; i < 3; i++ {
		conns = append(conns, dialTunnel(t, addr, up))
	}
	waitFor(t, "3 tracked tunnels", func() bool { return prx.ActiveTunnels() == 3 })

	closed := prx.CloseAllTunnels()
	if len(closed) != 3 {
		t.Fatalf("closed %d tunnels, want 3", len(closed))
	}
	for _, ti := range closed {
		if ti.Host != up || ti.Action != ConnectProxy || ti.Age <= 0 {
			t.Errorf("unexpected tunnel info %+v", ti)
		}
	}
	for _, c := range conns {
		expectEOF(t, c)
	}
	waitFor(t, "the tunnels to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	if again := prx.CloseAllTunnels(); len(again) != 0 {
		t.Fatalf("closed %d tunnels twice", len(again))
	}
	// Tunnels closed on purpose must not be reported as errors.
	rec.expectNone(t)
}

// OnConnect runs once the connection is hijacked, when http.Server no longer
// waits for it. While the callback blocks, on an external service say, the
// proxy must still see the tunnel and be able to close it, and must not dial
// the remote host afterwards.
func TestTunnelTrackedWhileOnConnectBlocks(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	prx, addr, rec := startProxyOnConnect(t, func(ctx *Context, host string) (ConnectAction, string) {
		close(entered)
		<-release
		return ConnectProxy, host
	})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(release) }) })
	var dialed atomic.Int32
	up := startUpstream(t, func(net.Conn) { dialed.Add(1) })

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", up, up)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("OnConnect was not called")
	}

	if n := prx.ActiveTunnels(); n != 1 {
		t.Fatalf("%d tracked tunnels while OnConnect runs, want 1", n)
	}
	closed := prx.CloseAllTunnels()
	if len(closed) != 1 || closed[0].Host != up || closed[0].Action != ConnectNone {
		t.Fatalf("closed %+v, want the tunnel to %s with no action decided yet", closed, up)
	}
	expectEOF(t, c)

	unblock.Do(func() { close(release) })
	waitFor(t, "the tunnel to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	time.Sleep(100 * time.Millisecond) // a dial, if any, reaches the upstream
	if dialed.Load() != 0 {
		t.Fatal("the proxy dialed the remote host of a closed tunnel")
	}
	rec.expectNone(t)
}

// The proxy tracks a CONNECT right before hijacking its connection. A tunnel
// closed in between has no connection to close yet: the hijacked connection
// must then be refused, so that the caller closes it.
func TestTunnelClosedBeforeHijack(t *testing.T) {
	prx := &Proxy{}
	tun := prx.trackTunnel("example.com:443")
	closed := prx.CloseAllTunnels()
	if len(closed) != 1 || closed[0].Host != "example.com:443" || closed[0].Action != ConnectNone {
		t.Fatalf("closed %+v, want the pending tunnel", closed)
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	if tun.setClient(server) {
		t.Fatal("a tunnel closed before the hijack accepted its connection")
	}
	if tun.setTarget("example.com:443", ConnectProxy) {
		t.Fatal("a closed tunnel accepted its target")
	}
	prx.untrackTunnel(tun)
	if n := prx.ActiveTunnels(); n != 0 {
		t.Fatalf("%d tracked tunnels, want 0", n)
	}
}

func TestMitmDrainingEndsSessionAfterResponse(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	target := startOKServer(t, 0).Listener.Addr().String()
	tc, br := mitmSession(t, addr, target)

	if resp := mitmGet(t, tc, br, target); resp.Close {
		t.Fatal("the MITM session should be kept alive before draining")
	}
	prx.SetDraining(true)
	if resp := mitmGet(t, tc, br, target); !resp.Close {
		t.Fatal(`while draining, the response should carry "Connection: close"`)
	}
	expectSessionEnd(t, br)
	waitFor(t, "the MITM session to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

// Draining that starts while the upstream is still working must still end
// the MITM session after that response.
func TestMitmDrainingStartedDuringUpstreamCall(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	target := startOKServer(t, 500*time.Millisecond).Listener.Addr().String()
	tc, br := mitmSession(t, addr, target)
	mitmGet(t, tc, br, target)

	sendMitmGet(t, tc, target)
	time.Sleep(150 * time.Millisecond) // the request now waits for the upstream
	prx.SetDraining(true)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	if !resp.Close {
		t.Fatal(`draining started during the upstream call: the response should carry "Connection: close"`)
	}
	expectSessionEnd(t, br)
	waitFor(t, "the MITM session to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

// A client that got "200" to its CONNECT but has not started the TLS
// handshake yet is connected: the proxy must see it and be able to close it.
func TestMitmHandshakeInProgressIsTracked(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	c := dialTunnel(t, addr, startOKServer(t, 0).Listener.Addr().String())

	waitFor(t, "the pending handshake to be tracked", func() bool { return prx.ActiveTunnels() == 1 })
	if closed := prx.CloseAllTunnels(); len(closed) != 1 {
		t.Fatalf("closed %d tunnels, want 1", len(closed))
	}
	expectEOF(t, c)
	waitFor(t, "the tunnel to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

// Closing a MITM session on purpose while a request is in progress must not
// be reported as an error.
func TestCloseAllTunnelsDuringMitmRequestIsNotAnError(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	target := startOKServer(t, 500*time.Millisecond).Listener.Addr().String()
	tc, br := mitmSession(t, addr, target)

	sendMitmGet(t, tc, target)
	time.Sleep(150 * time.Millisecond) // the request now waits for the upstream
	if closed := prx.CloseAllTunnels(); len(closed) != 1 {
		t.Fatalf("closed %d tunnels, want 1", len(closed))
	}
	if _, err := http.ReadResponse(br, nil); err == nil {
		t.Fatal("got a response from a session closed by the proxy")
	}
	// The proxy untracks the session once it has tried to write the
	// upstream response to the closed connection.
	waitFor(t, "the MITM session to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}
