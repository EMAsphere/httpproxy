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
	"net/url"
	"sync"
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
	prx, err := NewProxyCert(testCA(t))
	if err != nil {
		t.Fatal(err)
	}
	prx.OnConnect = func(ctx *Context, host string) (ConnectAction, string) {
		return action, host
	}
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

// mitmClient returns an HTTP client that goes through the MITM proxy.
func mitmClient(t *testing.T, proxyAddr string) *http.Client {
	t.Helper()
	proxyURL, err := url.Parse("http://" + proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	tr := &http.Transport{
		Proxy:           http.ProxyURL(proxyURL),
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

// keepAliveGet sends a keep-alive GET that must answer "ok", and returns the
// response with its body read.
func keepAliveGet(t *testing.T, client *http.Client, u string) *http.Response {
	t.Helper()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Connection", "keep-alive")
	resp, err := client.Do(req)
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

func TestMitmDrainingEndsSessionAfterResponse(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	upstream := startOKServer(t, 0)
	client := mitmClient(t, addr)

	if resp := keepAliveGet(t, client, upstream.URL); resp.Close {
		t.Fatal("the MITM session should be kept alive before draining")
	}
	waitFor(t, "the MITM session to be tracked", func() bool { return prx.ActiveTunnels() == 1 })

	prx.SetDraining(true)
	if resp := keepAliveGet(t, client, upstream.URL); !resp.Close {
		t.Fatal(`while draining, the response should carry "Connection: close"`)
	}
	waitFor(t, "the MITM session to end", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

// Draining that starts while the upstream is still working must still end
// the MITM session after that response.
func TestMitmDrainingStartedDuringUpstreamCall(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	upstream := startOKServer(t, 500*time.Millisecond)
	client := mitmClient(t, addr)
	keepAliveGet(t, client, upstream.URL)

	go func() {
		time.Sleep(150 * time.Millisecond)
		prx.SetDraining(true)
	}()
	if resp := keepAliveGet(t, client, upstream.URL); !resp.Close {
		t.Fatal(`draining started during the upstream call: the response should carry "Connection: close"`)
	}
	waitFor(t, "the MITM session to end", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

// A client that got "200" to its CONNECT but has not started the TLS
// handshake yet is connected: the proxy must see it and be able to close it.
func TestMitmHandshakeInProgressIsTracked(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	upstream := startOKServer(t, 0)
	c := dialTunnel(t, addr, upstream.Listener.Addr().String())

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
	upstream := startOKServer(t, 500*time.Millisecond)
	client := mitmClient(t, addr)
	keepAliveGet(t, client, upstream.URL)

	done := make(chan struct{})
	go func() {
		defer close(done)
		req, _ := http.NewRequest("GET", upstream.URL, nil)
		req.Header.Set("Connection", "keep-alive")
		if resp, err := client.Do(req); err == nil {
			resp.Body.Close()
		}
	}()
	time.Sleep(150 * time.Millisecond)
	if closed := prx.CloseAllTunnels(); len(closed) != 1 {
		t.Fatalf("closed %d tunnels, want 1", len(closed))
	}
	<-done
	waitFor(t, "the MITM session to end", func() bool { return prx.ActiveTunnels() == 0 })
	time.Sleep(700 * time.Millisecond) // let the upstream answer and the proxy try to write it
	rec.expectNone(t)
}
