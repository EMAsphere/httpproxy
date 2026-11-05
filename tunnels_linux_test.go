//go:build linux

package httpproxy

import (
	"bufio"
	"io"
	"net"
	"testing"
	"time"
)

const (
	testIdle = 300 * time.Millisecond
	// Servers take some time to answer. Without it, request and response
	// can fall in the same kernel tick, and their order is then unknown.
	serverTime = 50 * time.Millisecond
)

func TestCloseIdleTunnelsClosesIdleTunnel(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectProxy)
	c := dialTunnel(t, addr, startUpstream(t, pingPong(serverTime)))
	ping(t, c)
	if closed := prx.CloseIdleTunnels(testIdle); len(closed) != 0 {
		t.Fatal("closed a tunnel that was active a moment ago")
	}

	time.Sleep(2 * testIdle)
	closed := prx.CloseIdleTunnels(testIdle)
	if len(closed) != 1 {
		t.Fatalf("closed %d tunnels, want 1", len(closed))
	}
	if !closed[0].IdleKnown || closed[0].Idle < testIdle {
		t.Errorf("unexpected idle time in %+v", closed[0])
	}
	expectEOF(t, c)
	waitFor(t, "the tunnel to be untracked", func() bool { return prx.ActiveTunnels() == 0 })
	rec.expectNone(t)
}

func TestCloseIdleTunnelsKeepsRequestWaitingForResponse(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectProxy)
	c := dialTunnel(t, addr, startUpstream(t, pingPong(4*testIdle)))
	if _, err := io.WriteString(c, "ping\n"); err != nil {
		t.Fatal(err)
	}

	// Nothing moves while the server works, but the last data came from the
	// client: a request is waiting for its response.
	time.Sleep(2 * testIdle)
	if closed := prx.CloseIdleTunnels(testIdle); len(closed) != 0 {
		t.Fatal("closed a tunnel whose request was waiting for its response")
	}
	expectPong(t, c)

	time.Sleep(2 * testIdle)
	if closed := prx.CloseIdleTunnels(testIdle); len(closed) != 1 {
		t.Fatalf("closed %d tunnels once the response was delivered, want 1", len(closed))
	}
	expectEOF(t, c)
	rec.expectNone(t)
}

func TestCloseIdleTunnelsKeepsStreamingTunnel(t *testing.T) {
	prx, addr, _ := startProxy(t, ConnectProxy)
	c := dialTunnel(t, addr, startUpstream(t, func(c net.Conn) {
		chunk := make([]byte, 1024)
		for {
			if _, err := c.Write(chunk); err != nil {
				return
			}
			time.Sleep(testIdle / 10)
		}
	}))
	go io.Copy(io.Discard, c)

	for i := 0; i < 10; i++ {
		time.Sleep(testIdle / 2)
		if closed := prx.CloseIdleTunnels(testIdle); len(closed) != 0 {
			t.Fatal("closed a tunnel that streams data")
		}
	}
}

func TestCloseIdleTunnelsKeepsUndeliveredResponse(t *testing.T) {
	const size = 64 << 20
	prx, addr, rec := startProxy(t, ConnectProxy)
	c := dialTunnel(t, addr, startUpstream(t, func(c net.Conn) {
		br := bufio.NewReader(c)
		if _, err := br.ReadString('\n'); err != nil {
			return
		}
		if _, err := c.Write(make([]byte, size)); err != nil {
			return
		}
		io.Copy(io.Discard, br)
	}))
	if _, err := io.WriteString(c, "get\n"); err != nil {
		t.Fatal(err)
	}

	// The client does not read: the response fills the socket buffers and
	// stops moving. It looks idle, but bytes are still queued.
	time.Sleep(4 * testIdle)
	if closed := prx.CloseIdleTunnels(testIdle); len(closed) != 0 {
		t.Fatal("closed a tunnel whose response was still being delivered")
	}

	c.SetReadDeadline(time.Now().Add(30 * time.Second))
	if n, err := io.CopyN(io.Discard, c, size); err != nil {
		t.Fatalf("read %d bytes of the response: %v", n, err)
	}
	c.SetReadDeadline(time.Time{})

	time.Sleep(2 * testIdle)
	if closed := prx.CloseIdleTunnels(testIdle); len(closed) != 1 {
		t.Fatalf("closed %d tunnels once the response was delivered, want 1", len(closed))
	}
	rec.expectNone(t)
}

func TestCloseIdleTunnelsClosesIdleMitmSession(t *testing.T) {
	prx, addr, rec := startProxy(t, ConnectMitm)
	upstream := startOKServer(t, serverTime)
	client := mitmClient(t, addr)

	keepAliveGet(t, client, upstream.URL)
	waitFor(t, "the MITM session to be tracked", func() bool { return prx.ActiveTunnels() == 1 })

	time.Sleep(2 * testIdle)
	if closed := prx.CloseIdleTunnels(testIdle); len(closed) != 1 {
		t.Fatalf("closed %d MITM sessions, want 1", len(closed))
	}
	waitFor(t, "the MITM session to end", func() bool { return prx.ActiveTunnels() == 0 })

	// The client notices the closed connection and opens a new one.
	keepAliveGet(t, client, upstream.URL)
	rec.expectNone(t)
}
