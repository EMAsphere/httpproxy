package httpproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Context keeps context of each proxy request.
type Context struct {
	// Pointer of Proxy struct handled this context.
	// It's using internally. Don't change in Context struct!
	Prx *Proxy

	// Session number of this context obtained from Proxy struct.
	SessionNo int64

	// Sub session number of processing remote connection.
	SubSessionNo int64

	// Original Proxy request.
	// It's using internally. Don't change in Context struct!
	Req *http.Request

	// Original Proxy request, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectReq *http.Request

	// Action of after the CONNECT, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectAction ConnectAction

	// Remote host, if proxy request method is CONNECT.
	// It's using internally. Don't change in Context struct!
	ConnectHost string

	ConnectDialDuration time.Duration
	ConnectDialError    string
	ConnectDialAddr     string

	// User data to use free.
	UserData interface{}

	hijTLSConn   *tls.Conn
	hijTLSReader *bufio.Reader

	// CONNECT tunnel, tracked from the hijack until ServeHTTP returns.
	tunnel *Tunnel
	// The current MITM response ends the session ("Connection: close").
	closeAfterResponse bool
}

// closedByProxy reports whether the proxy closed the CONNECT tunnel itself:
// the resulting I/O errors are expected and must not be reported.
func (ctx *Context) closedByProxy() bool {
	return ctx.tunnel != nil && ctx.tunnel.ClosedByProxy()
}

// mitmResponseCloses reports whether the MITM response about to be sent must
// end the session. It is called right before the response headers go out, so
// that draining that started during the upstream call is taken into account.
func (ctx *Context) mitmResponseCloses() bool {
	return ctx.ConnectAction == ConnectMitm && ctx.Prx.Draining()
}

func (ctx *Context) onAccept(w http.ResponseWriter, r *http.Request) bool {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Accept", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAccept(ctx, w, r)
}

func (ctx *Context) onAuth(authType string, user string, pass string) bool {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Auth", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnAuth(ctx, authType, user, pass)
}

func (ctx *Context) onConnect(host string) (ConnectAction ConnectAction,
	newHost string) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Connect", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnConnect(ctx, host)
}

func (ctx *Context) onRequest(req *http.Request) (resp *http.Response) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Request", ErrPanic, err)
		}
	}()
	return ctx.Prx.OnRequest(ctx, req)
}

func (ctx *Context) onResponse(req *http.Request, resp *http.Response) {
	defer func() {
		if err, ok := recover().(error); ok {
			ctx.doError("Response", ErrPanic, err)
		}
	}()
	ctx.Prx.OnResponse(ctx, req, resp)
}

func (ctx *Context) doError(where string, err *Error, opErr error) {
	if ctx.Prx.OnError == nil {
		return
	}
	ctx.Prx.OnError(ctx, where, err, opErr)
}

func (ctx *Context) doAccept(w http.ResponseWriter, r *http.Request) bool {
	ctx.Req = r
	if !r.ProtoAtLeast(1, 0) || r.ProtoAtLeast(2, 0) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Accept", ErrNotSupportHTTPVer, nil)
		return true
	}
	if ctx.Prx.OnAccept != nil && ctx.onAccept(w, r) {
		if r.Body != nil {
			defer r.Body.Close()
		}
		return true
	}
	return false
}

func (ctx *Context) doAuth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "CONNECT" && !r.URL.IsAbs() {
		return false
	}
	if ctx.Prx.OnAuth == nil {
		return false
	}
	prxAuthType := ctx.Prx.AuthType
	if prxAuthType == "" {
		prxAuthType = "Basic"
	}
	unauthorized := false
	authParts := strings.SplitN(r.Header.Get("Proxy-Authorization"), " ", 2)
	if len(authParts) >= 2 {
		authType := authParts[0]
		authData := authParts[1]
		if prxAuthType == authType {
			unauthorized = true
			switch authType {
			case "Basic":
				userpassraw, err := base64.StdEncoding.DecodeString(authData)
				if err == nil {
					userpass := strings.SplitN(string(userpassraw), ":", 2)
					if len(userpass) >= 2 && ctx.onAuth(authType, userpass[0], userpass[1]) {
						return false
					}
				}
			default:
				unauthorized = false
			}
		}
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	respCode := 407
	respBody := "Proxy Authentication Required"
	if unauthorized {
		respBody += " [Unauthorized]"
	}
	err := ServeInMemory(w, respCode, map[string][]string{"Proxy-Authenticate": {prxAuthType}},
		[]byte(respBody))
	if err != nil && !isConnectionClosed(err) {
		ctx.doError("Auth", ErrResponseWrite, err)
	}
	return true
}

func (ctx *Context) doConnect(w http.ResponseWriter, r *http.Request) (b bool) {
	b = true
	if r.Method != "CONNECT" {
		b = false
		return
	}
	hij, ok := w.(http.Hijacker)
	if !ok {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, nil)
		return
	}
	conn, _, err := hij.Hijack()
	if err != nil {
		if r.Body != nil {
			defer r.Body.Close()
		}
		ctx.doError("Connect", ErrNotSupportHijacking, err)
		return
	}
	hijConn := conn
	ctx.ConnectReq = r
	ctx.ConnectAction = ConnectProxy
	host := r.URL.Host
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	if ctx.Prx.OnConnect != nil {
		var newHost string
		ctx.ConnectAction, newHost = ctx.onConnect(host)
		if newHost != "" {
			host = newHost
		}
	}
	if !hasPort.MatchString(host) {
		host += ":80"
	}
	ctx.ConnectHost = host
	// Track the connection before any blocking operation (dial, TLS
	// handshake), so that a draining proxy sees it. ServeHTTP untracks it.
	ctx.tunnel = ctx.Prx.trackTunnel(host, ctx.ConnectAction, hijConn)
	switch ctx.ConnectAction {
	case ConnectProxy:
		dialer := net.Dialer{Timeout: ctx.Prx.dialTimeout()}
		start := time.Now()
		conn, err := dialer.DialContext(r.Context(), "tcp", host)
		ctx.ConnectDialDuration = time.Since(start)
		if err != nil {
			ctx.ConnectDialError = ClassifyDialError(err)
			ctx.ConnectDialAddr = ExtractDialAddr(err)
			hijConn.Write([]byte("HTTP/1.1 503 Service Unavailable\r\n\r\n"))
			hijConn.Close()
			ctx.doError("Connect", ErrRemoteConnect, err)
			return
		}
		remoteConn := conn.(*net.TCPConn)
		if !ctx.tunnel.setRemote(remoteConn) {
			// The proxy closed the tunnel while dialing.
			remoteConn.Close()
			return
		}
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			remoteConn.Close()
			if !isConnectionClosed(err) && !ctx.closedByProxy() {
				ctx.doError("Connect", ErrResponseWrite, err)
			}
			return
		}
		tunnel := ctx.tunnel
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				if !isConnectionClosed(err) && !tunnel.ClosedByProxy() {
					ctx.doError("Connect", ErrRequestRead, err)
				}
			}()
			_, err := io.Copy(remoteConn, hijConn)
			if err != nil {
				panic(err)
			}
			remoteConn.CloseWrite()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseRead()
			}
		}()
		go func() {
			defer wg.Done()
			defer func() {
				e := recover()
				err, ok := e.(error)
				if !ok {
					return
				}
				hijConn.Close()
				remoteConn.Close()
				if !isConnectionClosed(err) && !tunnel.ClosedByProxy() {
					ctx.doError("Connect", ErrResponseWrite, err)
				}
			}()
			_, err := io.Copy(hijConn, remoteConn)
			if err != nil {
				panic(err)
			}
			remoteConn.CloseRead()
			if c, ok := hijConn.(*net.TCPConn); ok {
				c.CloseWrite()
			}
		}()
		wg.Wait()
		hijConn.Close()
		remoteConn.Close()
	case ConnectMitm:
		tlsConfig := &tls.Config{}
		cert := ctx.Prx.signer.SignHost(host)
		if cert == nil {
			hijConn.Close()
			ctx.doError("Connect", ErrTLSSignHost, err)
			return
		}
		tlsConfig.Certificates = append(tlsConfig.Certificates, *cert)
		if _, err := hijConn.Write([]byte("HTTP/1.1 200 OK\r\n\r\n")); err != nil {
			hijConn.Close()
			if !isConnectionClosed(err) && !ctx.closedByProxy() {
				ctx.doError("Connect", ErrResponseWrite, err)
			}
			return
		}
		ctx.hijTLSConn = tls.Server(hijConn, tlsConfig)
		if err := ctx.hijTLSConn.Handshake(); err != nil {
			ctx.hijTLSConn.Close()
			if !isConnectionClosed(err) && !ctx.closedByProxy() {
				ctx.doError("Connect '"+host+"'", ErrTLSHandshake, err)
			}
			return
		}
		ctx.hijTLSReader = bufio.NewReader(ctx.hijTLSConn)
		b = false
	default:
		hijConn.Close()
	}
	return
}

func (ctx *Context) doMitm() (w http.ResponseWriter, r *http.Request) {
	req, err := http.ReadRequest(ctx.hijTLSReader)
	if err != nil {
		if !isConnectionClosed(err) && !ctx.closedByProxy() {
			ctx.doError("Request", ErrRequestRead, err)
		}
		return
	}
	req.RemoteAddr = ctx.ConnectReq.RemoteAddr
	if req.URL.IsAbs() {
		ctx.doError("Request", ErrAbsURLAfterCONNECT, nil)
		return
	}
	req.URL.Scheme = "https"
	req.URL.Host = ctx.ConnectHost
	w = NewConnResponseWriter(ctx.hijTLSConn)
	r = req
	return
}

func (ctx *Context) doRequest(w http.ResponseWriter, r *http.Request) (bool, error) {
	if !r.URL.IsAbs() {
		if r.Body != nil {
			defer r.Body.Close()
		}
		err := ServeInMemory(w, 500, nil, []byte("This is a proxy server. Does not respond to non-proxy requests."))
		if err != nil && !isConnectionClosed(err) {
			ctx.doError("Request", ErrResponseWrite, err)
		}
		return true, err
	}
	r.RequestURI = r.URL.String()
	if ctx.Prx.OnRequest == nil {
		return false, nil
	}
	resp := ctx.onRequest(r)
	if resp == nil {
		return false, nil
	}
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	ctx.closeAfterResponse = ctx.mitmResponseCloses()
	err := serveResponse(w, resp, ctx.closeAfterResponse)
	if err != nil && !isConnectionClosed(err) && !ctx.closedByProxy() {
		ctx.doError("Request", ErrResponseWrite, err)
	}
	return true, err
}

func (ctx *Context) doResponse(w http.ResponseWriter, r *http.Request) error {
	if r.Body != nil {
		defer r.Body.Close()
	}
	resp, err := ctx.Prx.Rt.RoundTrip(r)
	if err != nil {
		if err != context.Canceled && !isConnectionClosed(err) && !ctx.closedByProxy() {
			ctx.doError("Response", ErrRoundTrip, err)
		}
		ctx.closeAfterResponse = ctx.mitmResponseCloses()
		err := serveResponse(w, InMemoryResponse(404, nil, nil), ctx.closeAfterResponse)
		if err != nil && !isConnectionClosed(err) && !ctx.closedByProxy() {
			ctx.doError("Response", ErrResponseWrite, err)
		}
		return err
	}
	if ctx.Prx.OnResponse != nil {
		ctx.onResponse(r, resp)
	}
	resp.Request = r
	resp.TransferEncoding = nil
	if ctx.ConnectAction == ConnectMitm && ctx.Prx.MitmChunked {
		resp.TransferEncoding = []string{"chunked"}
	}
	ctx.closeAfterResponse = ctx.mitmResponseCloses()
	err = serveResponse(w, resp, ctx.closeAfterResponse)
	if err != nil && !isConnectionClosed(err) && !ctx.closedByProxy() {
		ctx.doError("Response", ErrResponseWrite, err)
	}
	return err
}
