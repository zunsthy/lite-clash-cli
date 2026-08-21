package proxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

type httpProxy struct {
	app       *Application
	transport *http.Transport
}

func newHTTPProxy(application *Application) *httpProxy {
	proxy := &httpProxy{app: application}
	proxy.transport = &http.Transport{
		Proxy:             nil,
		DisableKeepAlives: true,
		ForceAttemptHTTP2: false,
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			return proxy.app.currentDialer().DialTCP(ctx, address)
		},
	}
	return proxy
}

func (p *httpProxy) Close() {
	p.transport.CloseIdleConnections()
}

func (p *httpProxy) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if !p.authorized(request) {
		response.Header().Set("Proxy-Authenticate", `Basic realm="lite-clash"`)
		http.Error(response, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	if request.Method == http.MethodConnect {
		p.serveConnect(response, request)
		return
	}
	if strings.EqualFold(request.Header.Get("Upgrade"), "websocket") {
		http.Error(response, "HTTP Upgrade is not supported; use CONNECT", http.StatusNotImplemented)
		return
	}
	p.serveForward(response, request)
}

func (p *httpProxy) authorized(request *http.Request) bool {
	users := p.app.currentConfig().Users
	if len(users) == 0 {
		return true
	}
	username, password, ok := parseProxyAuthorization(request.Header.Get("Proxy-Authorization"))
	if !ok {
		return false
	}
	expected, exists := users[username]
	return exists && expected == password
}

func parseProxyAuthorization(value string) (string, string, bool) {
	request := &http.Request{Header: make(http.Header)}
	request.Header.Set("Authorization", value)
	return request.BasicAuth()
}

func (p *httpProxy) serveConnect(response http.ResponseWriter, request *http.Request) {
	target := request.Host
	if !strings.Contains(target, ":") {
		target = net.JoinHostPort(target, "443")
	}
	remote, err := p.app.currentDialer().DialTCP(request.Context(), target)
	if err != nil {
		p.app.logger.Printf("HTTP CONNECT %s failed: %v", target, err)
		http.Error(response, "bad gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := response.(http.Hijacker)
	if !ok {
		_ = remote.Close()
		http.Error(response, "connection hijacking is unavailable", http.StatusInternalServerError)
		return
	}
	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = remote.Close()
		return
	}
	p.app.trackConnection(client)
	p.app.trackConnection(remote)
	defer p.app.untrackConnection(client)
	defer p.app.untrackConnection(remote)
	defer client.Close()
	defer remote.Close()

	if _, err := buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	if err := buffered.Flush(); err != nil {
		return
	}
	wrappedClient := net.Conn(client)
	if buffered.Reader.Buffered() != 0 {
		wrappedClient = &bufferedConn{Conn: client, reader: buffered.Reader}
	}
	relayConnections(wrappedClient, remote)
}

func (p *httpProxy) serveForward(response http.ResponseWriter, request *http.Request) {
	outgoing := request.Clone(request.Context())
	outgoing.RequestURI = ""
	if outgoing.URL.Scheme == "" {
		outgoing.URL.Scheme = "http"
	}
	if outgoing.URL.Host == "" {
		outgoing.URL.Host = request.Host
	}
	removeHopByHopHeaders(outgoing.Header)
	outgoing.Header.Del("Proxy-Authorization")

	upstream, err := p.transport.RoundTrip(outgoing)
	if err != nil {
		p.app.logger.Printf("HTTP %s %s failed: %v", request.Method, outgoing.URL.String(), err)
		http.Error(response, "bad gateway", http.StatusBadGateway)
		return
	}
	defer upstream.Body.Close()

	copyHeaders(response.Header(), upstream.Header)
	removeHopByHopHeaders(response.Header())
	response.WriteHeader(upstream.StatusCode)
	_, _ = io.Copy(response, upstream.Body)
}

func copyHeaders(destination, source http.Header) {
	for key, values := range source {
		for _, value := range values {
			destination.Add(key, value)
		}
	}
}

func removeHopByHopHeaders(header http.Header) {
	if connection := header.Get("Connection"); connection != "" {
		for _, name := range strings.Split(connection, ",") {
			header.Del(strings.TrimSpace(name))
		}
	}
	for _, name := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		header.Del(name)
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(buffer []byte) (int, error) {
	return c.reader.Read(buffer)
}

type channelListener struct {
	address net.Addr
	conns   chan net.Conn
	done    chan struct{}
	once    sync.Once
}

func newChannelListener(address net.Addr) *channelListener {
	return &channelListener{
		address: address,
		conns:   make(chan net.Conn, 64),
		done:    make(chan struct{}),
	}
}

func (l *channelListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		if conn == nil {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *channelListener) Close() error {
	l.once.Do(func() {
		close(l.done)
		for {
			select {
			case conn := <-l.conns:
				if conn != nil {
					_ = conn.Close()
				}
			default:
				return
			}
		}
	})
	return nil
}

func (l *channelListener) Addr() net.Addr {
	return l.address
}

func (l *channelListener) Dispatch(conn net.Conn) error {
	select {
	case l.conns <- conn:
		return nil
	case <-l.done:
		return net.ErrClosed
	default:
		return errors.New("HTTP connection queue is full")
	}
}

func relayConnections(left, right net.Conn) {
	var wait sync.WaitGroup
	wait.Add(2)
	copyDirection := func(destination, source net.Conn) {
		defer wait.Done()
		_, _ = io.Copy(destination, source)
		closeWrite(destination)
	}
	go copyDirection(left, right)
	go copyDirection(right, left)
	wait.Wait()
}

func closeWrite(conn net.Conn) {
	type closeWriter interface{ CloseWrite() error }
	if writer, ok := conn.(closeWriter); ok {
		_ = writer.CloseWrite()
	}
}

func serveHTTPServer(server *http.Server, listener net.Listener, logger interface{ Printf(string, ...any) }) {
	if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
		logger.Printf("HTTP listener stopped: %v", err)
	}
}
