package proxy

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sync"
	"sync/atomic"

	configpkg "lite-clash-cli/internal/config"
	"lite-clash-cli/internal/trojan"
)

type Application struct {
	config atomic.Pointer[configpkg.Runtime]
	logger *log.Logger

	ctx    context.Context
	cancel context.CancelFunc

	proxyHandler *httpProxy
	listeners    []net.Listener
	httpServers  []*http.Server
	httpChannels []*channelListener
	udpServers   []*socksUDPServer
	active       sync.Map
	wait         sync.WaitGroup
	closeOnce    sync.Once
}

func New(config *configpkg.Runtime, logger *log.Logger) *Application {
	ctx, cancel := context.WithCancel(context.Background())
	application := &Application{logger: logger, ctx: ctx, cancel: cancel}
	application.config.Store(config)
	application.proxyHandler = newHTTPProxy(application)
	return application
}

func (a *Application) Start() (err error) {
	defer func() {
		if err != nil {
			a.Close()
		}
	}()
	cfg := a.currentConfig()
	if cfg.Port != 0 {
		if err = a.startHTTP(cfg.ListenAddress(cfg.Port), "HTTP"); err != nil {
			return err
		}
	}
	if cfg.SocksPort != 0 {
		if err = a.startSocks(cfg.ListenAddress(cfg.SocksPort), false); err != nil {
			return err
		}
	}
	if cfg.MixedPort != 0 {
		if err = a.startSocks(cfg.ListenAddress(cfg.MixedPort), true); err != nil {
			return err
		}
	}
	if cfg.RedirPort != 0 {
		if err = a.startRedir(cfg.ListenAddress(cfg.RedirPort)); err != nil {
			return err
		}
	}
	return nil
}

func (a *Application) Reload(config *configpkg.Runtime) error {
	if config.ListenerKey() != a.currentConfig().ListenerKey() {
		return errors.New("listening ports, bind address, or authentication changed; restart is required")
	}
	a.config.Store(config)
	return nil
}

func (a *Application) Close() {
	a.closeOnce.Do(func() {
		a.cancel()
		for _, listener := range a.listeners {
			_ = listener.Close()
		}
		for _, listener := range a.httpChannels {
			_ = listener.Close()
		}
		for _, server := range a.httpServers {
			_ = server.Close()
		}
		for _, server := range a.udpServers {
			_ = server.Close()
		}
		a.proxyHandler.Close()
		a.active.Range(func(key, _ any) bool {
			_ = key.(net.Conn).Close()
			return true
		})
		a.wait.Wait()
	})
}

func (a *Application) currentConfig() *configpkg.Runtime {
	return a.config.Load()
}

func (a *Application) currentDialer() trojan.Dialer {
	return trojan.NewDialer(a.currentConfig().Selected)
}

func (a *Application) context() context.Context {
	return a.ctx
}

func (a *Application) trackConnection(conn net.Conn) {
	a.active.Store(conn, struct{}{})
}

func (a *Application) untrackConnection(conn net.Conn) {
	a.active.Delete(conn)
}

func (a *Application) connectionState(conn net.Conn, state http.ConnState) {
	switch state {
	case http.StateNew, http.StateActive, http.StateIdle:
		a.trackConnection(conn)
	case http.StateHijacked, http.StateClosed:
		a.untrackConnection(conn)
	}
}

func (a *Application) startHTTP(address, name string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("start %s listener at %s: %w", name, address, err)
	}
	a.listeners = append(a.listeners, listener)
	server := &http.Server{
		Handler:   a.proxyHandler,
		ConnState: a.connectionState,
		BaseContext: func(net.Listener) context.Context {
			return a.ctx
		},
	}
	a.httpServers = append(a.httpServers, server)
	a.wait.Add(1)
	go func() {
		defer a.wait.Done()
		serveHTTPServer(server, listener, a.logger)
	}()
	a.logger.Printf("%s proxy listening at %s", name, listener.Addr())
	return nil
}

func (a *Application) startSocks(address string, mixed bool) error {
	tcpListener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("start TCP listener at %s: %w", address, err)
	}
	udpConn, err := net.ListenPacket("udp", address)
	if err != nil {
		_ = tcpListener.Close()
		return fmt.Errorf("start UDP listener at %s: %w", address, err)
	}
	a.listeners = append(a.listeners, tcpListener)
	udpServer := newSocksUDPServer(a, udpConn)
	a.udpServers = append(a.udpServers, udpServer)
	a.wait.Add(1)
	go func() {
		defer a.wait.Done()
		udpServer.Serve()
	}()

	if mixed {
		httpListener := newChannelListener(tcpListener.Addr())
		a.httpChannels = append(a.httpChannels, httpListener)
		httpServer := &http.Server{
			Handler:   a.proxyHandler,
			ConnState: a.connectionState,
			BaseContext: func(net.Listener) context.Context {
				return a.ctx
			},
		}
		a.httpServers = append(a.httpServers, httpServer)
		a.wait.Add(1)
		go func() {
			defer a.wait.Done()
			serveHTTPServer(httpServer, httpListener, a.logger)
		}()
		a.startAcceptLoop(tcpListener, func(conn net.Conn) {
			handleMixedConnection(a, conn, httpListener, udpServer)
		})
		a.logger.Printf("mixed HTTP/SOCKS proxy listening at %s (TCP/UDP)", tcpListener.Addr())
		return nil
	}

	a.startAcceptLoop(tcpListener, func(conn net.Conn) {
		a.handleSocksConnection(conn, udpServer)
	})
	a.logger.Printf("SOCKS5 proxy listening at %s (TCP/UDP)", tcpListener.Addr())
	return nil
}

func (a *Application) startRedir(address string) error {
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("start redir listener at %s: %w", address, err)
	}
	a.listeners = append(a.listeners, listener)
	a.startAcceptLoop(listener, a.handleRedirConnection)
	a.logger.Printf("redir TCP proxy listening at %s", listener.Addr())
	return nil
}

func (a *Application) startAcceptLoop(listener net.Listener, handler func(net.Conn)) {
	a.wait.Add(1)
	go func() {
		defer a.wait.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if a.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
					return
				}
				a.logger.Printf("accept at %s failed: %v", listener.Addr(), err)
				continue
			}
			go handler(conn)
		}
	}()
}

func (a *Application) handleRedirConnection(conn net.Conn) {
	a.trackConnection(conn)
	defer a.untrackConnection(conn)
	defer conn.Close()

	target, err := originalDestination(conn)
	if err != nil {
		a.logger.Printf("redir destination lookup failed: %v", err)
		return
	}
	remote, err := a.currentDialer().DialTCP(a.ctx, target)
	if err != nil {
		a.logger.Printf("redir connection to %s failed: %v", target, err)
		return
	}
	a.trackConnection(remote)
	defer a.untrackConnection(remote)
	defer remote.Close()
	relayConnections(conn, remote)
}
