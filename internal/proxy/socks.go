package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	configpkg "lite-clash-cli/internal/config"
	"lite-clash-cli/internal/socksaddr"
	"lite-clash-cli/internal/trojan"
)

const (
	socksVersion        = byte(0x05)
	socksConnect        = byte(0x01)
	socksUDPAssociate   = byte(0x03)
	socksNoAuth         = byte(0x00)
	socksPasswordAuth   = byte(0x02)
	socksNoAcceptable   = byte(0xff)
	socksSucceeded      = byte(0x00)
	socksGeneralFailed  = byte(0x01)
	socksCmdUnsupported = byte(0x07)
)

func (a *Application) handleSocksConnection(conn net.Conn, udpServer *socksUDPServer) {
	a.trackConnection(conn)
	defer a.untrackConnection(conn)
	defer conn.Close()

	if err := a.serveSocksConnection(conn, udpServer); err != nil && !errors.Is(err, io.EOF) {
		a.logger.Printf("SOCKS connection from %s failed: %v", conn.RemoteAddr(), err)
	}
}

func (a *Application) serveSocksConnection(conn net.Conn, udpServer *socksUDPServer) error {
	users := a.currentConfig().Users
	if err := negotiateSocksAuthentication(conn, users); err != nil {
		return err
	}

	var requestHeader [3]byte
	if _, err := io.ReadFull(conn, requestHeader[:]); err != nil {
		return err
	}
	if requestHeader[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version %d", requestHeader[0])
	}
	target, err := socksaddr.Read(conn)
	if err != nil {
		_ = writeSocksReply(conn, 0x08, conn.LocalAddr())
		return err
	}

	switch requestHeader[1] {
	case socksConnect:
		targetText, err := socksaddr.String(target)
		if err != nil {
			_ = writeSocksReply(conn, 0x08, conn.LocalAddr())
			return err
		}
		remote, err := a.currentDialer().DialTCP(a.context(), targetText)
		if err != nil {
			_ = writeSocksReply(conn, socksGeneralFailed, conn.LocalAddr())
			return err
		}
		a.trackConnection(remote)
		defer a.untrackConnection(remote)
		defer remote.Close()
		if err := writeSocksReply(conn, socksSucceeded, conn.LocalAddr()); err != nil {
			return err
		}
		relayConnections(conn, remote)
		return nil
	case socksUDPAssociate:
		if udpServer == nil {
			_ = writeSocksReply(conn, socksCmdUnsupported, conn.LocalAddr())
			return errors.New("SOCKS UDP is not available on this listener")
		}
		if !a.currentConfig().Selected.UDP {
			_ = writeSocksReply(conn, socksCmdUnsupported, conn.LocalAddr())
			return errors.New("selected Trojan proxy has UDP disabled")
		}
		release := udpServer.authorize(conn.RemoteAddr())
		defer release()
		if err := writeSocksReply(conn, socksSucceeded, conn.LocalAddr()); err != nil {
			return err
		}
		_, err = io.Copy(io.Discard, conn)
		return err
	default:
		_ = writeSocksReply(conn, socksCmdUnsupported, conn.LocalAddr())
		return fmt.Errorf("unsupported SOCKS command %d", requestHeader[1])
	}
}

func negotiateSocksAuthentication(conn net.Conn, users configpkg.Credentials) error {
	var greeting [2]byte
	if _, err := io.ReadFull(conn, greeting[:]); err != nil {
		return err
	}
	if greeting[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version %d", greeting[0])
	}
	methods := make([]byte, int(greeting[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	wanted := socksNoAuth
	if len(users) != 0 {
		wanted = socksPasswordAuth
	}
	if !containsByte(methods, wanted) {
		_, _ = conn.Write([]byte{socksVersion, socksNoAcceptable})
		return errors.New("no acceptable SOCKS authentication method")
	}
	if _, err := conn.Write([]byte{socksVersion, wanted}); err != nil {
		return err
	}
	if wanted == socksNoAuth {
		return nil
	}
	return authenticateSocksPassword(conn, users)
}

func authenticateSocksPassword(conn net.Conn, users configpkg.Credentials) error {
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return errors.New("unsupported SOCKS password authentication version")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	var length [1]byte
	if _, err := io.ReadFull(conn, length[:]); err != nil {
		return err
	}
	password := make([]byte, int(length[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}
	expected, exists := users[string(username)]
	if !exists || expected != string(password) {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return errors.New("SOCKS authentication failed")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

func writeSocksReply(conn net.Conn, status byte, bindAddress net.Addr) error {
	address := socksaddr.FromNetAddr(bindAddress)
	if address == nil {
		address = []byte{0x01, 0, 0, 0, 0, 0, 0}
	}
	reply := append([]byte{socksVersion, status, 0x00}, address...)
	return writeAll(conn, reply)
}

func containsByte(values []byte, wanted byte) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

type socksUDPServer struct {
	app        *Application
	conn       net.PacketConn
	mu         sync.Mutex
	sessions   map[string]*udpSession
	authorized map[string]int
	closed     chan struct{}
	closeOnce  sync.Once
}

type udpSession struct {
	server    *socksUDPServer
	key       string
	client    net.Addr
	proxy     *trojan.PacketConn
	lastSeen  time.Time
	mu        sync.Mutex
	closeOnce sync.Once
}

func newSocksUDPServer(application *Application, conn net.PacketConn) *socksUDPServer {
	return &socksUDPServer{
		app:        application,
		conn:       conn,
		sessions:   make(map[string]*udpSession),
		authorized: make(map[string]int),
		closed:     make(chan struct{}),
	}
}

func (s *socksUDPServer) Serve() {
	go s.reapSessions()
	for {
		buffer := make([]byte, 65535)
		n, client, err := s.conn.ReadFrom(buffer)
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				s.app.logger.Printf("SOCKS UDP read failed: %v", err)
				continue
			}
		}
		packet := append([]byte(nil), buffer[:n]...)
		go s.handlePacket(client, packet)
	}
}

func (s *socksUDPServer) handlePacket(client net.Addr, packet []byte) {
	if !s.isAuthorized(client) {
		return
	}
	target, payload, err := decodeSocksUDPPacket(packet)
	if err != nil {
		return
	}
	target, err = resolveUDPAddress(s.app.context(), target, s.app.currentConfig().IPv6)
	if err != nil {
		s.app.logger.Printf("SOCKS UDP resolve failed: %v", err)
		return
	}

	session, err := s.sessionFor(client, target)
	if err != nil {
		s.app.logger.Printf("SOCKS UDP Trojan connection failed: %v", err)
		return
	}
	session.mu.Lock()
	session.lastSeen = time.Now()
	err = session.proxy.WritePacket(target, payload)
	session.mu.Unlock()
	if err != nil {
		session.Close()
	}
}

func (s *socksUDPServer) sessionFor(client net.Addr, firstTarget []byte) (*udpSession, error) {
	key := client.String()
	s.mu.Lock()
	if existing := s.sessions[key]; existing != nil {
		s.mu.Unlock()
		return existing, nil
	}
	s.mu.Unlock()

	proxy, err := s.app.currentDialer().DialUDP(s.app.context(), firstTarget)
	if err != nil {
		return nil, err
	}
	session := &udpSession{
		server:   s,
		key:      key,
		client:   client,
		proxy:    proxy,
		lastSeen: time.Now(),
	}

	s.mu.Lock()
	if existing := s.sessions[key]; existing != nil {
		s.mu.Unlock()
		_ = proxy.Close()
		return existing, nil
	}
	s.sessions[key] = session
	s.mu.Unlock()
	go session.readLoop()
	return session, nil
}

func (session *udpSession) readLoop() {
	defer session.Close()
	for {
		target, payload, err := session.proxy.ReadPacket()
		if err != nil {
			return
		}
		packet := encodeSocksUDPPacket(target, payload)
		if _, err := session.server.conn.WriteTo(packet, session.client); err != nil {
			return
		}
		session.mu.Lock()
		session.lastSeen = time.Now()
		session.mu.Unlock()
	}
}

func (session *udpSession) Close() {
	session.closeOnce.Do(func() {
		_ = session.proxy.Close()
		session.server.mu.Lock()
		if session.server.sessions[session.key] == session {
			delete(session.server.sessions, session.key)
		}
		session.server.mu.Unlock()
	})
}

func (s *socksUDPServer) Close() error {
	s.closeOnce.Do(func() {
		close(s.closed)
		_ = s.conn.Close()
		s.mu.Lock()
		sessions := make([]*udpSession, 0, len(s.sessions))
		for _, session := range s.sessions {
			sessions = append(sessions, session)
		}
		s.mu.Unlock()
		for _, session := range sessions {
			session.Close()
		}
	})
	return nil
}

func (s *socksUDPServer) reapSessions() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			cutoff := time.Now().Add(-60 * time.Second)
			s.mu.Lock()
			allSessions := make([]*udpSession, 0, len(s.sessions))
			for _, session := range s.sessions {
				allSessions = append(allSessions, session)
			}
			s.mu.Unlock()
			sessions := make([]*udpSession, 0)
			for _, session := range allSessions {
				session.mu.Lock()
				stale := session.lastSeen.Before(cutoff)
				session.mu.Unlock()
				if stale {
					sessions = append(sessions, session)
				}
			}
			for _, session := range sessions {
				session.Close()
			}
		case <-s.closed:
			return
		}
	}
}

func (s *socksUDPServer) authorize(address net.Addr) func() {
	if len(s.app.currentConfig().Users) == 0 {
		return func() {}
	}
	key := addressIP(address)
	s.mu.Lock()
	s.authorized[key]++
	s.mu.Unlock()
	return func() {
		s.mu.Lock()
		s.authorized[key]--
		if s.authorized[key] <= 0 {
			delete(s.authorized, key)
		}
		s.mu.Unlock()
	}
}

func (s *socksUDPServer) isAuthorized(address net.Addr) bool {
	if len(s.app.currentConfig().Users) == 0 {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.authorized[addressIP(address)] > 0
}

func addressIP(address net.Addr) string {
	switch value := address.(type) {
	case *net.TCPAddr:
		return value.IP.String()
	case *net.UDPAddr:
		return value.IP.String()
	default:
		host, _, _ := net.SplitHostPort(address.String())
		return host
	}
}

func decodeSocksUDPPacket(packet []byte) (target, payload []byte, err error) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 {
		return nil, nil, errors.New("invalid SOCKS UDP reserved bytes")
	}
	if packet[2] != 0 {
		return nil, nil, errors.New("fragmented SOCKS UDP packets are not supported")
	}
	target, length, err := socksaddr.Split(packet[3:])
	if err != nil {
		return nil, nil, err
	}
	return target, packet[3+length:], nil
}

func encodeSocksUDPPacket(target, payload []byte) []byte {
	packet := make([]byte, 0, 3+len(target)+len(payload))
	packet = append(packet, 0, 0, 0)
	packet = append(packet, target...)
	packet = append(packet, payload...)
	return packet
}

func resolveUDPAddress(ctx context.Context, address []byte, allowIPv6 bool) ([]byte, error) {
	if len(address) < 2 || address[0] != 0x03 {
		return address, nil
	}
	target, err := socksaddr.String(address)
	if err != nil {
		return nil, err
	}
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		return nil, err
	}
	resolveContext, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIPAddr(resolveContext, host)
	if err != nil {
		return nil, err
	}
	for _, candidate := range addresses {
		if candidate.IP.To4() != nil {
			return socksaddr.Encode(net.JoinHostPort(candidate.IP.String(), port))
		}
	}
	if allowIPv6 && len(addresses) != 0 {
		return socksaddr.Encode(net.JoinHostPort(addresses[0].IP.String(), port))
	}
	return nil, fmt.Errorf("no usable IP address for %s", host)
}

func handleMixedConnection(application *Application, conn net.Conn, httpListener *channelListener, udpServer *socksUDPServer) {
	application.trackConnection(conn)
	reader := bufio.NewReader(conn)
	first, err := reader.Peek(1)
	if err != nil {
		application.untrackConnection(conn)
		_ = conn.Close()
		return
	}
	wrapped := &bufferedConn{Conn: conn, reader: reader}
	if first[0] == socksVersion {
		application.handleSocksConnection(wrapped, udpServer)
		return
	}
	if err := httpListener.Dispatch(wrapped); err != nil {
		application.untrackConnection(conn)
		_ = conn.Close()
		return
	}
	application.untrackConnection(conn)
}
