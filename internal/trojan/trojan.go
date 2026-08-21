package trojan

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"lite-clash-cli/internal/socksaddr"
)

const (
	trojanCommandTCP = byte(0x01)
	trojanCommandUDP = byte(0x03)
	trojanMaxPacket  = 8192
)

var DefaultALPN = []string{"h2", "http/1.1"}

type Config struct {
	Name           string         `yaml:"name"`
	Server         string         `yaml:"server"`
	Port           int            `yaml:"port"`
	Type           string         `yaml:"type"`
	Password       string         `yaml:"password"`
	SNI            string         `yaml:"sni"`
	SkipCertVerify bool           `yaml:"skip-cert-verify"`
	UDP            bool           `yaml:"udp"`
	ALPN           []string       `yaml:"alpn"`
	Network        string         `yaml:"network"`
	Extra          map[string]any `yaml:",inline"`
}

type Dialer struct {
	config Config
}

func NewDialer(config Config) Dialer {
	return Dialer{config: config}
}

func (d Dialer) DialTCP(ctx context.Context, target string) (net.Conn, error) {
	addr, err := socksaddr.Encode(target)
	if err != nil {
		return nil, err
	}
	return d.dial(ctx, trojanCommandTCP, addr)
}

func (d Dialer) DialUDP(ctx context.Context, firstTarget []byte) (*PacketConn, error) {
	if !d.config.UDP {
		return nil, fmt.Errorf("Trojan proxy %q has UDP disabled", d.config.Name)
	}
	conn, err := d.dial(ctx, trojanCommandUDP, firstTarget)
	if err != nil {
		return nil, err
	}
	return &PacketConn{Conn: conn}, nil
}

func (d Dialer) dial(ctx context.Context, command byte, target []byte) (_ net.Conn, err error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
	}

	serverAddress := net.JoinHostPort(d.config.Server, strconv.Itoa(d.config.Port))
	rawConn, err := (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(ctx, "tcp", serverAddress)
	if err != nil {
		return nil, fmt.Errorf("connect to Trojan server %s: %w", serverAddress, err)
	}
	defer func() {
		if err != nil {
			_ = rawConn.Close()
		}
	}()

	tlsConn := tls.Client(rawConn, &tls.Config{
		ServerName:         d.config.SNI,
		InsecureSkipVerify: d.config.SkipCertVerify, //nolint:gosec -- explicit YAML option
		NextProtos:         append([]string(nil), d.config.ALPN...),
		MinVersion:         tls.VersionTLS12,
	})
	if err = tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("Trojan TLS handshake with %s: %w", serverAddress, err)
	}

	header := makeTrojanHeader(d.config.Password, command, target)
	if err = writeAll(tlsConn, header); err != nil {
		return nil, fmt.Errorf("write Trojan request header: %w", err)
	}
	return tlsConn, nil
}

func makeTrojanHeader(password string, command byte, target []byte) []byte {
	hash := sha256.Sum224([]byte(password))
	hexPassword := make([]byte, hex.EncodedLen(len(hash)))
	hex.Encode(hexPassword, hash[:])

	header := make([]byte, 0, len(hexPassword)+2+1+len(target)+2)
	header = append(header, hexPassword...)
	header = append(header, '\r', '\n', command)
	header = append(header, target...)
	header = append(header, '\r', '\n')
	return header
}

type PacketConn struct {
	net.Conn
	writeMu sync.Mutex
}

func (pc *PacketConn) WritePacket(target, payload []byte) error {
	pc.writeMu.Lock()
	defer pc.writeMu.Unlock()

	for offset := 0; offset < len(payload); {
		end := offset + trojanMaxPacket
		if end > len(payload) {
			end = len(payload)
		}
		frame := make([]byte, 0, len(target)+2+2+end-offset)
		frame = append(frame, target...)
		var length [2]byte
		binary.BigEndian.PutUint16(length[:], uint16(end-offset))
		frame = append(frame, length[:]...)
		frame = append(frame, '\r', '\n')
		frame = append(frame, payload[offset:end]...)
		if err := writeAll(pc.Conn, frame); err != nil {
			return err
		}
		offset = end
	}
	return nil
}

func (pc *PacketConn) ReadPacket() (target, payload []byte, err error) {
	target, err = socksaddr.Read(pc.Conn)
	if err != nil {
		return nil, nil, fmt.Errorf("read Trojan UDP address: %w", err)
	}
	var header [4]byte
	if _, err = io.ReadFull(pc.Conn, header[:]); err != nil {
		return nil, nil, fmt.Errorf("read Trojan UDP length: %w", err)
	}
	length := int(binary.BigEndian.Uint16(header[:2]))
	if length > trojanMaxPacket {
		return nil, nil, fmt.Errorf("invalid Trojan UDP packet length %d", length)
	}
	if header[2] != '\r' || header[3] != '\n' {
		return nil, nil, errors.New("invalid Trojan UDP CRLF")
	}
	payload = make([]byte, length)
	if _, err = io.ReadFull(pc.Conn, payload); err != nil {
		return nil, nil, fmt.Errorf("read Trojan UDP payload: %w", err)
	}
	return target, payload, nil
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}
