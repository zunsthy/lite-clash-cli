package socksaddr

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

func Encode(address string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("invalid target address %q: %w", address, err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return nil, fmt.Errorf("invalid target port in %q", address)
	}

	var result []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			result = make([]byte, 1+net.IPv4len+2)
			result[0] = 0x01
			copy(result[1:], ip4)
		} else {
			result = make([]byte, 1+net.IPv6len+2)
			result[0] = 0x04
			copy(result[1:], ip.To16())
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("invalid target host %q", host)
		}
		result = make([]byte, 1+1+len(host)+2)
		result[0] = 0x03
		result[1] = byte(len(host))
		copy(result[2:], host)
	}
	binary.BigEndian.PutUint16(result[len(result)-2:], uint16(port))
	return result, nil
}

func Read(reader io.Reader) ([]byte, error) {
	var kind [1]byte
	if _, err := io.ReadFull(reader, kind[:]); err != nil {
		return nil, err
	}
	var remaining int
	switch kind[0] {
	case 0x01:
		remaining = net.IPv4len + 2
	case 0x04:
		remaining = net.IPv6len + 2
	case 0x03:
		var length [1]byte
		if _, err := io.ReadFull(reader, length[:]); err != nil {
			return nil, err
		}
		result := make([]byte, 2+int(length[0])+2)
		result[0], result[1] = kind[0], length[0]
		if _, err := io.ReadFull(reader, result[2:]); err != nil {
			return nil, err
		}
		return result, nil
	default:
		return nil, fmt.Errorf("unsupported SOCKS address type %d", kind[0])
	}
	result := make([]byte, 1+remaining)
	result[0] = kind[0]
	if _, err := io.ReadFull(reader, result[1:]); err != nil {
		return nil, err
	}
	return result, nil
}

func String(address []byte) (string, error) {
	if len(address) < 1+2 {
		return "", errors.New("short SOCKS address")
	}
	var host string
	switch address[0] {
	case 0x01:
		if len(address) != 1+net.IPv4len+2 {
			return "", errors.New("invalid IPv4 SOCKS address")
		}
		host = net.IP(address[1 : 1+net.IPv4len]).String()
	case 0x04:
		if len(address) != 1+net.IPv6len+2 {
			return "", errors.New("invalid IPv6 SOCKS address")
		}
		host = net.IP(address[1 : 1+net.IPv6len]).String()
	case 0x03:
		length := int(address[1])
		if len(address) != 1+1+length+2 {
			return "", errors.New("invalid domain SOCKS address")
		}
		host = string(address[2 : 2+length])
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", address[0])
	}
	port := binary.BigEndian.Uint16(address[len(address)-2:])
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

func FromNetAddr(address net.Addr) []byte {
	var ip net.IP
	var port int
	switch value := address.(type) {
	case *net.TCPAddr:
		ip, port = value.IP, value.Port
	case *net.UDPAddr:
		ip, port = value.IP, value.Port
	default:
		return nil
	}
	if ip4 := ip.To4(); ip4 != nil {
		result := make([]byte, 1+net.IPv4len+2)
		result[0] = 0x01
		copy(result[1:], ip4)
		binary.BigEndian.PutUint16(result[1+net.IPv4len:], uint16(port))
		return result
	}
	if ip6 := ip.To16(); ip6 != nil {
		result := make([]byte, 1+net.IPv6len+2)
		result[0] = 0x04
		copy(result[1:], ip6)
		binary.BigEndian.PutUint16(result[1+net.IPv6len:], uint16(port))
		return result
	}
	return nil
}

func Split(data []byte) ([]byte, int, error) {
	if len(data) < 1 {
		return nil, 0, io.ErrUnexpectedEOF
	}
	length := 0
	switch data[0] {
	case 0x01:
		length = 1 + net.IPv4len + 2
	case 0x04:
		length = 1 + net.IPv6len + 2
	case 0x03:
		if len(data) < 2 {
			return nil, 0, io.ErrUnexpectedEOF
		}
		length = 1 + 1 + int(data[1]) + 2
	default:
		return nil, 0, fmt.Errorf("unsupported SOCKS address type %d", data[0])
	}
	if len(data) < length {
		return nil, 0, io.ErrUnexpectedEOF
	}
	return append([]byte(nil), data[:length]...), length, nil
}
