//go:build darwin

package proxy

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
	"unsafe"
)

func originalDestination(conn net.Conn) (string, error) {
	const (
		pfOut        = 2
		iocOut       = 0x40000000
		iocIn        = 0x80000000
		iocInOut     = iocIn | iocOut
		iocParamMask = 0x1fff
		natLookLen   = 4*16 + 4*4 + 4
		diocNatLook  = iocInOut | ((natLookLen & iocParamMask) << 16) | ('D' << 8) | 23
	)

	fd, err := syscall.Open("/dev/pf", syscall.O_RDONLY, 0)
	if err != nil {
		return "", err
	}
	defer syscall.Close(fd)

	remote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok || remote.IP.To4() == nil {
		return "", fmt.Errorf("unsupported redir source %v", conn.RemoteAddr())
	}
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok || local.IP.To4() == nil {
		return "", fmt.Errorf("unsupported redir destination %v", conn.LocalAddr())
	}

	lookup := struct {
		sourceAddress, destinationAddress                 [16]byte
		redirectSourceAddress, redirectDestinationAddress [16]byte
		sourcePort, destinationPort                       [4]byte
		redirectSourcePort, redirectDestinationPort       [4]byte
		addressFamily, protocol, variant, direction       uint8
	}{
		addressFamily: syscall.AF_INET,
		protocol:      syscall.IPPROTO_TCP,
		direction:     pfOut,
	}
	copy(lookup.sourceAddress[:4], remote.IP.To4())
	copy(lookup.destinationAddress[:4], local.IP.To4())
	lookup.sourcePort[0], lookup.sourcePort[1] = byte(remote.Port>>8), byte(remote.Port)
	lookup.destinationPort[0], lookup.destinationPort[1] = byte(local.Port>>8), byte(local.Port)

	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), uintptr(diocNatLook), uintptr(unsafe.Pointer(&lookup))); errno != 0 {
		return "", errno
	}
	ip := net.IP(lookup.redirectDestinationAddress[:4]).String()
	port := int(lookup.redirectDestinationPort[0])<<8 | int(lookup.redirectDestinationPort[1])
	return net.JoinHostPort(ip, strconv.Itoa(port)), nil
}
