//go:build !darwin

package proxy

import (
	"errors"
	"net"
)

func originalDestination(net.Conn) (string, error) {
	return "", errors.New("redir is only supported on macOS by this build")
}
