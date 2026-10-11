// package tcptarget validates the private TCP address used by a publisher.
package tcptarget

import (
	"errors"
	"net"
	"strconv"

	"github.com/tnldotdev/tnl/internal/tcpport"
)

func Host(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", errors.New("private TCP target must be a host and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || !tcpport.ValidNetwork(number) {
		return "", errors.New("private TCP target port is invalid")
	}
	return host, nil
}

func Normalize(target string) (string, error) {
	if number, err := strconv.Atoi(target); err == nil && tcpport.ValidNetwork(number) {
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(number)), nil
	}
	if _, err := Host(target); err != nil {
		return "", err
	}
	return target, nil
}
