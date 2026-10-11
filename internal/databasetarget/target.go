// package databasetarget validates the private database address used by a publisher.
package databasetarget

import (
	"errors"
	"net"
	"strconv"

	"github.com/tnldotdev/tnl/internal/tcpport"
)

func Host(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", errors.New("database target must be a host and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || !tcpport.ValidNetwork(number) {
		return "", errors.New("database target port is invalid")
	}
	return host, nil
}
