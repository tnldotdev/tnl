// package databasetarget validates the private database address used by a publisher.
package databasetarget

import (
	"errors"
	"net"
	"strconv"
)

func Host(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return "", errors.New("database target must be a host and port")
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", errors.New("database target port is invalid")
	}
	return host, nil
}
