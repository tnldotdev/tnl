// package tcpport defines public and ordinary TCP port bounds.
package tcpport

const (
	Min = 1024
	Max = 65535
)

func Valid(port int) bool { return port >= Min && port <= Max }

// ValidNetwork accepts a nonzero TCP source, destination, or private target port.
func ValidNetwork(port int) bool { return port >= 1 && port <= Max }
