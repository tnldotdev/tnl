// package tcpport defines network TCP port bounds.
package tcpport

// ValidNetwork accepts a nonzero TCP source, destination, or private target port.
func ValidNetwork(port int) bool { return port >= 1 && port <= 65535 }
