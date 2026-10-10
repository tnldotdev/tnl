// package tcpport defines the public TCP port inventory bounds used by control.
package tcpport

const (
	Min = 1024
	Max = 65535
)

func Valid(port int) bool { return port >= Min && port <= Max }
