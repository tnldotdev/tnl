package daemon

import (
	"net"
	"strconv"
	"testing"
)

// each topology declares its own inventory so independent test processes never
// compete for the deployment's default ports on the host.
func integrationServicePorts(t *testing.T) []string {
	t.Helper()
	ports, listeners := reserveIntegrationServicePorts(t)
	for _, listener := range listeners {
		_ = listener.Close()
	}
	return ports
}

func reserveIntegrationServicePorts(t *testing.T) ([]string, []net.Listener) {
	t.Helper()
	var listeners []net.Listener
	t.Cleanup(func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	})
	var ports []string
	for range 8 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
		ports = append(ports, strconv.Itoa(listener.Addr().(*net.TCPAddr).Port))
	}
	return ports, listeners
}
