package daemon

import (
	"net"
	"strconv"
	"testing"
)

type servicePortListeners []net.Listener

// inventory and serving use the same retained sockets, never released probes.
func newServicePortListeners(t *testing.T, owner *runtimeTopology) servicePortListeners {
	t.Helper()
	var listeners servicePortListeners
	owner.cleanupResource(t, func() {
		for _, listener := range listeners {
			_ = listener.Close()
		}
	})
	for range 8 {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		listeners = append(listeners, listener)
	}
	return listeners
}

func (listeners servicePortListeners) inventory() []string {
	ports := make([]string, len(listeners))
	for index, listener := range listeners {
		ports[index] = strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	}
	return ports
}
