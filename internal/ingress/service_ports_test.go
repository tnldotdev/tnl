package ingress

import (
	"errors"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/tcpport"
)

func TestIngressInventoryValidationAndOwnership(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	configuration := Config{MaxConnections: 8, Lookup: func(string) (PublicURL, LookupReason) { return PublicURL{}, "" }}
	public, err := New(listener, configuration)
	if err != nil {
		t.Fatal("public-only ingress requires no inventory", err)
	}
	t.Cleanup(public.cancelOpens)
	if public.servicePorts.Contains(20000) {
		t.Fatal("public-only ingress gained service ports")
	}
	for _, ranges := range [][]tcpport.Range{{}, {{First: 1023, Last: 1024}}, {{First: 20000, Last: 20256}}, {{First: 20000, Last: 20001}, {First: 20001, Last: 20002}}} {
		configuration.ServicePortRanges = ranges
		if _, err := New(listener, configuration); !errors.Is(err, tcpport.ErrInventory) {
			t.Fatal("invalid ingress inventory", ranges, err)
		}
	}
	ranges := []tcpport.Range{{First: 20000, Last: 20255}}
	configuration.ServicePortRanges = ranges
	server, err := New(listener, configuration)
	if err != nil {
		t.Fatal("256-port inventory", err)
	}
	t.Cleanup(server.cancelOpens)
	ranges[0] = tcpport.Range{First: 30000, Last: 30000}
	if !server.servicePorts.Contains(20000) || !server.servicePorts.Contains(20255) || server.servicePorts.Contains(30000) {
		t.Fatal("ingress retained a mutable inventory")
	}
}
