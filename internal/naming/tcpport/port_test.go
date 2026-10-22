package tcpport

import "testing"

func TestNetworkPortBounds(t *testing.T) {
	for _, test := range []struct {
		port    int
		network bool
	}{
		{0, false},
		{1, true},
		{1023, true},
		{1024, true},
		{65535, true},
		{65536, false},
	} {
		if ValidNetwork(test.port) != test.network {
			t.Errorf("port %d: network=%t", test.port, ValidNetwork(test.port))
		}
	}
}
