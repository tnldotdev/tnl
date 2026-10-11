package tcpport

import "testing"

func TestPublicAndNetworkPortBounds(t *testing.T) {
	for _, test := range []struct {
		port            int
		public, network bool
	}{
		{0, false, false},
		{1, false, true},
		{1023, false, true},
		{1024, true, true},
		{65535, true, true},
		{65536, false, false},
	} {
		if Valid(test.port) != test.public || ValidNetwork(test.port) != test.network {
			t.Errorf("port %d: public=%t network=%t", test.port, Valid(test.port), ValidNetwork(test.port))
		}
	}
}
