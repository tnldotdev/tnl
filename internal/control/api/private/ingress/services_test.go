package ingress

import "testing"

func TestPrivateSourceRequiresExactSocketIP(t *testing.T) {
	for _, source := range []string{"192.0.2.1", "2001:db8::1"} {
		if parsed, ok := privateSource(source); !ok || parsed.String() != source {
			t.Fatalf("rejected canonical socket source %q", source)
		}
	}
	for _, source := range []string{"", "192.0.2.1:443", "192.0.2.001", "2001:db8::1%eth0", "2001:0db8::1", "not-an-ip"} {
		if _, ok := privateSource(source); ok {
			t.Fatalf("accepted untrusted source %q", source)
		}
	}
}
