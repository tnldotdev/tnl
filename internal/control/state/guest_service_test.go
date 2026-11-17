package state

import (
	"errors"
	"net/netip"
	"testing"
)

func TestGuestDemoTargetUsesOnlyBoundHTTPLoopbackOrigin(t *testing.T) {
	for _, test := range []struct{ input, target string }{
		{"http://127.0.0.1:3000", "127.0.0.1:3000"},
		{"http://127.0.0.1:3000/", "127.0.0.1:3000"},
		{"http://[::1]:3000", "[::1]:3000"},
		{"http://[::ffff:127.0.0.1]:3000", "127.0.0.1:3000"},
	} {
		target, err := guestDemoTarget(test.input)
		if err != nil || target != test.target {
			t.Fatalf("target %q = %q, %v", test.input, target, err)
		}
	}
	for _, target := range []string{
		"", "127.0.0.1:3000", "https://127.0.0.1:3000", "http://127.0.0.1", "http://localhost:3000",
		"http://0.0.0.0:3000", "http://[::]:3000", "http://192.0.2.7:3000", "http://127.0.0.1:0",
		"http://127.0.0.1:65536", "http://user:password@127.0.0.1:3000",
		"http://127.0.0.1:3000/path", "http://127.0.0.1:3000/?query", "http://127.0.0.1:3000/#fragment",
		"http://[::1%25en0]:3000",
	} {
		if _, err := guestDemoTarget(target); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatalf("target %q accepted: %v", target, err)
		}
	}
}

func TestGuestTrialRejectsMissingZonedAndUnspecifiedSource(t *testing.T) {
	for _, source := range []netip.Addr{{}, netip.IPv4Unspecified(), netip.IPv6Unspecified(),
		netip.MustParseAddr("::ffff:0.0.0.0"), netip.MustParseAddr("fe80::1%en0")} {
		if _, err := NewGuestTrialCredential(source); !errors.Is(err, ErrGuestUnknown) {
			t.Fatalf("source %s created credential: %v", source, err)
		}
	}
}
