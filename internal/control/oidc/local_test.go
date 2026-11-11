package oidc

import "testing"

func TestProviderEndpointTransportBoundary(t *testing.T) {
	for _, tc := range []struct {
		issuer, endpoint string
		valid            bool
	}{
		{"https://identity.example", "https://keys.example/keys", true},
		{"https://identity.example", "http://localhost/keys", false},
		{"http://localhost:8444", "http://localhost:8444/keys", true},
		{"http://localhost:8444", "http://localhost:8445/keys", false},
		{"http://localhost:8444", "http://127.0.0.1:8444/keys", false},
		{"http://localhost:8444", "https://remote.example/keys", false},
		{"http://localhost:8444", "http://user@localhost:8444/keys", false},
		{"http://localhost:8444", "http://localhost:8444/keys#fragment", false},
	} {
		if got := validProviderEndpoint(tc.endpoint, tc.issuer); got != tc.valid {
			t.Errorf("endpoint %q for %q: got %v", tc.endpoint, tc.issuer, got)
		}
	}
	for _, issuer := range []string{"http://identity", "http://identity.127.0.0.1.nip.io", "http://localhost.example", "http://192.168.1.1"} {
		if _, err := NewVerifier(VerifierConfig{Issuer: issuer, ClientID: "client"}); err == nil {
			t.Errorf("accepted non-loopback issuer %q", issuer)
		}
	}
}
