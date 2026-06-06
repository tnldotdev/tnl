package oidcnonce

import "testing"

func TestNonceBindsCoreEndpoint(t *testing.T) {
	const coreA = "https://core-a.example"
	nonce, err := New(coreA)
	if err != nil {
		t.Fatal(err)
	}
	if !Validate(coreA, nonce) {
		t.Fatal("nonce was not valid for its Core")
	}
	if Validate("https://core-b.example", nonce) {
		t.Fatal("nonce was valid for another Core")
	}
	second, err := New(coreA)
	if err != nil || second == nonce {
		t.Fatalf("second nonce = %q, error = %v", second, err)
	}
	for _, invalid := range []string{"", "random", nonce + ".extra", "tnl-core-v2" + nonce[len("tnl-core-v1"):]} {
		if Validate(coreA, invalid) {
			t.Fatalf("invalid nonce accepted: %q", invalid)
		}
	}
}

func TestNonceRequiresCanonicalCoreEndpoint(t *testing.T) {
	for _, endpoint := range []string{"", "http://core.example", "https://CORE.example", "https://core.example/", "https://core.example:443"} {
		if _, err := New(endpoint); err == nil {
			t.Fatalf("noncanonical endpoint accepted: %q", endpoint)
		}
	}
}
