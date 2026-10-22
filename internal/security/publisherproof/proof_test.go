package publisherproof

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestAssertionBindsClientKeyGrantAudienceAndLifetime(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	audience := "https://control.example/v1/publisher-token"
	jwt, err := Sign("client", "key", "grant", audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if key, err := KeyID(jwt); err != nil || key != "key" {
		t.Fatalf("key selector = %q, %v", key, err)
	}
	if a, err := Verify(jwt, "client", "key", "grant", audience, public, now); err != nil || a.ID == "" || !a.Until.Equal(now.Add(time.Minute)) {
		t.Fatalf("valid proof = %+v, %v", a, err)
	}
	for _, tc := range []struct {
		client, key, grant, audience string
		at                           time.Time
		token                        string
	}{
		{"other", "key", "grant", audience, now, jwt}, {"client", "other", "grant", audience, now, jwt}, {"client", "key", "other", audience, now, jwt}, {"client", "key", "grant", "https://other.example", now, jwt},
		{"client", "key", "grant", audience, now.Add(time.Minute), jwt}, {"client", "key", "grant", audience, now.Add(-6 * time.Second), jwt}, {"client", "key", "grant", audience, now, jwt + "x"}, {"client", "key", "grant", audience, now, strings.Repeat("a", 8193)},
	} {
		if _, err := Verify(tc.token, tc.client, tc.key, tc.grant, tc.audience, public, tc.at); err == nil {
			t.Fatal("out-of-scope or expired proof accepted")
		}
	}
}

func TestRunProofBindsExactURLAndRetry(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	proof, err := SignRun(private, "url_one", "retry_one")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := VerifyRun(public, proof, "url_one", "retry_one")
	if err != nil || secret == ([32]byte{}) {
		t.Fatal("valid run proof failed")
	}
	repeated, _ := SignRun(private, "url_one", "retry_one")
	if proof != repeated {
		t.Fatal("proof is not retry-stable")
	}
	for _, pair := range [][2]string{{"url_two", "retry_one"}, {"url_one", "retry_two"}, {"url_one\x00retry_one", ""}} {
		if _, err := VerifyRun(public, proof, pair[0], pair[1]); err == nil {
			t.Fatal("run proof crossed its retry boundary")
		}
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyRun(other, proof, "url_one", "retry_one"); err == nil {
		t.Fatal("foreign key accepted")
	}
}
