package publisheridentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestRunProofBindsURLIdempotencyAndKey(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SignRun(private, "url_a", "attempt_a")
	if err != nil {
		t.Fatal(err)
	}
	first, err := VerifyRun(public, proof, "url_a", "attempt_a")
	if err != nil {
		t.Fatal(err)
	}
	retry, err := SignRun(private, "url_a", "attempt_a")
	if err != nil || proof != retry {
		t.Fatalf("run proof changed on retry: %v", err)
	}
	if first == ([32]byte{}) {
		t.Fatal("retry secret is empty")
	}
	otherPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, proof, urlID, key string
		public                  ed25519.PublicKey
	}{
		{"wrong URL", proof, "url_b", "attempt_a", public},
		{"wrong idempotency", proof, "url_a", "attempt_b", public},
		{"wrong key", proof, "url_a", "attempt_a", otherPublic},
		{"tampered", proof + "a", "url_a", "attempt_a", public},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := VerifyRun(test.public, test.proof, test.urlID, test.key); !errors.Is(err, ErrRunProof) {
				t.Fatalf("proof error = %v", err)
			}
		})
	}
}
