package publisheridentity

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

func TestRunProofBindsURLAndAttempt(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := SignRun(private, "url_1", "attempt-1")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := VerifyRun(public, proof, "url_1", "attempt-1")
	if err != nil || secret == [32]byte{} {
		t.Fatalf("valid proof = %x, %v", secret, err)
	}
	for _, other := range [][2]string{{"url_2", "attempt-1"}, {"url_1", "attempt-2"}} {
		if _, err := VerifyRun(public, proof, other[0], other[1]); !errors.Is(err, ErrRunProof) {
			t.Fatalf("proof accepted for %v: %v", other, err)
		}
	}
	if again, err := VerifyRun(public, proof, "url_1", "attempt-1"); err != nil || again != secret {
		t.Fatalf("retry secret changed: %v", err)
	}
}
