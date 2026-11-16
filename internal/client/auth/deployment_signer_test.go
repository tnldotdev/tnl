package auth

import (
	"crypto/ed25519"
	"errors"
	"testing"
	"time"
)

func TestDeploymentCapturedSignerSurvivesApprovalExpiryWithoutRevalidation(t *testing.T) {
	credential := deploymentFixture(t)
	captured, err := credential.CaptureSigner()
	if err != nil {
		t.Fatal(err)
	}
	public := captured.PublicKey()
	credential.Approval.ExpiresAt = time.Now().Add(-time.Second)
	message := []byte("negative connector cleanup")
	if _, err := credential.Sign(message); !errors.Is(err, ErrDeploymentCredential) {
		t.Fatal("ordinary signing stopped checking the current approval", err)
	}
	if _, err := credential.CaptureSigner(); !errors.Is(err, ErrDeploymentCredential) {
		t.Fatal("an expired approval captured another signer", err)
	}
	if !ed25519.Verify(public, message, captured.Sign(message)) {
		t.Fatal("the original captured signing operation depended on current approval")
	}
	public[0] ^= 1
	if !ed25519.Verify(captured.PublicKey(), message, captured.Sign(message)) {
		t.Fatal("the public key exposed the captured private key's backing bytes")
	}
}
