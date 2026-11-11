package machineproof_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestPublicationCleanupBindsOnlyOriginalRemoval(t *testing.T) {
	scope := machineproof.PublicationCleanup("session", "invocation")
	for _, other := range []string{
		machineproof.PublicationCleanup("other", "invocation"),
		machineproof.PublicationCleanup("session", "other"),
		machineproof.Publication("session", "", "cleanup", "", "invocation"),
		machineproof.Provisioning("session", "invocation"),
	} {
		if scope == other {
			t.Fatal("cleanup proof authorized another purpose or allocation")
		}
	}
}

func TestPublicationScopesAndPossessionDoNotMixPurposes(t *testing.T) {
	scope := machineproof.Publication("resource", "", "exchange", "public", "nonce")
	for _, other := range []string{machineproof.Publication("other", "", "exchange", "public", "nonce"), machineproof.Publication("", "resource", "exchange", "public", "nonce"), machineproof.Publication("resource", "", "refresh", "public", "nonce"), machineproof.Publication("resource", "", "exchange", "other", "nonce"), machineproof.Publication("resource", "", "exchange", "public", "other"), machineproof.Provisioning("resource", "read")} {
		if scope == other {
			t.Fatal("publication scope collision")
		}
	}
	digest := sha256.Sum256([]byte("platform assertion"))
	message := machineproof.PublicationPossession("resource", "", "exchange", "public", "nonce", digest)
	if bytes.Equal(message, machineproof.PublicationPossession("resource", "", "refresh", "public", "nonce", digest)) {
		t.Fatal("exchange possession authorized refresh")
	}
	other := sha256.Sum256([]byte("different platform assertion"))
	if bytes.Equal(message, machineproof.PublicationPossession("resource", "", "exchange", "public", "nonce", other)) {
		t.Fatal("possession did not bind the identity assertion")
	}
}

func TestMachineProofOperationAndScopeBinding(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	scope := machineproof.Provisioning("grant-one", "create")
	audience := "https://control.example/v1/provisioning-sessions/exchange"
	token, err := publisherproof.Sign("machine-one", "key-one", scope, audience, private, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publisherproof.Verify(token, "machine-one", "key-one", scope, audience, public, now); err != nil {
		t.Fatal(err)
	}
	for name, fields := range map[string][5]string{
		"identity":  {"machine-two", "key-one", scope, audience, ""},
		"key":       {"machine-one", "key-two", scope, audience, ""},
		"grant":     {"machine-one", "key-one", machineproof.Provisioning("grant-two", "create"), audience, ""},
		"operation": {"machine-one", "key-one", machineproof.Provisioning("grant-one", "enroll"), audience, ""},
		"audience":  {"machine-one", "key-one", scope, "https://other.example/v1/provisioning-sessions/exchange", ""},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := publisherproof.Verify(token, fields[0], fields[1], fields[2], fields[3], public, now); err == nil {
				t.Fatal("accepted wrong proof scope")
			}
		})
	}
	if _, err = publisherproof.Verify(token, "machine-one", "key-one", scope, audience, public, now.Add(time.Minute)); err == nil {
		t.Fatal("accepted expired proof")
	}
	_, foreign, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := publisherproof.Sign("machine-one", "key-one", scope, audience, foreign, now)
	if _, err = publisherproof.Verify(forged, "machine-one", "key-one", scope, audience, public, now); err == nil {
		t.Fatal("accepted foreign signature")
	}
}

func TestMachineWorkloadProofBindsEveryExchangeField(t *testing.T) {
	scope := machineproof.Workload("group", "workload", "exchange", "public", "nonce", []string{"group/api"})
	for _, other := range []string{
		machineproof.Workload("other", "workload", "exchange", "public", "nonce", []string{"group/api"}),
		machineproof.Workload("group", "other", "exchange", "public", "nonce", []string{"group/api"}),
		machineproof.Workload("group", "workload", "resolve", "public", "nonce", []string{"group/api"}),
		machineproof.Workload("group", "workload", "exchange", "other", "nonce", []string{"group/api"}),
		machineproof.Workload("group", "workload", "exchange", "public", "other", []string{"group/api"}),
		machineproof.Workload("group", "workload", "exchange", "public", "nonce", []string{"group/db"}),
	} {
		if scope == other {
			t.Fatal("exchange scope collision")
		}
	}
	if machineproof.Provisioning("group", "read") == scope {
		t.Fatal("proof purpose collision")
	}
}
