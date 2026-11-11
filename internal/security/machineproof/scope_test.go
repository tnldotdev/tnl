package machineproof_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

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
