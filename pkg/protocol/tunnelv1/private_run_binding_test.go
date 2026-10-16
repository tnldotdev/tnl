package tunnelv1

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestPublisherRunKeyBindingIsExactAndRetryStable(t *testing.T) {
	enrolled, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	streamKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	binding := PrivateRunKeyBinding{TeamID: testOpaqueID(opaqueid.TeamPrefix),
		PrivateServiceID: testOpaqueID(opaqueid.PrivateServicePrefix), PrivateRunID: testOpaqueID(opaqueid.PrivateRunPrefix),
		RunNumber: 1, PublisherIdentityID: testOpaqueID(opaqueid.PublisherIdentityPrefix),
		PublisherGrantID: testOpaqueID(opaqueid.PublisherGrantPrefix), PublisherKeyID: testOpaqueID(opaqueid.PublisherIdentityKeyPrefix),
		IdempotencyKey: "attempt", BindingNonce: make([]byte, 32), StreamPublicKey: streamKey}
	digest, err := PrivateRunBindingDigest(binding)
	if err != nil {
		t.Fatal(err)
	}
	signature := ed25519.Sign(signer, digest)
	if !VerifyPrivateRunKeyBinding(enrolled, binding, signature) ||
		!VerifyPrivateRunKeyBinding(enrolled, binding, signature) {
		t.Fatal("matching idempotent binding rejected")
	}
	for _, mutate := range []func(*PrivateRunKeyBinding){
		func(b *PrivateRunKeyBinding) { b.TeamID = opaqueid.TeamPrefix + strings.Repeat("b", 22) },
		func(b *PrivateRunKeyBinding) {
			b.PrivateServiceID = opaqueid.PrivateServicePrefix + strings.Repeat("b", 22)
		},
		func(b *PrivateRunKeyBinding) { b.PrivateRunID = opaqueid.PrivateRunPrefix + strings.Repeat("b", 22) },
		func(b *PrivateRunKeyBinding) { b.RunNumber++ },
		func(b *PrivateRunKeyBinding) {
			b.PublisherIdentityID = opaqueid.PublisherIdentityPrefix + strings.Repeat("b", 22)
		},
		func(b *PrivateRunKeyBinding) {
			b.PublisherGrantID = opaqueid.PublisherGrantPrefix + strings.Repeat("b", 22)
		},
		func(b *PrivateRunKeyBinding) {
			b.PublisherKeyID = opaqueid.PublisherIdentityKeyPrefix + strings.Repeat("b", 22)
		},
		func(b *PrivateRunKeyBinding) { b.IdempotencyKey = "another-attempt" },
		func(b *PrivateRunKeyBinding) { b.BindingNonce = append([]byte{1}, b.BindingNonce[1:]...) },
		func(b *PrivateRunKeyBinding) { b.StreamPublicKey = enrolled },
	} {
		changed := binding
		mutate(&changed)
		if VerifyPrivateRunKeyBinding(enrolled, changed, signature) {
			t.Fatalf("cross-run publisher signature accepted: %+v", changed)
		}
	}
	binding.BindingNonce = nil
	if _, err := PrivateRunBindingDigest(binding); err == nil {
		t.Fatal("accepted binding without control nonce")
	}
	binding.BindingNonce = make([]byte, 32)
	binding.PrivateServiceID = testOpaqueID(opaqueid.PublicURLPrefix)
	if _, err := PrivateRunBindingDigest(binding); err == nil {
		t.Fatal("accepted public URL ID in private run binding")
	}
	binding.PrivateServiceID = testOpaqueID(opaqueid.PrivateServicePrefix)
	binding.PrivateRunID = testOpaqueID(opaqueid.PublishRunPrefix)
	if _, err := PrivateRunBindingDigest(binding); err == nil {
		t.Fatal("accepted public publish run ID in private run binding")
	}
}
