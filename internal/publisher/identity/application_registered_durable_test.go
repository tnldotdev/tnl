package identity

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestRegisteredApplicationDurableReopenPinsOriginalKeyNonceSourceAndURL(t *testing.T) {
	f := newDurableApplicationHTTP(t, func(binding *clientstate.ApplicationPublicationBinding) {
		binding.SourceKind = "registered_key"
		binding.SourceKeyID = "registered-source"
	})
	source := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{19}, 32))
	f.verifySource = func(assertion, operation, nonce, audience string) {
		public := base64.RawURLEncoding.EncodeToString(f.public)
		if _, err := publisherproof.Verify(assertion, f.binding.SourceMachineID, f.binding.SourceKeyID, machineproof.Publication("", f.binding.Namespace, operation, public, nonce), audience, source.Public().(ed25519.PublicKey), time.Now()); err != nil {
			t.Fatal("registered source lost exact canonical scope", err)
		}
	}
	proof := func(operation, key string) string {
		record := f.snapshot()
		defer clear(record.NativeKey)
		nonce, audience := record.Nonce, f.binding.ServerURL+"/v1/machine-publication-sessions/exchange"
		if operation == "refresh" {
			nonce = record.SessionID
			audience = f.binding.ServerURL + "/v1/machine-publication-sessions/" + record.SessionID + "/refresh"
		}
		public := base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(record.NativeKey).Public().(ed25519.PublicKey))
		assertion, err := publisherproof.Sign(f.binding.SourceMachineID, key, machineproof.Publication("", f.binding.Namespace, operation, public, nonce), audience, source, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return assertion
	}
	original := f.snapshot()
	defer clear(original.NativeKey)
	f.lose = "/v1/machine-publication-sessions/exchange"
	if _, err := OpenApplicationSession(t.Context(), f.control, f.authority, f.entry, proof("exchange", f.binding.SourceKeyID)); !errors.Is(err, lostApplicationReply) {
		t.Fatal(err)
	}
	f.reopen()
	s := f.open(proof("exchange", f.binding.SourceKeyID))
	before, err := s.Allocate(t.Context(), controlv1.AllocateEphemeralPublicURLRequest{InvocationId: f.binding.InvocationID, Target: f.binding.Target})
	if err != nil {
		t.Fatal(err)
	}
	f.response.IdentityExpiresAt = f.response.IdentityExpiresAt.Add(time.Minute)
	f.lose = "/v1/machine-publication-sessions/" + f.response.Id + "/refresh"
	if err := s.Refresh(t.Context(), proof("refresh", f.binding.SourceKeyID)); !errors.Is(err, lostApplicationReply) {
		t.Fatal(err)
	}
	f.reopen()
	s = f.open(proof("exchange", f.binding.SourceKeyID))
	recovered, err := s.Allocate(t.Context(), controlv1.AllocateEphemeralPublicURLRequest{InvocationId: f.binding.InvocationID, Target: f.binding.Target})
	if err != nil || recovered.Id != before.Id || recovered.CanonicalHostname != before.CanonicalHostname || f.allocations != 1 || f.creations != 1 {
		t.Fatal("registered reopen replaced its accepted URL", err)
	}
	accepted := f.snapshot()
	defer clear(accepted.NativeKey)
	if accepted.Nonce != original.Nonce || !bytes.Equal(accepted.NativeKey, original.NativeKey) || accepted.Binding.SourceKeyID != f.binding.SourceKeyID {
		t.Fatal("registered reopen replaced source or native signing tuple")
	}
	if err := s.Refresh(t.Context(), proof("refresh", "rotated-source")); !errors.Is(err, ErrScope) || f.refreshes != 1 {
		t.Fatal("rotated source key escaped the original pin", err)
	}
	f.revoked = true
	if err := s.Refresh(t.Context(), proof("refresh", f.binding.SourceKeyID)); err == nil {
		t.Fatal("revoked source extended serving")
	}
	f.reopen()
	if err := CleanupApplicationPublication(t.Context(), f.entry, f.authority); err != nil {
		t.Fatal("cleanup needed the revoked source key", err)
	}
	if f.cleanups != 1 || f.tokens != 1 || f.allocations != 1 || f.exchanges != 3 || f.refreshes != 2 {
		t.Fatal("cleanup/recovery acquired another source or allocation")
	}
}
