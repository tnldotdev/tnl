package local

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	localv1 "github.com/tnldotdev/tnl/pkg/api/publisher/local/v1"
)

func registeredApplicationRequest(t *testing.T, a *appRuntime) (publisherprotocol.Endpoint, publisherprotocol.ApplicationPublication, ed25519.PrivateKey) {
	t.Helper()
	endpoint, request := applicationRequest(t, a)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request.Auth = registeredApplicationAuth(t, nil)
	return endpoint, request, private
}

func registeredApplicationAuth(t *testing.T, reply *authorityv1.IdentitySourceReply) json.RawMessage {
	t.Helper()
	encoded, err := json.Marshal(localv1.ApplicationRegisteredKeyProof{Kind: "registered_key", MachineId: "mci_0123456789ABCDEFGHIJKL", KeyId: "source-key", Reply: reply})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func issueApplicationChallenge(t *testing.T, endpoint publisherprotocol.Endpoint, request publisherprotocol.ApplicationPublication) authorityv1.IdentitySourceChallenge {
	t.Helper()
	var challenge authorityv1.IdentitySourceChallenge
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/identity-source-challenges", request, &challenge); err != nil {
		t.Fatal(err)
	}
	if err := machineproof.ValidateSourceChallenge(challenge, time.Now()); err != nil {
		t.Fatal(err)
	}
	return challenge
}

func signApplicationReply(t *testing.T, challenge authorityv1.IdentitySourceChallenge, private ed25519.PrivateKey) authorityv1.IdentitySourceReply {
	t.Helper()
	assertion, err := publisherproof.Sign(challenge.Source.MachineId, challenge.Source.KeyId, challenge.Scope, challenge.Audience, private, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return authorityv1.IdentitySourceReply{Schema: 1, ChallengeId: challenge.Id, Assertion: assertion}
}

func TestRegisteredApplicationChallengeBindsDurableTupleAndConsumesOnce(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request, private := registeredApplicationRequest(t, a)
	var resolves atomic.Int32
	a.ApplicationAuthority = applicationAuthority(func(_ context.Context, s invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
		resolves.Add(1)
		return applicationGrant(s), nil
	})
	a.workers.RunPublisher = readyInvocation
	challenge := issueApplicationChallenge(t, endpoint, request)
	fingerprint, _ := applicationRequestFingerprint(request)
	entry, err := a.applicationCheckpoint(t.Context(), request, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	record, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record.NativeKey)
	if record.Binding.SourceKind != "registered_key" || record.Binding.SourceKeyID != "source-key" || challenge.Publication.Resource != *request.ResourceId || challenge.Nonce != record.Nonce || challenge.BindingDigest != applicationChallengeBinding(record) || challenge.NativePublicKey != base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(record.NativeKey).Public().(ed25519.PublicKey)) || resolves.Load() != 0 {
		t.Fatal("challenge preceded synced immutable source/native intent")
	}
	reply := signApplicationReply(t, challenge, private)
	request.Auth = registeredApplicationAuth(t, &reply)
	var accepted publisherprotocol.AcceptedPublication
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, &accepted); err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, new(publisherprotocol.AcceptedPublication)); err == nil || resolves.Load() != 1 {
		t.Fatal("consumed source reply was replayed", err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/unregister", accepted.Registration, nil); err != nil {
		t.Fatal(err)
	}
}

func TestRegisteredApplicationChallengeRejectsCrossOwnerTargetRevisionAndExpiry(t *testing.T) {
	for _, change := range []string{"owner", "target", "revision", "expiry", "resource", "key-rotation", "replaced-challenge"} {
		t.Run(change, func(t *testing.T) {
			a, _ := testAppRuntimeWorkers(t, true)
			endpoint, request, private := registeredApplicationRequest(t, a)
			var calls atomic.Int32
			a.ApplicationAuthority = applicationAuthority(func(_ context.Context, s invocation.ApplicationSelection) (invocation.ApplicationGrant, error) {
				calls.Add(1)
				return applicationGrant(s), nil
			})
			a.workers.RunPublisher = readyInvocation
			challenge := issueApplicationChallenge(t, endpoint, request)
			fingerprint, _ := applicationRequestFingerprint(request)
			entry, err := a.applicationCheckpoint(t.Context(), request, fingerprint)
			if err != nil {
				t.Fatal(err)
			}
			reply := signApplicationReply(t, challenge, private)
			request.Auth = registeredApplicationAuth(t, &reply)
			switch change {
			case "owner":
				request.Owner = strings.Repeat("a", 32)
			case "target":
				request.Target = "http://127.0.0.1:4000"
			case "resource":
				request.ResourceId = new("url_1123456789ABCDEFGHIJKL")
			case "revision":
				if err := entry.RenewOwner(t.Context(), time.Now().Add(time.Minute)); err != nil {
					t.Fatal(err)
				}
			case "expiry":
				a.mu.Lock()
				slot := a.applicationChallenges[request.InvocationId]
				slot.challenge.ExpiresAt = time.Now().Add(-time.Second)
				a.applicationChallenges[request.InvocationId] = slot
				a.mu.Unlock()
			case "key-rotation":
				request.Auth = json.RawMessage(strings.ReplaceAll(string(request.Auth), "source-key", "replacement-key"))
			case "replaced-challenge":
				fresh := request
				fresh.Auth = registeredApplicationAuth(t, nil)
				replacement := issueApplicationChallenge(t, endpoint, fresh)
				if replacement.Id == challenge.Id || replacement.NativePublicKey != challenge.NativePublicKey || replacement.Nonce != challenge.Nonce {
					t.Fatal("replacement challenge changed original native tuple")
				}
			}
			if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/publications", request, new(publisherprotocol.AcceptedPublication)); err == nil || calls.Load() != 0 {
				t.Fatal("cross-boundary source reply reached authority", err)
			}
		})
	}
}

func TestRegisteredApplicationChallengeCleanupAndDenialNeverAcquireAnotherSource(t *testing.T) {
	a, _ := testAppRuntimeWorkers(t, true)
	endpoint, request, _ := registeredApplicationRequest(t, a)
	issueApplicationChallenge(t, endpoint, request)
	fingerprint, _ := applicationRequestFingerprint(request)
	entry, err := a.applicationCheckpoint(t.Context(), request, fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	record, err := entry.Snapshot(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record.NativeKey)
	record.Phase = clientstate.ApplicationDenied
	if err := entry.Checkpoint(t.Context(), record); err != nil {
		t.Fatal(err)
	}
	if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/identity-source-challenges", request, new(authorityv1.IdentitySourceChallenge)); err == nil {
		t.Fatal("denied intent acquired another source challenge")
	}
	if err := a.unregisterApplication(t.Context(), request.InvocationId, publisherprotocol.Registration{Version: 1, Owner: request.Owner, Target: request.Target}); err != nil {
		t.Fatal(err)
	}
	completed, err := entry.Snapshot(t.Context())
	if err != nil || completed.Phase != clientstate.ApplicationCleanupDone || len(completed.NativeKey) != 0 {
		t.Fatal("resource-less original intent did not finish without source", err)
	}
	if !errors.Is(machineproof.ValidateSourceChallenge(authorityv1.IdentitySourceChallenge{}, time.Now()), machineproof.ErrSourceChallenge) {
		t.Fatal("empty shared challenge accepted")
	}
}
