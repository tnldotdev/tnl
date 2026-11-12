package local

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type applicationChallenge struct {
	challenge authorityv1.IdentitySourceChallenge
	revision  uint64
}

func applicationRequestFingerprint(request publisherprotocol.ApplicationPublication) ([32]byte, error) {
	request.Auth = nil
	encoded, err := json.Marshal(request)
	return sha256.Sum256(encoded), err
}

// challenge binding includes public local-owner facts and the original native
// tuple, never its signing key or transient source assertion.
func applicationChallengeBinding(r clientstate.ApplicationPublicationRecord) string {
	public := base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(r.NativeKey).Public().(ed25519.PublicKey))
	encoded, _ := json.Marshal([]any{r.StateRoot, r.ProjectRoot, r.WorktreeRoot, r.Binding, r.Revision, r.Phase, r.ResumePhase, public, r.Nonce, r.SessionID, r.Publisher, r.PublicURL, r.OwnerExpiresAt, r.IdentityExpiresAt, r.ConfirmationDeadline, r.ConfirmedAt})
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func (a *appRuntime) challengeApplication(ctx context.Context, request publisherprotocol.ApplicationPublication) (authorityv1.IdentitySourceChallenge, error) {
	if err := validateApplication(request); err != nil {
		return authorityv1.IdentitySourceChallenge{}, err
	}
	source, err := applicationSourceProof(request.Auth, false)
	if err != nil || source.selection.Kind != "registered_key" || source.reply != nil {
		return authorityv1.IdentitySourceChallenge{}, publisherprotocol.ErrApplicationAuthInvalid
	}
	release, err := a.beginPreparation(ctx, request.InvocationId)
	if err != nil {
		return authorityv1.IdentitySourceChallenge{}, err
	}
	defer release()
	finish := a.manager.BeginPreparation()
	defer finish()
	fingerprint, err := applicationRequestFingerprint(request)
	if err != nil {
		return authorityv1.IdentitySourceChallenge{}, err
	}
	entry, err := a.applicationCheckpoint(ctx, request, fingerprint)
	if err != nil {
		return authorityv1.IdentitySourceChallenge{}, err
	}
	record, err := entry.Snapshot(ctx)
	if err != nil {
		return authorityv1.IdentitySourceChallenge{}, err
	}
	defer clear(record.NativeKey)
	if record.Phase == clientstate.ApplicationDenied || record.Phase == clientstate.ApplicationCleanupPending || record.Phase == clientstate.ApplicationCleanupDone || len(record.NativeKey) != ed25519.PrivateKeySize {
		return authorityv1.IdentitySourceChallenge{}, publisherprotocol.ErrApplicationDenied
	}
	now := time.Now()
	expires := now.Add(time.Minute)
	if record.OwnerExpiresAt.Before(expires) {
		expires = record.OwnerExpiresAt
	}
	if record.Publisher != nil && record.IdentityExpiresAt.Before(expires) {
		expires = record.IdentityExpiresAt
	}
	if record.ConfirmationPending() && record.ConfirmationDeadline.Before(expires) {
		expires = record.ConfirmationDeadline
	}
	challenge := authorityv1.IdentitySourceChallenge{Schema: 1, Source: source.selection, Server: record.Binding.ServerURL, BindingDigest: applicationChallengeBinding(record), ExpiresAt: expires, NativePublicKey: base64.RawURLEncoding.EncodeToString(ed25519.PrivateKey(record.NativeKey).Public().(ed25519.PublicKey)), Publication: &authorityv1.IdentitySourcePublicationSelection{Resource: record.Binding.ResourceID, Namespace: record.Binding.Namespace}}
	operation, nonce := "exchange", record.Nonce
	challenge.Operation, challenge.Nonce = "publication_exchange", record.Nonce
	switch {
	case record.ConfirmationPending():
	case record.Phase == clientstate.ApplicationExchangePending || record.Phase == clientstate.ApplicationRefreshPending:
	case record.Phase == clientstate.ApplicationSessionAccepted || record.Phase == clientstate.ApplicationAllocationPending || record.Phase == clientstate.ApplicationURLAccepted:
		operation, nonce = "refresh", record.SessionID
		challenge.Operation, challenge.Nonce, challenge.SessionId = "publication_refresh", "", record.SessionID
	default:
		return authorityv1.IdentitySourceChallenge{}, publisherprotocol.ErrApplicationDenied
	}
	challenge.Audience = challenge.Server + "/v1/machine-publication-sessions/exchange"
	if operation == "refresh" {
		challenge.Audience = challenge.Server + "/v1/machine-publication-sessions/" + record.SessionID + "/refresh"
	}
	challenge.Scope = machineproof.Publication(record.Binding.ResourceID, record.Binding.Namespace, operation, challenge.NativePublicKey, nonce)
	challenge.Id, err = publisherprotocol.Random(16)
	if err != nil {
		return authorityv1.IdentitySourceChallenge{}, err
	}
	if err := machineproof.ValidateSourceChallenge(challenge, now); err != nil {
		return authorityv1.IdentitySourceChallenge{}, publisherprotocol.ErrApplicationDenied
	}
	if err := context.Cause(ctx); err != nil {
		return authorityv1.IdentitySourceChallenge{}, err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.applicationChallenges == nil {
		a.applicationChallenges = map[string]applicationChallenge{}
	}
	for invocation, slot := range a.applicationChallenges {
		if !slot.challenge.ExpiresAt.After(now) {
			delete(a.applicationChallenges, invocation)
		}
	}
	if _, existing := a.applicationChallenges[request.InvocationId]; !existing && len(a.applicationChallenges) >= clientstate.ApplicationPublicationCapacity {
		return authorityv1.IdentitySourceChallenge{}, publisherprotocol.ErrApplicationUnavailable
	}
	a.applicationChallenges[request.InvocationId] = applicationChallenge{challenge: challenge, revision: record.Revision}
	return challenge, nil
}

// the caller holds the invocation preparation gate across consumption and its
// authority operation. a response-loss retry must request a fresh challenge for
// the same durable tuple; an old source reply is never a reusable credential.
func (a *appRuntime) consumeApplicationChallenge(ctx context.Context, request publisherprotocol.ApplicationPublication, entry *clientstate.ApplicationPublication) error {
	source, err := applicationSourceProof(request.Auth, true)
	if err != nil {
		return err
	}
	if source.selection.Kind == "oidc" {
		return nil
	}
	record, err := entry.Snapshot(ctx)
	if err != nil {
		return err
	}
	defer clear(record.NativeKey)
	if len(record.NativeKey) != ed25519.PrivateKeySize {
		return publisherprotocol.ErrApplicationDenied
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	slot, found := a.applicationChallenges[request.InvocationId]
	if !found || source.reply == nil || slot.challenge.Id != source.reply.ChallengeId || slot.challenge.Source != source.selection || record.Revision != slot.revision || slot.challenge.BindingDigest != applicationChallengeBinding(record) || machineproof.ValidateSourceChallenge(slot.challenge, time.Now()) != nil {
		return publisherprotocol.ErrApplicationChallengeStale
	}
	delete(a.applicationChallenges, request.InvocationId)
	return nil
}

func (a *appRuntime) forgetApplicationChallenge(invocation string) {
	a.mu.Lock()
	delete(a.applicationChallenges, invocation)
	a.mu.Unlock()
}
