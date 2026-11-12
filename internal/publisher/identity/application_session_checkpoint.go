package identity

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// recoverSession replays only an uncertain exchange/refresh using the original
// nonce and key. control decides whether the stored session is still valid;
// fresh source proof must not turn that replay into a new session or lease.
func (s *ApplicationSession) recoverSession(ctx context.Context, record clientstate.ApplicationPublicationRecord, assertion string) error {
	if !record.OwnerExpiresAt.After(time.Now()) {
		return s.recordFailure(ctx, ErrScope)
	}
	if record.ConfirmationPending() && !time.Now().Before(record.ConfirmationDeadline) {
		return s.recordFailure(ctx, ErrScope)
	}
	if record.Publisher != nil && !record.IdentityExpiresAt.After(time.Now()) {
		return s.recordFailure(ctx, ErrScope)
	}
	deadline := record.OwnerExpiresAt
	if record.Publisher != nil && record.IdentityExpiresAt.Before(deadline) {
		deadline = record.IdentityExpiresAt
	}
	if record.ConfirmationPending() && record.ConfirmationDeadline.Before(deadline) {
		deadline = record.ConfirmationDeadline
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	public := base64.RawURLEncoding.EncodeToString(s.private.Public().(ed25519.PublicKey))
	body := authorityv1.MachinePublicationExchange{MachineId: record.Binding.SourceMachineID, Resource: s.resource, Namespace: s.namespace, Assertion: assertion, Nonce: s.nonce, PublicKey: public, Signature: s.possession("exchange", s.nonce, assertion)}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	response, err := s.authority.ExchangeMachinePublication(ctx, body)
	if err != nil {
		return s.recordFailure(ctx, errors.Join(context.Cause(ctx), err))
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	previousID, previousScope, previousAccess, previousIdentity := s.id, s.scope, s.expiresAt, s.identityExpiresAt
	accepted := false
	defer func() {
		if !accepted {
			s.id, s.scope, s.expiresAt, s.identityExpiresAt = previousID, previousScope, previousAccess, previousIdentity
		}
	}()
	if err := s.accept(response, false, time.Now()); err != nil {
		return err
	}
	if record.Publisher != nil {
		previous, err := newNativeScope(*record.Publisher)
		if err != nil || response.Id != record.SessionID || s.scope != previous || response.IdentityExpiresAt.Before(record.IdentityExpiresAt) || response.ExpiresAt.Before(record.AccessExpiresAt) {
			return invalidApplicationSession()
		}
	}
	phase := clientstate.ApplicationSessionAccepted
	if record.Phase == clientstate.ApplicationRefreshPending {
		phase = record.ResumePhase
	} else if record.ConfirmationPending() {
		phase = record.Phase
	}
	if err := s.checkpointSession(ctx, record, response, phase); err != nil {
		return errors.Join(ErrApplicationSessionUncertain, err)
	}
	if err := s.advanceFence(ctx, s.identityExpiresAt, deadline); err != nil {
		return err
	}
	accepted = true
	return nil
}

func (s *ApplicationSession) checkpointSession(ctx context.Context, record clientstate.ApplicationPublicationRecord, response authorityv1.MachinePublicationSession, phase clientstate.ApplicationPublicationPhase) error {
	record.SessionID, record.Publisher = response.Id, &response.Publisher
	record.AccessExpiresAt, record.IdentityExpiresAt, record.RenewAfter = response.ExpiresAt, response.IdentityExpiresAt, response.RenewAfter
	record.Phase, record.ResumePhase = phase, ""
	record.OwnerExpiresAt = time.Now().Add(clientstate.ApplicationPublicationLeaseDuration)
	checkpointErr := s.publication.Checkpoint(ctx, record)
	if err := errors.Join(context.Cause(ctx), checkpointErr); err != nil {
		return errors.Join(ErrApplicationSessionUncertain, err)
	}
	if err := context.Cause(ctx); err != nil {
		return errors.Join(ErrApplicationSessionUncertain, err)
	}
	return nil
}

func (s *ApplicationSession) recordFailure(ctx context.Context, operation error) error {
	reason, _ := failure.ReasonOf(operation)
	if !errors.Is(operation, ErrScope) && reason != failure.Authentication && reason != failure.ServerDenied && reason != failure.ServerResourceNotFound && reason != failure.PublisherGrantMismatch {
		return errors.Join(ErrApplicationSessionUncertain, operation)
	}
	if fence := s.fence.Load(); fence != nil {
		s.publishFence(fence.deadline, true)
	}
	checkpoint, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	record, err := s.publication.Snapshot(checkpoint)
	if err != nil {
		return errors.Join(operation, err)
	}
	defer clear(record.NativeKey)
	if record.Phase == clientstate.ApplicationDenied || record.Phase == clientstate.ApplicationCleanupPending || record.Phase == clientstate.ApplicationCleanupDone {
		return operation
	}
	record.Phase, record.ResumePhase = clientstate.ApplicationDenied, ""
	return errors.Join(operation, s.publication.Checkpoint(checkpoint, record))
}

func (s *ApplicationSession) acceptPublicURL(ctx context.Context, publicURL controlv1.PublicURL) error {
	record, err := s.publication.Snapshot(ctx)
	if err != nil {
		return err
	}
	defer clear(record.NativeKey)
	record.PublicURL, record.Phase = &publicURL, clientstate.ApplicationURLAccepted
	record.OwnerExpiresAt = time.Now().Add(clientstate.ApplicationPublicationLeaseDuration)
	if err := s.publication.Checkpoint(ctx, record); err != nil {
		return errors.Join(ErrApplicationSessionUncertain, err)
	}
	return nil
}

func (s *ApplicationSession) SavedPublicURL(ctx context.Context) (controlv1.PublicURL, error) {
	record, err := s.publication.Snapshot(ctx)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	defer clear(record.NativeKey)
	if record.Phase == clientstate.ApplicationURLAccepted && record.PublicURL != nil {
		return clonePublicURL(*record.PublicURL), nil
	}
	u, err := s.native.SavedPublicURL(ctx)
	if err != nil {
		return u, s.recordFailure(ctx, err)
	}
	return u, s.acceptPublicURL(ctx, u)
}

// CleanupApplicationPublication works directly from the original checkpoint.
// it never needs a source assertion, serving token, installed key, or new grant.
// the process owner must join any publication worker before calling it.
func CleanupApplicationPublication(ctx context.Context, publication ApplicationCheckpoint, authority ApplicationSessionAuthority) error {
	record, err := publication.Snapshot(ctx)
	if err != nil {
		return err
	}
	defer clear(record.NativeKey)
	if record.Phase == clientstate.ApplicationCleanupDone {
		return nil
	}
	if record.Phase != clientstate.ApplicationCleanupPending {
		record.Phase, record.ResumePhase = clientstate.ApplicationCleanupPending, ""
		if err := publication.Checkpoint(ctx, record); err != nil {
			return err
		}
		record, err = publication.Snapshot(ctx)
		if err != nil {
			return err
		}
		defer clear(record.NativeKey)
	}
	if record.Binding.Namespace != "" && record.Publisher != nil {
		p := record.Publisher
		audience := record.Binding.ServerURL + "/v1/machine-publication-sessions/" + record.SessionID + "/cleanup"
		assertion, err := publisherproof.Sign(p.ClientId, p.KeyId, machineproof.PublicationCleanup(record.SessionID, record.Binding.InvocationID), audience, ed25519.PrivateKey(record.NativeKey), time.Now())
		if err != nil {
			return err
		}
		if err := authority.CleanupMachinePublication(ctx, record.SessionID, authorityv1.MachinePublicationCleanup{InvocationId: record.Binding.InvocationID, Assertion: assertion}); err != nil {
			return errors.Join(context.Cause(ctx), err)
		}
	}
	record.Phase, record.NativeKey = clientstate.ApplicationCleanupDone, nil
	return publication.Checkpoint(ctx, record)
}
