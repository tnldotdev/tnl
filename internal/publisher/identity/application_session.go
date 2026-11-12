package identity

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type ApplicationSessionAuthority interface {
	AssertionExchanger
	ExchangeMachinePublication(context.Context, authorityv1.MachinePublicationExchange) (authorityv1.MachinePublicationSession, error)
	RefreshMachinePublication(context.Context, string, authorityv1.MachinePublicationRefresh) (authorityv1.MachinePublicationSession, error)
	CleanupMachinePublication(context.Context, string, authorityv1.MachinePublicationCleanup) error
}

// ApplicationCheckpoint is the exact durable capability this owner consumes.
// client state implements it; identity does not own its filesystem or locks.
type ApplicationCheckpoint interface {
	Snapshot(context.Context) (clientstate.ApplicationPublicationRecord, error)
	Checkpoint(context.Context, clientstate.ApplicationPublicationRecord) error
}

// ErrApplicationSessionUncertain retains the original intent for a live owner
// after a reply is lost. it never authorizes serving beyond a confirmed fence.
var ErrApplicationSessionUncertain = errors.New("application publication reply is uncertain")

// ApplicationSession owns one native key and its exact source-bound grant. it
// neither selects installed identities nor owns publication workers/listeners.
// durable recovery of these facts belongs to client state, not a new exchange.
type ApplicationSession struct {
	mu                sync.Mutex
	allocation        sync.Mutex
	authority         ApplicationSessionAuthority
	native            *Native
	private           ed25519.PrivateKey
	server            string
	resource          string
	namespace         string
	invocation        string
	id                string
	scope             nativeScope
	expiresAt         time.Time
	identityExpiresAt time.Time
	cleaned           bool
	publication       ApplicationCheckpoint
	nonce             string
	fence             atomic.Pointer[applicationSessionFence]
	fenceMu           sync.Mutex
}

func (*ApplicationSession) String() string   { return "application publication session" }
func (*ApplicationSession) GoString() string { return "application publication session" }

// OpenApplicationSession uses a synced original key/nonce intent. a new process
// may resolve an uncertain reply, never replace an accepted publisher or scope.
func OpenApplicationSession(ctx context.Context, control PublicURLControl, authority ApplicationSessionAuthority, publication ApplicationCheckpoint, assertion string) (*ApplicationSession, error) {
	if err := context.Cause(ctx); err != nil {
		return nil, err
	}
	if control == nil || authority == nil || publication == nil || !ValidApplicationAssertion(assertion) {
		return nil, ErrScope
	}
	record, err := publication.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(record.NativeKey)
	if record.ConfirmationPending() && !time.Now().Before(record.ConfirmationDeadline) {
		return nil, ErrScope
	}
	if !applicationSourceMatches(record, assertion) {
		return nil, ErrScope
	}
	resource, namespace, invocation := record.Binding.ResourceID, record.Binding.Namespace, record.Binding.InvocationID
	server, err := naming.CanonicalControlURL(control.ControlURL())
	if err != nil || server != control.ControlURL() {
		return nil, ErrScope
	}
	if resource != "" && !opaqueid.Valid(resource, opaqueid.PublicURLPrefix) {
		return nil, ErrScope
	}
	if namespace != "" {
		canonical, err := naming.CanonicalizeHostname(namespace)
		if err != nil || canonical != namespace {
			return nil, ErrScope
		}
	}
	if record.Binding.ServerURL != server || !record.OwnerExpiresAt.After(time.Now()) || record.Phase == clientstate.ApplicationDenied || record.Phase == clientstate.ApplicationCleanupPending || record.Phase == clientstate.ApplicationCleanupDone {
		return nil, ErrScope
	}
	s := &ApplicationSession{authority: authority, private: append(ed25519.PrivateKey(nil), record.NativeKey...), server: server, resource: resource, namespace: namespace, invocation: invocation, publication: publication, nonce: record.Nonce}
	opened := false
	defer func() {
		if !opened {
			clear(s.private)
		}
	}()
	if record.Publisher != nil {
		s.scope, err = newNativeScope(*record.Publisher)
		if err != nil {
			return nil, invalidApplicationSession()
		}
		s.id, s.expiresAt, s.identityExpiresAt = record.SessionID, record.AccessExpiresAt, record.IdentityExpiresAt
		if record.ConfirmationPending() && record.ConfirmationDeadline.Before(s.identityExpiresAt) {
			s.identityExpiresAt = record.ConfirmationDeadline
		}
	}
	if record.ConfirmationPending() || record.Phase == clientstate.ApplicationExchangePending || record.Phase == clientstate.ApplicationRefreshPending {
		if err := s.recoverSession(ctx, record, assertion); err != nil {
			return nil, err
		}
	} else {
		if err := s.Refresh(ctx, assertion); err != nil {
			return nil, err
		}
	}
	s.native, err = NewNative(NativeControl{PublicURLControl: control}, s, s.scope.enrollment(), s.private, nil)
	if err != nil {
		return nil, invalidApplicationSession()
	}
	latest, err := publication.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	defer clear(latest.NativeKey)
	if latest.PublicURL != nil {
		if err := s.native.SelectPublicURL(*latest.PublicURL); err != nil {
			return nil, err
		}
	}
	confirmationDeadline := latest.IdentityExpiresAt
	if latest.OwnerExpiresAt.Before(confirmationDeadline) {
		confirmationDeadline = latest.OwnerExpiresAt
	}
	if err := s.advanceFence(ctx, latest.IdentityExpiresAt, confirmationDeadline); err != nil {
		return nil, err
	}
	opened = true
	return s, nil
}

// ValidApplicationAssertion checks only bounded private handoff syntax. control
// remains the sole verifier of source trust, identity and proof expiration.
func ValidApplicationAssertion(assertion string) bool {
	return len(assertion) > 0 && len(assertion) <= 32768 && utf8.ValidString(assertion) && strings.IndexFunc(assertion, func(r rune) bool { return r == 0 || r == '\ufeff' || unicode.IsSpace(r) }) < 0
}

func invalidApplicationSession() error {
	return failure.Wrap("validate application publication session", failure.ServerResponseInvalid, errors.New("authority returned inconsistent application publication facts"))
}

func (s *ApplicationSession) accept(response authorityv1.MachinePublicationSession, refresh bool, now time.Time) error {
	scope, err := newNativeScope(response.Publisher)
	if err != nil || !opaqueid.Valid(scope.teamID, opaqueid.TeamPrefix) || !opaqueid.Valid(response.Id, "mps_") ||
		response.TokenType != "Bearer" || !ValidApplicationAssertion(response.AccessToken) ||
		!response.ExpiresAt.After(now) || !response.IdentityExpiresAt.After(now) || response.ExpiresAt.After(response.IdentityExpiresAt) ||
		response.RenewAfter.IsZero() || !response.RenewAfter.Before(response.ExpiresAt) ||
		s.resource != "" && (scope.kind != authorityv1.SavedPublicUrl || scope.publicURLID != s.resource) ||
		s.namespace != "" && (scope.kind != authorityv1.Namespace || scope.namespace != s.namespace) {
		return invalidApplicationSession()
	}
	if refresh && (response.Id != s.id || scope != s.scope || response.ExpiresAt.Before(s.expiresAt) || response.IdentityExpiresAt.Before(s.identityExpiresAt) || !now.Before(s.identityExpiresAt)) {
		return invalidApplicationSession()
	}
	s.id, s.scope, s.expiresAt, s.identityExpiresAt = response.Id, scope, response.ExpiresAt, response.IdentityExpiresAt
	return nil
}

func (s *ApplicationSession) possession(operation, nonce, assertion string) string {
	public := base64.RawURLEncoding.EncodeToString(s.private.Public().(ed25519.PublicKey))
	message := machineproof.PublicationPossession(s.resource, s.namespace, operation, public, nonce, sha256.Sum256([]byte(assertion)))
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, message))
}

func (s *ApplicationSession) Publisher() *Native { return s.native }

func (s *ApplicationSession) Refresh(ctx context.Context, assertion string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned || !ValidApplicationAssertion(assertion) {
		return ErrScope
	}
	if fence := s.fence.Load(); fence != nil && fence.denied {
		return ErrScope
	}
	record, err := s.publication.Snapshot(ctx)
	if err != nil {
		return err
	}
	defer clear(record.NativeKey)
	if !applicationSourceMatches(record, assertion) {
		return ErrScope
	}
	if record.Phase == clientstate.ApplicationDenied || record.Phase == clientstate.ApplicationCleanupPending || record.Phase == clientstate.ApplicationCleanupDone {
		return ErrScope
	}
	if !record.OwnerExpiresAt.After(time.Now()) {
		return s.recordFailure(ctx, ErrScope)
	}
	if record.ConfirmationPending() || record.Phase == clientstate.ApplicationRefreshPending {
		if record.ConfirmationPending() && !time.Now().Before(record.ConfirmationDeadline) {
			return s.recordFailure(ctx, ErrScope)
		}
		return s.recoverSession(ctx, record, assertion)
	}
	if !time.Now().Before(s.identityExpiresAt) {
		return s.recordFailure(ctx, ErrScope)
	}
	record.ResumePhase, record.Phase = record.Phase, clientstate.ApplicationRefreshPending
	if err := s.publication.Checkpoint(ctx, record); err != nil {
		return err
	}
	record, err = s.publication.Snapshot(ctx)
	if err != nil {
		return err
	}
	defer clear(record.NativeKey)
	deadline := s.identityExpiresAt
	if record.OwnerExpiresAt.Before(deadline) {
		deadline = record.OwnerExpiresAt
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	if err := context.Cause(ctx); err != nil {
		return err
	}
	response, err := s.authority.RefreshMachinePublication(ctx, s.id, authorityv1.MachinePublicationRefresh{Assertion: assertion, Signature: s.possession("refresh", s.id, assertion)})
	if err != nil {
		return s.recordFailure(ctx, errors.Join(context.Cause(ctx), err))
	}
	if err := context.Cause(ctx); err != nil {
		return err
	}
	previousID, previousScope, previousAccess, previousIdentity := s.id, s.scope, s.expiresAt, s.identityExpiresAt
	if err := s.accept(response, true, time.Now()); err != nil {
		return err
	}
	if err := s.checkpointSession(ctx, record, response, record.ResumePhase); err != nil {
		s.id, s.scope, s.expiresAt, s.identityExpiresAt = previousID, previousScope, previousAccess, previousIdentity
		return errors.Join(ErrApplicationSessionUncertain, err)
	}
	if err := s.advanceFence(ctx, s.identityExpiresAt, deadline); err != nil {
		s.id, s.scope, s.expiresAt, s.identityExpiresAt = previousID, previousScope, previousAccess, previousIdentity
		return err
	}
	return nil
}

func applicationSourceMatches(record clientstate.ApplicationPublicationRecord, assertion string) bool {
	if record.Binding.SourceKind != "registered_key" {
		return record.Binding.SourceKind == "oidc"
	}
	key, err := publisherproof.KeyID(assertion)
	return err == nil && key == record.Binding.SourceKeyID
}

// ExchangePublisherAssertion retains NewNative's canonical token path but never
// allows a key, grant or late reply to escape the last confirmed source lease.
func (s *ApplicationSession) ExchangePublisherAssertion(ctx context.Context, publisher, grant, key string, private ed25519.PrivateKey) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned || publisher != s.scope.clientID || grant != s.scope.grantID || key != s.scope.keyID || subtle.ConstantTimeCompare(private, s.private) != 1 || !time.Now().Before(s.identityExpiresAt) {
		return "", ErrScope
	}
	if err := s.CheckServing(); err != nil {
		return "", err
	}
	ctx, cancel := context.WithDeadline(ctx, s.identityExpiresAt)
	defer cancel()
	token, err := s.authority.ExchangePublisherAssertion(ctx, publisher, grant, key, private)
	if err != nil {
		return "", s.recordFailure(ctx, errors.Join(context.Cause(ctx), err))
	}
	if err := context.Cause(ctx); err != nil {
		return "", err
	}
	if !time.Now().Before(s.identityExpiresAt) {
		return "", ErrScope
	}
	return token, nil
}

// CleanupAllocation proves only original-key ownership of this invocation. it
// needs no current source proof, publisher token or replacement grant.
func (s *ApplicationSession) CleanupAllocation(ctx context.Context) error {
	s.allocation.Lock()
	defer s.allocation.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cleaned {
		return nil
	}
	s.publishFence(s.identityExpiresAt, true)
	if err := CleanupApplicationPublication(ctx, s.publication, s.authority); err != nil {
		return err
	}
	s.cleaned = true
	return nil
}

func (s *ApplicationSession) Allocate(ctx context.Context, body controlv1.AllocateEphemeralPublicURLRequest) (controlv1.PublicURL, error) {
	// cleanup must join an uncertain allocation attempt before deleting its
	// tuple. do not hold mu here: NewNative's token exchange takes that lock.
	s.allocation.Lock()
	defer s.allocation.Unlock()
	if s.namespace == "" || body.InvocationId != s.invocation {
		return controlv1.PublicURL{}, ErrScope
	}
	record, err := s.publication.Snapshot(ctx)
	if err != nil {
		return controlv1.PublicURL{}, err
	}
	defer clear(record.NativeKey)
	if body.Target != record.Binding.Target {
		return controlv1.PublicURL{}, ErrScope
	}
	if record.Phase == clientstate.ApplicationURLAccepted && record.PublicURL != nil {
		return clonePublicURL(*record.PublicURL), nil
	}
	if record.Phase == clientstate.ApplicationSessionAccepted {
		record.Phase = clientstate.ApplicationAllocationPending
		if err := s.publication.Checkpoint(ctx, record); err != nil {
			return controlv1.PublicURL{}, err
		}
	} else if record.Phase != clientstate.ApplicationAllocationPending {
		return controlv1.PublicURL{}, ErrScope
	}
	u, err := s.native.Allocate(ctx, body)
	if err != nil {
		return u, s.recordFailure(ctx, err)
	}
	return u, s.acceptPublicURL(ctx, u)
}
