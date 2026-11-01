package state

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func publisherOwnsRun(ctx context.Context, q *controlstatedb.Queries, p PublisherIdentity, u controlstatedb.ControlPublicUrl) error {
	if p.Scope.TeamID != u.TeamID || u.LifecycleState != "enabled" {
		return ErrPublisherIdentity
	}
	if p.Scope.Kind == "saved_public_url" {
		if p.Scope.PublicURLID != u.ID || p.GuestID == "" && u.Ephemeral {
			return ErrPublisherIdentity
		}
		return validatePublisherScope(ctx, q, p.Scope, p.GuestID)
	}
	if p.Scope.Kind != "namespace" || p.GuestID != "" || !u.Ephemeral || u.ServiceProtocol != "http" || u.DomainID != p.Scope.DomainID || u.Namespace != p.Scope.Namespace {
		return ErrPublisherIdentity
	}
	a, err := q.GetPublisherAllocation(ctx, u.ID)
	if err != nil {
		return publisherLookupError(err, ErrPublisherIdentity)
	}
	if a.PublisherIdentityID != p.ID || a.PublisherGrantID != p.GrantID {
		return ErrPublisherIdentity
	}
	return validatePublisherScope(ctx, q, p.Scope, "")
}

func (d *Database) authorizePublisherRun(ctx context.Context, q *controlstatedb.Queries, u controlstatedb.ControlPublicUrl, r PublishRunRequest, now time.Time) ([32]byte, error) {
	p, _, err := d.livePublisher(ctx, q, r.PublisherIdentityID, r.PublisherGrantID, r.PublisherSourceIP, now)
	if err != nil {
		return [32]byte{}, err
	}
	if r.ActingIdentityID != p.CreatorID || r.GuestID != p.GuestID || p.GuestID != "" && r.PublisherSourceIP == "" {
		return [32]byte{}, ErrPublisherIdentity
	}
	if err := publisherOwnsRun(ctx, q, p, u); err != nil {
		return [32]byte{}, err
	}
	k, err := q.GetPublisherKey(ctx, controlstatedb.GetPublisherKeyParams{ID: r.PublisherKeyID, PublisherIdentityID: p.ID})
	if err != nil {
		return [32]byte{}, publisherLookupError(err, ErrPublisherIdentity)
	}
	secret, err := publisherproof.VerifyRun(k.PublicKey, r.PublisherRunProof, u.ID, r.IdempotencyKey)
	if err != nil {
		return [32]byte{}, ErrPublisherIdentity
	}
	// a retired key can recover only its exact persisted run attempt. the URL
	// and publisher locks serialize this decision with creation and rotation;
	// the outer retry path also checks the request digest and derived run token.
	if k.RetiredAt.Valid {
		run, err := q.GetPublishRunByIdempotency(ctx, controlstatedb.GetPublishRunByIdempotencyParams{PublicURLID: u.ID, IdempotencyKey: r.IdempotencyKey})
		if err != nil {
			return [32]byte{}, publisherLookupError(err, ErrPublisherIdentity)
		}
		if run.PublisherIdentityID.String != p.ID || run.PublisherGrantID.String != p.GrantID {
			return [32]byte{}, ErrPublisherIdentity
		}
	}
	domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: u.DomainID, TeamID: text(u.TeamID)})
	if err != nil {
		return [32]byte{}, err
	}
	plan := publisherCertificatePlan(p, u.CanonicalHostname, u.Namespace, domain.Kind == "custom" && u.PublicURLScope == "shared")
	if plan == nil || plan.CacheKey != r.CertificateCacheKey || plan.Scope != r.CertificateScope || !slices.Equal(plan.Identifiers, r.CertificateIdentifiers) || plan.ChallengeMethod != r.CertificateChallenge {
		return [32]byte{}, ErrPublisherIdentity
	}
	return secret, nil
}

func (d *Database) publisherRunLive(ctx context.Context, q *controlstatedb.Queries, u controlstatedb.ControlPublicUrl, run controlstatedb.ControlPublishRun, now time.Time) (bool, error) {
	if !run.PublisherIdentityID.Valid {
		return true, nil
	}
	p, _, err := d.livePublisher(ctx, q, run.PublisherIdentityID.String, run.PublisherGrantID.String, "", now)
	if errors.Is(err, ErrPublisherIdentity) || errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	err = publisherOwnsRun(ctx, q, p, u)
	if errors.Is(err, ErrPublisherIdentity) || errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func (d *Database) PublisherRunPlan(ctx context.Context, p PublisherIdentity, u PublicURL, _ bool) (authorization.CertificatePlan, error) {
	if p.Scope.Kind != "saved_public_url" && p.Scope.Kind != "namespace" || u.TeamID != p.Scope.TeamID || u.LifecycleState != PublicURLLifecycleEnabled || p.Scope.Kind == "saved_public_url" && u.ID != p.Scope.PublicURLID || p.Scope.Kind == "namespace" && (!u.Ephemeral || u.ServiceProtocol != PublicURLServiceHTTP) {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	domain, err := controlstatedb.New(d.pool).GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: u.DomainID, TeamID: text(u.TeamID)})
	if err != nil {
		return authorization.CertificatePlan{}, err
	}
	plan := publisherCertificatePlan(p, u.CanonicalHostname, u.Namespace, domain.Kind == "custom" && u.PublicURLScope == PublicURLScopeShared)
	if plan == nil || !certificateidentity.Covers(plan.Identifiers, u.CanonicalHostname) || p.Scope.Kind == "namespace" && plan.ChallengeMethod != certificateidentity.ChallengeDNS01 {
		return authorization.CertificatePlan{}, ErrPublisherIdentity
	}
	return *plan, nil
}

func publisherCertificatePlan(p PublisherIdentity, hostname, namespace string, apexAllowed bool) *authorization.CertificatePlan {
	// a saved-URL grant cannot give its publisher a key covering sibling URLs.
	if p.Scope.Kind == "saved_public_url" {
		return authorization.PublicURLCertificatePlan(hostname, hostname, false, false)
	}
	if p.Scope.Kind != "namespace" || p.Scope.Namespace != namespace {
		return nil
	}
	return authorization.PublicURLCertificatePlan(hostname, namespace, apexAllowed, true)
}
