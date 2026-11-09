package state

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func newRandomPublicURLHostname(namespace string) (string, error) {
	canonical, err := naming.CanonicalizeHostname(namespace)
	if err != nil || canonical != namespace {
		return "", ErrPublicURLInvalid
	}
	label, err := naming.RandomHostnameLabel()
	if err != nil {
		return "", err
	}
	host := label + "." + namespace
	if len(host) > naming.MaxHostnameBytes {
		return "", ErrPublicURLInvalid
	}
	return host, nil
}

func (d *Database) validatePublisherAllocation(ctx context.Context, q *controlstatedb.Queries, r CreatePublicURLRequest, now time.Time) (PublisherIdentity, controlstatedb.ControlDomain, error) {
	p, _, err := d.livePublisher(ctx, q, r.PublisherIdentityID, r.PublisherGrantID, "", now)
	if err != nil {
		return p, controlstatedb.ControlDomain{}, err
	}
	if p.Operation != ApplicationAllocate || p.GuestID != "" || p.Scope.Kind != "namespace" || p.Scope.Namespace != r.PublisherNamespace || p.Scope.DomainID != r.DomainID || p.Scope.TeamID != r.TeamID || p.CreatorID != r.ActingIdentityID || r.ServiceProtocol != PublicURLServiceHTTP || r.Purpose != PublicURLPurposeApp || r.DNSState != PublicURLDNSPending {
		return p, controlstatedb.ControlDomain{}, ErrPublisherIdentity
	}
	domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: r.DomainID, TeamID: text(r.TeamID)})
	return p, domain, err
}

type PublisherPublicURLOptions struct {
	AccessMode         VisitorAccessMode
	RequirePostQuantum bool
}

func (d *Database) AllocatePublisherPublicURL(ctx context.Context, p PublisherIdentity, invocation, target string, prefixes []string, binding []byte, now time.Time, options ...PublisherPublicURLOptions) (PublicURL, error) {
	if p.Operation != ApplicationAllocate || p.Scope.Kind != "namespace" || p.GuestID != "" {
		return PublicURL{}, ErrPublisherIdentity
	}
	mode := VisitorAccessRestricted
	requirePostQuantum := false
	if len(options) != 0 {
		mode = options[0].AccessMode
		requirePostQuantum = options[0].RequirePostQuantum
	}
	if !mode.Valid() || len(options) > 1 {
		return PublicURL{}, ErrPublicURLInvalid
	}
	encoded, err := json.Marshal(struct {
		Identity, Grant, Invocation, Target string
		Mode                                VisitorAccessMode
		RequirePostQuantum                  bool
		Prefixes                            []string
		Binding                             []byte
	}{p.ID, p.GrantID, invocation, target, mode, requirePostQuantum, prefixes, binding})
	if err != nil {
		return PublicURL{}, err
	}
	team, err := d.pool.Query(ctx, `SELECT policy_revision FROM control.teams WHERE id=$1 AND deleted_at IS NULL`, p.Scope.TeamID)
	if err != nil {
		return PublicURL{}, err
	}
	var revision int64
	if !team.Next() {
		team.Close()
		return PublicURL{}, ErrPublisherIdentity
	}
	err = team.Scan(&revision)
	team.Close()
	if err != nil {
		return PublicURL{}, err
	}
	// hashing the ownership tuple keeps URL idempotency scoped to the exact
	// grant even when one identity has several namespace grants.
	idempotency := sha256.Sum256([]byte(p.ID + "\x00" + p.GrantID + "\x00" + invocation))
	return d.CreatePublicURL(ctx, CreatePublicURLRequest{RequirePostQuantum: requirePostQuantum, TeamID: p.Scope.TeamID, DomainID: p.Scope.DomainID, MembershipID: p.Scope.MembershipID, ActingIdentityID: p.CreatorID, IdempotencyKey: base32.StdEncoding.EncodeToString(idempotency[:]), RequestDigest: sha256.Sum256(encoded), Target: target, ServiceProtocol: PublicURLServiceHTTP, Purpose: PublicURLPurposeApp, PublicURLScope: p.Scope.PublicURLScope, AccessMode: mode, AllowedIPPrefixes: prefixes, PolicyRevision: uint64(revision), Ephemeral: true, DNSState: PublicURLDNSPending, PublisherIdentityID: p.ID, PublisherGrantID: p.GrantID, PublisherInvocationID: invocation, PublisherNamespace: p.Scope.Namespace}, now)
}

func (d *Database) validatePublisherDeletion(ctx context.Context, q *controlstatedb.Queries, r AuthorizedPublicURLDeleteRequest, u controlstatedb.ControlPublicUrl, now time.Time) error {
	p, _, err := d.livePublisher(ctx, q, r.PublisherIdentityID, r.PublisherGrantID, "", now)
	if err != nil {
		return err
	}
	if p.Operation != ApplicationAllocate || p.GuestID != "" || p.Scope.Kind != "namespace" || u.CreatedByIdentityID != p.CreatorID || r.ActingIdentityID != p.CreatorID {
		return ErrPublisherIdentity
	}
	return publisherOwnsRun(ctx, q, p, u)
}

func (d *Database) PublisherMayStartRun(ctx context.Context, p PublisherIdentity, id string) (bool, error) {
	if p.Operation != ApplicationPublish && p.Operation != ApplicationAllocate {
		return false, ErrPublisherIdentity
	}
	if p.Scope.Kind == "saved_public_url" {
		return p.Scope.PublicURLID == id, nil
	}
	a, err := controlstatedb.New(d.pool).GetPublisherAllocation(ctx, id)
	if err != nil {
		return false, err
	}
	return a.PublisherIdentityID == p.ID && a.PublisherGrantID == p.GrantID, nil
}
