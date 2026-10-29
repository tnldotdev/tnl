package state

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

const (
	publicURLPageSize                     = 100
	ephemeralPublicURLGracePeriod         = 2 * time.Minute
	maximumExpiredEphemeralPublicURLBatch = 100
)

var (
	ErrPublicURLAccess        = errors.New("controlstate: public URL access denied")
	ErrPublicURLConflict      = errors.New("controlstate: public URL hostname is already in use")
	ErrPublicURLCreationGated = errors.New("controlstate: public URL creation is disabled")
	ErrPublicURLIdempotency   = errors.New("controlstate: public URL idempotency conflict")
	ErrPublicURLInvalid       = errors.New("controlstate: public URL request is invalid")
	ErrPublishRunOpen         = errors.New("controlstate: public URL has an open publish run")
	ErrPublicURLMutationStale = errors.New("controlstate: authorized public URL state changed")
)

type PublicURL struct {
	ID                            string
	TeamID                        string
	DomainID                      string
	MembershipID                  string
	CanonicalHostname             string
	Namespace                     string
	Target                        string
	ServiceProtocol               PublicURLServiceProtocol
	PublisherPool                 bool
	PublicURLScope                PublicURLScope
	Purpose                       PublicURLPurpose
	AccessMode                    VisitorAccessMode
	PolicyRevision                int64
	LifecycleState                PublicURLLifecycleState
	DNSAuthorityReference         string
	DNSState                      PublicURLDNSState
	AllowedIPPrefixes             []netip.Prefix
	NextPublishRunNumber          int64
	MutationRevision              uint64
	AuthorizationPublishRunNumber uint64
	Ephemeral                     bool
	ExpiresAt                     *time.Time
	OpenPublishRunID              string
	CreatedAt                     time.Time
	UpdatedAt                     time.Time
}

type CreatePublicURLRequest struct {
	GuestID               string
	TeamID                string
	DomainID              string
	MembershipID          string
	ActingIdentityID      string
	IdempotencyKey        string
	RequestDigest         [32]byte
	CanonicalHostname     string
	Target                string
	PublisherPool         bool
	ServiceProtocol       PublicURLServiceProtocol
	PublicURLScope        PublicURLScope
	Purpose               PublicURLPurpose
	AccessMode            VisitorAccessMode
	ManagedURLMode        naming.ManagedURLMode
	AllowedIPPrefixes     []string
	DNSState              PublicURLDNSState
	DNSAuthorityReference string
	PolicyRevision        uint64
	Ephemeral             bool
	PublisherIdentityID   string
	PublisherGrantID      string
	PublisherInvocationID string
	PublisherNamespace    string
}

type AuthorizedPublicURLUpdateRequest struct {
	PublicURLID              string
	TeamID                   string
	ActingIdentityID         string
	Target                   string
	AllowedIPPrefixes        []string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
}

type AuthorizedPublicURLDeleteRequest struct {
	PublicURLID              string
	TeamID                   string
	ActingIdentityID         string
	GuestID                  string
	PolicyRevision           uint64
	ExpectedMutationRevision uint64
	PublisherIdentityID      string
	PublisherGrantID         string
}

type PublicURLPage struct {
	PublicURLs []PublicURL
	NextCursor string
}

func (d *Database) CreatePublicURL(ctx context.Context, request CreatePublicURLRequest, now time.Time) (result PublicURL, retErr error) {
	if request.PublisherPool && (request.GuestID != "" || request.Ephemeral || request.PublisherIdentityID != "") {
		return result, ErrPublicURLAccess
	}
	if request.ServiceProtocol == "" {
		request.ServiceProtocol = PublicURLServiceHTTP
	}
	if request.AccessMode == "" {
		request.AccessMode = VisitorAccessRestricted
		if request.Purpose == PublicURLPurposeOAuth || request.Purpose == PublicURLPurposeWebhooks {
			request.AccessMode = VisitorAccessAnonymous
		}
	}
	if !request.AccessMode.Valid() || request.GuestID != "" && request.AccessMode != VisitorAccessRestricted ||
		(request.Purpose == PublicURLPurposeOAuth || request.Purpose == PublicURLPurposeWebhooks) && request.AccessMode != VisitorAccessAnonymous {
		return PublicURL{}, ErrPublicURLInvalid
	}
	prefixes, err := validateCreatePublicURLRequest(request)
	if err != nil {
		return PublicURL{}, err
	}
	if err := d.requireOpen(); err != nil {
		return PublicURL{}, err
	}
	tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: begin transaction: %w", err)
	}
	defer rollback(ctx, tx, "create route", &retErr)()
	queries := controlstatedb.New(tx)
	if request.GuestID == "" {
		if _, err := queries.LockLocalTeamForMutation(ctx, request.TeamID); errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		} else if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: lock team: %w", err)
		}
	}
	if request.PublisherIdentityID == "" {
		if _, err := queries.LockPublicURLCreator(ctx, request.ActingIdentityID); errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		} else if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: lock creator: %w", err)
		}
	}
	if request.PublisherIdentityID != "" {
		publisher, domain, err := d.validatePublisherAllocation(ctx, queries, request, now)
		if err != nil {
			return PublicURL{}, err
		}
		request.DNSAuthorityReference = domain.DnsAuthorityReference.String
		request.PublicURLScope, request.MembershipID = publisher.Scope.PublicURLScope, publisher.Scope.MembershipID
	}
	policyRevision := int64(0)
	namespace := ""
	ingressPoolID := ""
	if request.GuestID != "" {
		policyRevision = positive(request.PolicyRevision)
	}

	existing, err := queries.GetPublicURLByCreatorIdempotency(ctx, controlstatedb.GetPublicURLByCreatorIdempotencyParams{
		IdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
	})
	if err == nil {
		if request.PublisherIdentityID != "" {
			allocation, lookupErr := queries.GetPublisherAllocation(ctx, existing.ID)
			if lookupErr != nil || allocation.PublisherIdentityID != request.PublisherIdentityID || allocation.PublisherGrantID != request.PublisherGrantID ||
				allocation.InvocationID != request.PublisherInvocationID {
				return PublicURL{}, ErrPublicURLAccess
			}
		}
		if PublicURLLifecycleState(existing.LifecycleState) == PublicURLLifecycleDeleted {
			return PublicURL{}, ErrPublicURLIdempotency
		}
		if existing.Purpose != string(request.Purpose) || existing.ServiceProtocol != string(request.ServiceProtocol) || existing.PublisherPool != request.PublisherPool {
			return PublicURL{}, ErrPublicURLIdempotency
		}
		storedDigest, _, digestErr := d.openSecret(existing.RequestDigestStorageKeyID.String,
			publicURLRequestDigestContext(existing.ID), existing.RequestDigestCiphertext)
		if digestErr != nil {
			return PublicURL{}, fmt.Errorf("controlstate: read private idempotency digest: %w", digestErr)
		}
		if subtle.ConstantTimeCompare(storedDigest, request.RequestDigest[:]) != 1 {
			return PublicURL{}, ErrPublicURLIdempotency
		}
		if err := tx.Commit(ctx); err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: commit retry: %w", err)
		}
		result := publicURLFromIdempotencyRow(existing)
		result.AllowedIPPrefixes, err = d.openIPPolicy(existing.ID, existing.AllowedIpPolicyStorageKeyID.String, existing.AllowedIpPolicyCiphertext)
		if err != nil {
			return PublicURL{}, err
		}
		return result, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: read idempotent public_url: %w", err)
	}
	if request.PublisherIdentityID != "" {
		request.CanonicalHostname, err = newEphemeralHostname(request.PublisherNamespace)
		if err != nil {
			return PublicURL{}, err
		}
	}
	if request.GuestID != "" {
		guest, err := queries.LockGuestTrialByID(ctx, request.GuestID)
		if errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		}
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: lock guest trial: %w", err)
		}
		if guest.TeamID != request.TeamID || guest.MembershipID != request.MembershipID {
			return PublicURL{}, ErrPublicURLAccess
		}
		// guest team IDs are trial-owned, not rows in control.teams.
		ingressPoolID = PrimaryIngressPoolID
		if !guest.ExpiresAt.Time.After(now) || guest.UsedReadyNs >= int64(GuestReadyAllowance) {
			return PublicURL{}, ErrGuestTrialSpent
		}
		if guest.LastDemoNumber < 1 || !strings.HasPrefix(request.CanonicalHostname, fmt.Sprintf("demo-%d.%s.", guest.LastDemoNumber, guest.NamespaceLabel)) ||
			request.DomainID != guest.DomainID ||
			request.DNSState != PublicURLDNSUnmanaged && request.DNSAuthorityReference != guest.DnsAuthorityReference {
			return PublicURL{}, ErrPublicURLAccess
		}
		managed, err := queries.FindManagedDomain(ctx)
		if err != nil || managed.ID != guest.DomainID {
			return PublicURL{}, ErrPublicURLAccess
		}
		namespace = guest.NamespaceLabel + "." + managed.CanonicalDomain
		count, err := queries.CountGuestCurrentPublicURLs(ctx, request.GuestID)
		if err != nil {
			return PublicURL{}, err
		}
		if count != 0 || guest.ServingUntil.Valid && guest.ServingUntil.Time.After(now) {
			return PublicURL{}, ErrPublishRunOpen
		}
	}

	enabled, err := queries.LockPublicURLCreationControl(ctx)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: read maintenance control: %w", err)
	}
	if !enabled {
		return PublicURL{}, ErrPublicURLCreationGated
	}
	if request.PublisherIdentityID != "" {
		namespace = request.PublisherNamespace
		policyRevision = positive(request.PolicyRevision)
		_, err := queries.LockLocalTeamForSession(ctx, request.TeamID)
		if err != nil {
			return PublicURL{}, err
		}
		if err := tx.QueryRow(ctx, `SELECT ingress_pool_id, policy_revision FROM control.teams WHERE id=$1`, request.TeamID).Scan(&ingressPoolID, &policyRevision); err != nil {
			return PublicURL{}, err
		}
		domain, err := queries.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: request.DomainID, TeamID: text(request.TeamID)})
		if err != nil {
			return PublicURL{}, err
		}
		if domain.Kind == "managed" && namespace == domain.CanonicalDomain {
			return PublicURL{}, ErrPublicURLAccess
		}
	} else if request.GuestID == "" {
		creation, err := queries.GetPublicURLCreationContext(ctx, controlstatedb.GetPublicURLCreationContextParams{
			IdentityID: request.ActingIdentityID, DomainID: request.DomainID, TeamID: request.TeamID,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return PublicURL{}, ErrPublicURLAccess
		}
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: read authority context: %w", err)
		}
		labels, err := queries.ListTeamNamespaceLabels(ctx, request.TeamID)
		if err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create public_url: read namespaces: %w", err)
		}
		if err := authorizeRouteCreation(request, creation, labels); err != nil {
			return PublicURL{}, err
		}
		ingressPoolID = creation.IngressPoolID
		if request.PublicURLScope == PublicURLScopeShared {
			namespace = naming.SharedPublicURLNamespace(creation.CanonicalDomain, creation.DomainKind == "managed", request.ManagedURLMode, creation.TeamDisplayName, creation.TeamManagedLabel)
		} else {
			namespace, _ = naming.PublicURLNamespace(naming.NamespaceFacts{
				Domain: creation.CanonicalDomain, Managed: creation.DomainKind == "managed",
				Mode: request.ManagedURLMode, Personal: creation.TeamKind == "personal",
				TeamName: creation.TeamDisplayName, MemberSlug: creation.ActorMemberSlug,
				ManagedLabel: creation.ActorManagedLabel,
			})
		}
		if creation.DomainKind == "custom" && request.PublicURLScope == PublicURLScopeShared && request.CanonicalHostname != creation.CanonicalDomain {
			relative := strings.TrimSuffix(request.CanonicalHostname, "."+creation.CanonicalDomain)
			label := relative[strings.LastIndex(relative, ".")+1:]
			if reserved, err := queries.TeamMemberSlugReserved(ctx, controlstatedb.TeamMemberSlugReservedParams{
				TeamID: request.TeamID, Label: label,
			}); err != nil {
				return PublicURL{}, fmt.Errorf("controlstate: check reserved member slug: %w", err)
			} else if reserved {
				return PublicURL{}, ErrPublicURLConflict
			}
		}
		policyRevision = creation.PolicyRevision
	}

	publicURLID, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: generate route ID: %w", err)
	}
	policyCiphertext, policyHashes, policyKeyID, err := d.storeIPPolicy(publicURLID, prefixes, request.GuestID != "")
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: protect IP policy: %w", err)
	}
	digestCiphertext, err := d.sealSecret(publicURLRequestDigestContext(publicURLID), request.RequestDigest[:])
	if err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: protect request digest: %w", err)
	}
	policyStorageKeyID := ""
	if len(policyCiphertext) != 0 {
		policyStorageKeyID = d.storageKey.CurrentID()
	}
	membershipID := pgtype.Text{}
	if request.MembershipID != "" {
		membershipID = text(request.MembershipID)
	}
	managed, err := queries.ServiceNamespaceOwnsHostname(ctx, request.CanonicalHostname)
	if err != nil {
		return result, err
	}
	if managed {
		return result, ErrPublicURLConflict
	}
	row, err := queries.InsertPublicURL(ctx, controlstatedb.InsertPublicURLParams{
		ID: publicURLID, TeamID: request.TeamID, DomainID: request.DomainID, MembershipID: membershipID,
		CreatedByIdentityID: request.ActingIdentityID, IdempotencyKey: request.IdempotencyKey,
		RequestDigestCiphertext:   digestCiphertext,
		RequestDigestStorageKeyID: text(d.storageKey.CurrentID()),
		CanonicalHostname:         request.CanonicalHostname, Namespace: namespace, Target: request.Target,
		PublicURLScope: string(request.PublicURLScope), Purpose: string(request.Purpose), IngressPoolID: ingressPoolID,
		ServiceProtocol: string(request.ServiceProtocol),
		PublisherPool:   request.PublisherPool,
		PolicyRevision:  policyRevision, AccessMode: string(request.AccessMode), IpPolicy: string(routeIPPolicy(prefixes)),
		AllowedIpPolicyCiphertext:   policyCiphertext,
		AllowedIpPolicyStorageKeyID: nullableText(policyStorageKeyID),
		AllowedIpHashes:             policyHashes, AllowedIpHashKeyID: nullableText(policyKeyID),
		DnsAuthorityReference: nullableText(request.DNSAuthorityReference),
		DnsState:              string(request.DNSState), Ephemeral: request.Ephemeral,
		ExpiresAt: ephemeralRouteExpiry(request.Ephemeral, now), CreatedAt: timestamptz(now),
	})
	if err != nil {
		var postgresError *pgconn.PgError
		if errors.As(err, &postgresError) && postgresError.Code == "23505" {
			switch postgresError.ConstraintName {
			case "public_urls_current_hostname":
				return PublicURL{}, ErrPublicURLConflict
			case "public_urls_creator_idempotency":
				return PublicURL{}, ErrPublicURLIdempotency
			}
		}
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: insert public_url: %w", err)
	}
	if request.PublisherIdentityID != "" {
		if err := queries.InsertPublisherAllocation(ctx, controlstatedb.InsertPublisherAllocationParams{PublicURLID: publicURLID, PublisherIdentityID: request.PublisherIdentityID, PublisherGrantID: request.PublisherGrantID, InvocationID: request.PublisherInvocationID}); err != nil {
			return PublicURL{}, err
		}
	}
	if request.GuestID != "" {
		if err := queries.InsertGuestPublicURL(ctx, controlstatedb.InsertGuestPublicURLParams{
			PublicURLID: publicURLID, GuestID: request.GuestID, CreatedAt: timestamptz(now),
		}); err != nil {
			return PublicURL{}, fmt.Errorf("controlstate: create guest public_url: %w", err)
		}
	}
	if err := queries.InsertPublicURLCreateAuditEvent(ctx, controlstatedb.InsertPublicURLCreateAuditEventParams{
		ActorIdentityID: text(request.ActingIdentityID), RequestID: request.IdempotencyKey,
		PublicURLID: publicURLID, OccurredAt: timestamptz(now),
	}); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: insert audit event: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return PublicURL{}, fmt.Errorf("controlstate: create public_url: commit: %w", err)
	}
	d.activity.metrics.Load().ObservePublicURLCreated(string(request.Purpose))
	result = publicURLFromModel(row, "")
	if request.GuestID == "" {
		result.AllowedIPPrefixes = append([]netip.Prefix(nil), prefixes...)
	} else {
		result.AllowedIPPrefixes = nil
	}
	return result, nil
}
