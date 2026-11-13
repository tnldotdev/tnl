package state

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// apply owns the saved URL, not the person or publisher that first created it.
// the deployment's namespace is independent of any exact custom hostname.
func (d *Database) createDeploymentPublicURL(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, group, service string, s ProjectServiceConfiguration) (string, error) {
	q := controlstatedb.New(tx)
	if s.PublicURL == nil || s.PublicURL.Ephemeral || s.Protocol != "http" {
		return "", ErrProjectConfigurationInvalid
	}
	var namespace string
	if err := tx.QueryRow(ctx, `SELECT namespace FROM control.project_publisher_groups WHERE id=$1 AND team_id=$2 AND project_key=$3 AND deleted_at IS NULL`, group, r.TeamID, r.ProjectKey).Scan(&namespace); err != nil {
		return "", err
	}
	p := s.PublicURL
	domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: p.DomainID, TeamID: text(r.TeamID)})
	if err != nil {
		return "", publisherLookupError(err, ErrProjectConfigurationInvalid)
	}
	hostname := p.Hostname
	if hostname == "" {
		hostname = s.Name + "." + namespace
		if !strings.HasSuffix(namespace, "."+domain.CanonicalDomain) {
			return "", ErrProjectConfigurationInvalid
		}
	} else {
		// exact hostnames still pass normal shared-URL ownership checks. apply
		// cannot take another member's or deployment's namespace by naming it.
		creation, err := q.GetPublicURLCreationContext(ctx, controlstatedb.GetPublicURLCreationContextParams{IdentityID: r.ActorID, DomainID: p.DomainID, TeamID: r.TeamID})
		if err != nil {
			return "", err
		}
		labels, err := q.ListTeamNamespaceLabels(ctx, r.TeamID)
		if err != nil {
			return "", err
		}
		if err := authorizeRouteCreation(CreatePublicURLRequest{TeamID: r.TeamID, DomainID: p.DomainID, ActingIdentityID: r.ActorID, CanonicalHostname: hostname, PublicURLScope: PublicURLScopeShared, ManagedURLMode: d.managedURLMode}, creation, labels); err != nil {
			return "", err
		}
	}
	if canonical, err := naming.CanonicalizeHostname(hostname); err != nil || canonical != hostname {
		return "", ErrProjectConfigurationInvalid
	}
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims WHERE (retired_at IS NULL OR NOT control.service_namespace_reusable(namespace,$3)) AND group_id IS DISTINCT FROM $2::text AND ($1=namespace OR right($1,length(namespace)+1)='.'||namespace))
		OR EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=$1 AND (retired_at IS NULL OR dns_state<>'removed'))`, hostname, group, r.Now).Scan(&conflict); err != nil {
		return "", err
	}
	if conflict {
		return "", ErrPublicURLConflict
	}
	allowed, err := q.LockPublicURLCreationControl(ctx)
	if err != nil {
		return "", err
	}
	if !allowed {
		return "", ErrPublicURLCreationGated
	}
	var ingress string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT ingress_pool_id,policy_revision FROM control.teams WHERE id=$1`, r.TeamID).Scan(&ingress, &revision); err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(group + "/" + service + "/" + hostname + "/" + strconv.FormatInt(r.ExpectedRevision+1, 10)))
	key := "deployment-url/" + hex.EncodeToString(digest[:])
	target := s.Target
	if target == "app" {
		target = ""
	}
	request := CreatePublicURLRequest{TeamID: r.TeamID, DomainID: p.DomainID, ActingIdentityID: r.ActorID, IdempotencyKey: key, RequestDigest: digest, CanonicalHostname: hostname, Target: target, PublisherPool: true, ServiceProtocol: PublicURLServiceHTTP, PublicURLScope: PublicURLScopeShared, Purpose: PublicURLPurposeApp, AccessMode: VisitorAccessMode(p.Access.Mode), DNSState: PublicURLDNSUnmanaged, AllowedIPPrefixes: p.Access.IP}
	if p.RequirePostQuantum != nil {
		request.RequirePostQuantum = *p.RequirePostQuantum
	}
	if r.DNSAutomation {
		request.DNSState, request.DNSAuthorityReference = PublicURLDNSPending, domain.DnsAuthorityReference.String
	}
	prefixes, err := validateCreatePublicURLRequest(request)
	if err != nil {
		return "", err
	}
	url, err := d.insertPublicURL(ctx, q, request, namespace, ingress, revision, prefixes, r.Now)
	if err != nil {
		return "", projectConstraintError(err)
	}
	if err := q.InsertPublicURLCreateAuditEvent(ctx, controlstatedb.InsertPublicURLCreateAuditEventParams{ActorIdentityID: text(r.ActorID), RequestID: key, PublicURLID: url.ID, OccurredAt: timestamptz(r.Now)}); err != nil {
		return "", err
	}
	return url.ID, nil
}

func updateDeploymentPublicURLTarget(ctx context.Context, tx pgx.Tx, id string, s ProjectServiceConfiguration, now time.Time) error {
	target := s.Target
	if target == "app" {
		target = ""
	}
	_, err := tx.Exec(ctx, `UPDATE control.public_urls SET target=$2,updated_at=$3,mutation_revision=mutation_revision+1 WHERE id=$1 AND target IS DISTINCT FROM $2`, id, target, now)
	return err
}
