package state

import (
	"context"
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// ServicePlacement selects a ready team domain and a source-bound local
// worktree. control captures the resulting identity once; defaults never rename it.
type ServicePlacement struct {
	DomainID      string `json:"domain_id,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	WorktreeKey   string `json:"worktree_key,omitempty"`
	WorktreeLabel string `json:"worktree_label,omitempty"`
	DNSAutomation bool   `json:"-"`
	SourceKey     string `json:"-"`
}

func (p ServicePlacement) Validate() error {
	if len(p.WorktreeKey) > 128 || strings.TrimSpace(p.WorktreeKey) != p.WorktreeKey || strings.ContainsAny(p.WorktreeKey, "\x00\r\n") || p.WorktreeLabel != "" && (p.WorktreeKey == "" || !validProjectDNSLabel(p.WorktreeLabel)) || strings.TrimSpace(p.DomainID) != p.DomainID || strings.ContainsAny(p.DomainID, "\x00\r\n") {
		return ErrProjectConfigurationInvalid
	}
	if p.Hostname != "" {
		canonical, err := naming.CanonicalizeHostname(p.Hostname)
		if err != nil || canonical != p.Hostname {
			return ErrProjectConfigurationInvalid
		}
	}
	return nil
}

func localPlacementKey(key string) string {
	digest := sha256.Sum256([]byte(key))
	return fmt.Sprintf("local/%x", digest[:])
}

func localManagedWorktreeLabel(key, label string) (string, error) {
	if label != "" {
		if !validProjectDNSLabel(label) {
			return "", ErrProjectConfigurationInvalid
		}
		return label, nil
	}
	if key == "" {
		return "", nil
	}
	digest := sha256.Sum256([]byte(key))
	return fmt.Sprintf("worktree-%x", digest[:6]), nil
}

func (d *Database) ensureLocalServiceEndpoint(ctx context.Context, tx pgx.Tx, service, actor, name string, placement ServicePlacement, public bool, now time.Time) error {
	row, err := controlstatedb.New(tx).LockService(ctx, service)
	if err != nil {
		return err
	}
	domainID := placement.DomainID
	if domainID == "" && row.DomainID.Valid {
		domainID = row.DomainID.String
	}
	if domainID == "" {
		if err = tx.QueryRow(ctx, `SELECT COALESCE(default_domain_id,'') FROM control.teams WHERE id=$1 AND deleted_at IS NULL`, row.TeamID).Scan(&domainID); err != nil {
			return err
		}
	}
	facts, err := serviceHostnameAuthority(ctx, tx, row.TeamID.String, actor, domainID, now)
	if err != nil {
		return err
	}
	owner := naming.MemberNamespace(facts.CanonicalDomain, facts.DomainKind == "managed", facts.ActorManagedLabel, facts.ActorMemberSlug)
	label, err := localManagedWorktreeLabel(placement.WorktreeKey, placement.WorktreeLabel)
	if err != nil {
		return err
	}
	namespace := owner
	if label != "" {
		namespace = label + "." + owner
	}
	hostname, err := naming.CanonicalizeHostname(name + "." + namespace)
	if err != nil {
		return ErrProjectConfigurationInvalid
	}
	if placement.Hostname != "" {
		hostname = placement.Hostname
		if err := d.authorizeLocalServiceHostname(ctx, tx, facts, row.TeamID.String, hostname); err != nil {
			return err
		}
	}
	sourceKey := placement.SourceKey
	if sourceKey == "" {
		sourceKey = "adhoc/" + placement.WorktreeKey + "/" + name
	}
	digest := sha256.Sum256([]byte(facts.ActorMembershipID + "\x00" + sourceKey))
	sourceKey = fmt.Sprintf("%x", digest[:])
	if row.CertificateHostname != "" {
		if placement.Hostname != "" && row.CertificateHostname != placement.Hostname ||
			placement.Hostname == "" && !strings.HasSuffix(row.CertificateHostname, "."+owner) ||
			row.DomainID.String != domainID || row.PlacementWorktreeKey != placement.WorktreeKey || row.PlacementWorktreeLabel != label {
			return ErrServiceConflict
		}
		if err = claimLocalServiceHostname(ctx, tx, row.CertificateHostname, sourceKey, facts.ActorMembershipID, domainID, now); err != nil {
			return err
		}
		return d.setLocalServiceExposure(ctx, tx, service, public, now)
	}
	if err = claimLocalServiceHostname(ctx, tx, hostname, sourceKey, facts.ActorMembershipID, domainID, now); err != nil {
		return err
	}
	port, err := allocateServicePort(ctx, tx, service, facts.IngressPoolID, public, now)
	if err != nil {
		return err
	}
	// local publishers receive exact-host plans, never authority over another
	// service or the member/worktree namespace as a whole.
	if err = reconcileServiceEndpoint(ctx, tx, serviceEndpoint{ServiceID: service, LocalSourceKey: sourceKey, DomainID: domainID, Hostname: hostname, Namespace: hostname, PoolID: facts.IngressPoolID, Public: public, Automation: placement.DNSAutomation}, now); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET certificate_hostname=$2,certificate_scope=$2,domain_id=$3,service_port=$4,ingress_pool_id=$5,placement_worktree_key=$6,placement_worktree_label=$7,public=$8 WHERE id=$1`, service, hostname, domainID, port, facts.IngressPoolID, placement.WorktreeKey, label, public)
	return projectConstraintError(err)
}

func (d *Database) authorizeLocalServiceHostname(ctx context.Context, tx pgx.Tx, facts serviceHostnameFacts, team, hostname string) error {
	actorNamespace, direct := naming.PublicURLNamespace(naming.NamespaceFacts{
		Domain: facts.CanonicalDomain, Managed: facts.DomainKind == "managed", Mode: d.managedURLMode,
		Personal: facts.TeamKind == "personal", TeamName: facts.TeamDisplayName,
		MemberSlug: facts.ActorMemberSlug, ManagedLabel: facts.ActorManagedLabel,
	})
	scope, membership := "shared", ""
	if !direct && hostname != actorNamespace && hostnameWithin(hostname, actorNamespace) {
		scope, membership = "member", facts.ActorMembershipID
	}
	if scope == "shared" && facts.TeamKind != "personal" {
		return ErrServiceAccess
	}
	labels, err := controlstatedb.New(tx).ListTeamNamespaceLabels(ctx, team)
	if err != nil {
		return err
	}
	return authorizeServiceHostname(facts, labels, team, membership, hostname, scope, d.managedURLMode)
}

func claimLocalServiceHostname(ctx context.Context, tx pgx.Tx, hostname, sourceKey, membership, domainID string, now time.Time) error {
	var conflict bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_namespace_claims WHERE ($1=namespace OR right($1,length(namespace)+1)='.'||namespace) AND (local_source_key<>$2 OR membership_id IS DISTINCT FROM $3))`, hostname, sourceKey, membership).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return ErrServiceConflict
	}
	var claimed string
	if err := tx.QueryRow(ctx, `INSERT INTO control.service_namespace_claims(namespace,local_source_key,membership_id,domain_id,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(namespace) DO UPDATE SET local_source_key=EXCLUDED.local_source_key WHERE control.service_namespace_claims.local_source_key=EXCLUDED.local_source_key AND control.service_namespace_claims.membership_id=EXCLUDED.membership_id AND control.service_namespace_claims.domain_id=EXCLUDED.domain_id AND control.service_namespace_claims.retired_at IS NULL RETURNING namespace`, hostname, sourceKey, membership, domainID, now).Scan(&claimed); err != nil {
		return publisherLookupError(err, ErrServiceConflict)
	}
	return nil
}

// configure keeps captured placement unless the declaration explicitly selects
// another hostname or domain. claims and DNS use the same owners as creation;
// endpoint changes never close runs or replace connector authority.
func (d *Database) configureStandaloneServiceEndpoint(ctx context.Context, tx pgx.Tx, row controlstatedb.ControlService, actor string, declaration ProjectServiceConfiguration, now time.Time) error {
	var endpoint serviceEndpoint
	err := tx.QueryRow(ctx, `SELECT service_id,local_source_key,domain_id,hostname,namespace,ingress_pool_id,public,dns_automation
	    FROM control.service_endpoints WHERE service_id=$1 AND hostname=$2 AND retired_at IS NULL AND deployment_id IS NULL`,
		row.ID, row.CertificateHostname).Scan(&endpoint.ServiceID, &endpoint.LocalSourceKey, &endpoint.DomainID, &endpoint.Hostname, &endpoint.Namespace, &endpoint.PoolID, &endpoint.Public, &endpoint.Automation)
	if err != nil {
		return err
	}
	if endpoint.LocalSourceKey == "" {
		return ErrServiceAccess
	}
	desired := endpoint
	if declaration.DomainID != "" {
		desired.DomainID = declaration.DomainID
	}
	facts, err := serviceHostnameAuthority(ctx, tx, row.TeamID.String, actor, desired.DomainID, now)
	if err != nil {
		return err
	}
	if declaration.Hostname != "" {
		desired.Hostname = declaration.Hostname
	} else if desired.DomainID != endpoint.DomainID {
		namespace := naming.MemberNamespace(facts.CanonicalDomain, facts.DomainKind == "managed", facts.ActorManagedLabel, facts.ActorMemberSlug)
		if row.PlacementWorktreeLabel != "" {
			namespace = row.PlacementWorktreeLabel + "." + namespace
		}
		desired.Hostname = row.Name + "." + namespace
	}
	desired.Namespace, desired.PoolID, desired.Public = desired.Hostname, facts.IngressPoolID, projectServicePublic(declaration)
	if desired == endpoint {
		return nil
	}
	if desired.Hostname != endpoint.Hostname || desired.DomainID != endpoint.DomainID {
		if err = d.authorizeLocalServiceHostname(ctx, tx, facts, row.TeamID.String, desired.Hostname); err != nil {
			return err
		}
		if err = claimLocalServiceHostname(ctx, tx, desired.Hostname, desired.LocalSourceKey, facts.ActorMembershipID, desired.DomainID, now); err != nil {
			return err
		}
	}
	port, err := allocateServicePort(ctx, tx, row.ID, desired.PoolID, desired.Public, now)
	if err != nil {
		return err
	}
	if err = reconcileServiceEndpoint(ctx, tx, desired, now); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET certificate_hostname=$2,certificate_scope=$2,domain_id=$3,service_port=$4,ingress_pool_id=$5,
	    endpoint_revision=endpoint_revision+CASE WHEN public<>$6 THEN 1 ELSE 0 END,public=$6 WHERE id=$1`,
		row.ID, desired.Hostname, desired.DomainID, port, desired.PoolID, desired.Public)
	return projectConstraintError(err)
}

// exposure updates keep the captured hostname and provenance. applying a project
// never reconstructs another worktree's name, domain defaults, or DNS ownership.
func (d *Database) setLocalServiceExposure(ctx context.Context, tx pgx.Tx, service string, public bool, now time.Time) error {
	row, err := controlstatedb.New(tx).LockService(ctx, service)
	if err != nil {
		return err
	}
	if row.Public == public {
		return nil
	}
	var endpoint serviceEndpoint
	var automated bool
	err = tx.QueryRow(ctx, `SELECT service_id,local_source_key,domain_id,hostname,namespace,ingress_pool_id,dns_automation
	    FROM control.service_endpoints WHERE service_id=$1 AND hostname=$2 AND retired_at IS NULL AND deployment_id IS NULL`,
		service, row.CertificateHostname).Scan(&endpoint.ServiceID, &endpoint.LocalSourceKey, &endpoint.DomainID, &endpoint.Hostname, &endpoint.Namespace, &endpoint.PoolID, &automated)
	if err != nil {
		return err
	}
	port, err := allocateServicePort(ctx, tx, service, endpoint.PoolID, public, now)
	if err != nil {
		return err
	}
	endpoint.Public, endpoint.Automation = public, automated
	if err = reconcileServiceEndpoint(ctx, tx, endpoint, now); err != nil {
		return err
	}
	return bindServicePort(ctx, tx, service, port, public)
}
