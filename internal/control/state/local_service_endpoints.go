package state

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

// ServicePlacement selects a ready team domain and a source-bound local
// worktree. control captures the resulting identity once; defaults never rename it.
type ServicePlacement struct {
	DomainID         string `json:"domain_id,omitempty"`
	Hostname         string `json:"hostname,omitempty"`
	WorktreeKey      string `json:"worktree_key,omitempty"`
	WorktreeLabel    string `json:"worktree_label,omitempty"`
	PreviewPublisher string `json:"preview_publisher_id,omitempty"`
	UseSavedAddress  bool   `json:"use_saved_address,omitempty"`
	DNSAutomation    bool   `json:"-"`
	SourceKey        string `json:"-"`
	RunAliasParent   string `json:"-"`
	CertificateScope string `json:"-"`
	Reserve          bool   `json:"-"`
}

func (p ServicePlacement) Validate() error {
	if p.UseSavedAddress && (!p.Reserve || p.PreviewPublisher != "" || p.Hostname == "" ||
		p.WorktreeKey != "" || p.WorktreeLabel != "") {
		return ErrProjectConfigurationInvalid
	}
	if p.PreviewPublisher != "" && (!opaqueid.Valid(p.PreviewPublisher, opaqueid.PublisherIdentityPrefix) ||
		p.Hostname != "" || p.RunAliasParent != "" || !p.DNSAutomation) {
		return ErrProjectConfigurationInvalid
	}
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
	if domainID == "" && placement.PreviewPublisher != "" {
		domain, err := controlstatedb.New(tx).FindManagedDomain(ctx)
		if err != nil {
			return err
		}
		domainID = domain.ID
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
	owner := facts.localNamespace(d.managedURLMode)
	label, err := localManagedWorktreeLabel(placement.WorktreeKey, placement.WorktreeLabel)
	if err != nil {
		return err
	}
	namespace := owner
	if label != "" && d.managedURLMode != naming.ManagedURLModeGenerated {
		namespace = label + "." + owner
	}
	hostLabel := name
	if label != "" && d.managedURLMode == naming.ManagedURLModeGenerated {
		hostLabel = naming.ProjectDNSLabel(name, label)
	}
	hostname, err := naming.CanonicalizeHostname(hostLabel + "." + namespace)
	if err != nil {
		return ErrProjectConfigurationInvalid
	}
	if placement.Hostname != "" {
		hostname = placement.Hostname
	}
	var previewGrant, previewParent string
	if placement.PreviewPublisher != "" {
		if d.managedURLMode != naming.ManagedURLModeGenerated || facts.DomainKind != "managed" || row.Protocol != "http" || !public {
			return ErrProjectConfigurationInvalid
		}
		if row.CertificateHostname == "" {
			previewGrant, previewParent, err = previewPublisherGrant(ctx, tx, placement.PreviewPublisher, row.TeamID.String, facts.ActorMembershipID, domainID, facts.CanonicalDomain, now)
			if err != nil {
				return err
			}
			hostname, err = naming.RandomHostname(naming.ServiceHostnameKind, previewParent)
			if err != nil {
				return err
			}
		} else if _, ok := naming.PreviewHostname(row.CertificateHostname, facts.CanonicalDomain); !ok {
			return ErrServiceConflict
		}
	}
	intent := placement.SourceKey
	standalone := intent == ""
	if standalone {
		intent = "adhoc/" + placement.WorktreeKey + "/" + name
	}
	var sourceOwner serviceSourceOwner
	if row.CertificateHostname != "" {
		sourceOwner, err = storedServiceSourceOwner(ctx, tx, row, false)
		if err != nil {
			return err
		}
		if placement.Hostname != "" && row.CertificateHostname != placement.Hostname ||
			row.DomainID.String != domainID || row.PlacementWorktreeKey != placement.WorktreeKey ||
			standalone && row.PlacementWorktreeLabel != label ||
			sourceOwner.local == standalone || sourceOwner.key != sourceOwner.sourceKey(intent) {
			return ErrServiceConflict
		}
		if err = d.authorizeOwnedServiceHostname(ctx, tx, facts, sourceOwner, row.TeamID.String, domainID, row.CertificateHostname, now); err != nil {
			return err
		}
		if err = claimServiceSourceHostname(ctx, tx, row.CertificateHostname, domainID, sourceOwner, now); err != nil {
			return err
		}
		if err := d.setLocalServiceExposure(ctx, tx, service, public, now); err != nil {
			return err
		}
		return d.configureServiceRunAliasParent(ctx, tx, service, actor, placement.RunAliasParent, now)
	}
	sourceOwner, err = d.newServiceSourceOwner(ctx, tx, facts, row.TeamID.String, hostname, intent, standalone, placement.Hostname != "")
	if err != nil {
		return err
	}
	if err = recordServiceSourceOwner(ctx, tx, service, row.TeamID.String, sourceOwner); err != nil {
		return err
	}
	if err = claimServiceSourceHostname(ctx, tx, hostname, domainID, sourceOwner, now); err != nil {
		if !errors.Is(err, ErrServiceConflict) || placement.Hostname != "" || previewGrant != "" || standalone || d.managedURLMode != naming.ManagedURLModeGenerated {
			return err
		}
		hostname = naming.ProjectDNSLabel(hostLabel, sourceOwner.key[:10]) + "." + namespace
		if err = claimServiceSourceHostname(ctx, tx, hostname, domainID, sourceOwner, now); err != nil {
			return err
		}
	}
	port, err := allocateServicePort(ctx, tx, service, facts.IngressPoolID, public, now)
	if err != nil {
		return err
	}
	// the endpoint is exact. a preview publisher gets wildcard scope only at
	// run preparation, after control checks its dedicated parent grant.
	if err = reconcileServiceEndpoint(ctx, tx, serviceEndpoint{ServiceID: service, LocalSourceKey: sourceOwner.key, DomainID: domainID, Hostname: hostname, Namespace: hostname, PoolID: facts.IngressPoolID, Public: public, Automation: placement.DNSAutomation}, now); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.services SET certificate_hostname=$2,certificate_scope=$2,domain_id=$3,service_port=$4,ingress_pool_id=$5,placement_worktree_key=$6,placement_worktree_label=$7,public=$8 WHERE id=$1`, service, hostname, domainID, port, facts.IngressPoolID, placement.WorktreeKey, label, public)
	if err != nil {
		return projectConstraintError(err)
	}
	if previewGrant != "" {
		if _, err = tx.Exec(ctx, `INSERT INTO control.opaque_service_hosts(service_id,grant_id,hostname,parent)
		    VALUES($1,$2,$3,$4)`, service, previewGrant, hostname, previewParent); err != nil {
			return err
		}
	}
	return d.configureServiceRunAliasParent(ctx, tx, service, actor, placement.RunAliasParent, now)
}

func previewPublisherGrant(ctx context.Context, tx pgx.Tx, publisher, team, membership, domain, suffix string, now time.Time) (grant, parent string, err error) {
	err = tx.QueryRow(ctx, `SELECT g.id,g.namespace FROM control.publisher_grants g
	    JOIN control.publisher_identities p ON p.id=g.publisher_identity_id
	    WHERE p.id=$1 AND p.team_id=$2 AND p.owner_membership_id=$3 AND g.membership_id=$3
	      AND g.domain_id=$4 AND g.kind='namespace' AND g.revoked_at IS NULL AND control.active_publisher(p.id,$5)
	      AND (g.expires_at IS NULL OR g.expires_at>$5)
	      AND g.namespace ~ '^[a-z2-7]{26}\.preview\.'`, publisher, team, membership, domain, now).Scan(&grant, &parent)
	if err != nil {
		return "", "", publisherLookupError(err, ErrServiceAccess)
	}
	if !naming.PreviewParent(parent, suffix) {
		return "", "", ErrServiceAccess
	}
	return grant, parent, nil
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
	owner, err := storedServiceSourceOwner(ctx, tx, row, false)
	if err != nil {
		return err
	}
	if owner.local {
		return ErrProjectManaged
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
		namespace := facts.localNamespace(d.managedURLMode)
		if row.PlacementWorktreeLabel != "" {
			namespace = row.PlacementWorktreeLabel + "." + namespace
		}
		desired.Hostname = row.Name + "." + namespace
	}
	desired.Namespace, desired.PoolID, desired.Public = desired.Hostname, facts.IngressPoolID, projectServicePublic(declaration)
	if desired == endpoint {
		return d.configureServiceRunAliasParent(ctx, tx, row.ID, actor, declaration.RunAliasParent, now)
	}
	if desired.Hostname != endpoint.Hostname || desired.DomainID != endpoint.DomainID {
		if err = d.authorizeOwnedServiceHostname(ctx, tx, facts, owner, row.TeamID.String, desired.DomainID, desired.Hostname, now); err != nil {
			return err
		}
		if err = claimServiceSourceHostname(ctx, tx, desired.Hostname, desired.DomainID, owner, now); err != nil {
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
	if err != nil {
		return projectConstraintError(err)
	}
	return d.configureServiceRunAliasParent(ctx, tx, row.ID, actor, declaration.RunAliasParent, now)
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
