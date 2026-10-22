package controlstate

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

// PrivateServicePlacement selects a ready team domain and a source-bound local
// worktree. control captures the resulting identity once; defaults never rename it.
type PrivateServicePlacement struct {
	DomainID      string `json:"domain_id,omitempty"`
	WorktreeKey   string `json:"worktree_key,omitempty"`
	WorktreeLabel string `json:"worktree_label,omitempty"`
	DNSAutomation bool   `json:"-"`
	SourceKey     string `json:"-"`
}

func (p PrivateServicePlacement) Validate() error {
	if len(p.WorktreeKey) > 128 || strings.TrimSpace(p.WorktreeKey) != p.WorktreeKey || strings.ContainsAny(p.WorktreeKey, "\x00\r\n") || p.WorktreeLabel != "" && (p.WorktreeKey == "" || !validProjectDNSLabel(p.WorktreeLabel)) || strings.TrimSpace(p.DomainID) != p.DomainID || strings.ContainsAny(p.DomainID, "\x00\r\n") {
		return ErrProjectConfigurationInvalid
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

func (d *Database) ensureLocalManagedEndpoint(ctx context.Context, tx pgx.Tx, service, actor, name string, placement PrivateServicePlacement, now time.Time) error {
	row, err := controlstatedb.New(tx).LockPrivateService(ctx, service)
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
	domain, err := controlstatedb.New(tx).GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: domainID, TeamID: text(row.TeamID)})
	if err != nil {
		return publisherLookupError(err, ErrPrivateServiceAccess)
	}
	var membership, managed, slug, pool string
	if err = tx.QueryRow(ctx, `SELECT member.id,member.managed_label,reservation.member_slug,team.ingress_pool_id FROM control.team_memberships member JOIN control.member_slug_reservations reservation ON reservation.id=member.slug_reservation_id AND reservation.team_id=member.team_id JOIN control.teams team ON team.id=member.team_id JOIN control.identities person ON person.id=member.identity_id WHERE member.team_id=$1 AND member.identity_id=$2 AND member.removed_at IS NULL AND person.disabled_at IS NULL AND team.deleted_at IS NULL`, row.TeamID, actor).Scan(&membership, &managed, &slug, &pool); err != nil {
		return publisherLookupError(err, ErrPrivateServiceAccess)
	}
	owner := naming.MemberNamespace(domain.CanonicalDomain, domain.Kind == "managed", managed, slug)
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
	if row.CertificateHostname != "" {
		if !strings.HasSuffix(row.CertificateHostname, "."+owner) || row.DomainID.String != domainID || row.PlacementWorktreeKey != placement.WorktreeKey || row.PlacementWorktreeLabel != label {
			return ErrPrivateServiceConflict
		}
		return nil
	}
	sourceKey := placement.SourceKey
	if sourceKey == "" {
		sourceKey = "adhoc/" + placement.WorktreeKey + "/" + name
	}
	digest := sha256.Sum256([]byte(membership + "\x00" + sourceKey))
	sourceKey = fmt.Sprintf("%x", digest[:])
	var conflict bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.public_urls WHERE canonical_hostname=$1 AND lifecycle_state<>'deleted') OR EXISTS(SELECT 1 FROM control.managed_namespace_claims WHERE ($1=namespace OR right($1,length(namespace)+1)='.'||namespace) AND (local_source_key<>$2 OR membership_id IS DISTINCT FROM $3))`, hostname, sourceKey, membership).Scan(&conflict); err != nil {
		return err
	}
	if conflict {
		return ErrPrivateServiceConflict
	}
	var claimed string
	if err = tx.QueryRow(ctx, `INSERT INTO control.managed_namespace_claims(namespace,local_source_key,membership_id,domain_id,created_at) VALUES($1,$2,$3,$4,$5) ON CONFLICT(namespace) DO UPDATE SET local_source_key=EXCLUDED.local_source_key WHERE control.managed_namespace_claims.local_source_key=EXCLUDED.local_source_key AND control.managed_namespace_claims.membership_id=EXCLUDED.membership_id AND control.managed_namespace_claims.domain_id=EXCLUDED.domain_id AND control.managed_namespace_claims.retired_at IS NULL RETURNING namespace`, hostname, sourceKey, membership, domainID, now).Scan(&claimed); err != nil {
		return publisherLookupError(err, ErrPrivateServiceConflict)
	}
	port, err := allocateManagedServicePort(ctx, tx, service, pool, now)
	if err != nil {
		return err
	}
	// local publishers receive exact-host plans, never authority over another
	// service or the member/worktree namespace as a whole.
	if err = reconcileManagedEndpoint(ctx, tx, managedEndpoint{ServiceID: service, LocalSourceKey: sourceKey, DomainID: domainID, Hostname: hostname, Namespace: hostname, PoolID: pool, Automation: placement.DNSAutomation}, now); err != nil {
		return err
	}
	_, err = tx.Exec(ctx, `UPDATE control.private_services SET certificate_hostname=$2,certificate_scope=$2,domain_id=$3,service_port=$4,ingress_pool_id=$5,placement_worktree_key=$6,placement_worktree_label=$7 WHERE id=$1`, service, hostname, domainID, port, pool, placement.WorktreeKey, label)
	return projectConstraintError(err)
}
