package state

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

type environmentNamespace struct {
	DomainID string
	Public   bool
}

// domain defaults are captured once. changing the team's default cannot rename
// an existing endpoint or move certificate authority to another domain.
func (d *Database) ensureEnvironmentNamespace(ctx context.Context, tx pgx.Tx, r serviceResourceMutation, groupID, name string, group environmentNamespace) error {
	var namespace, domainID, projectLabel string
	if err := tx.QueryRow(ctx, `SELECT g.namespace,COALESCE(g.domain_id,''),p.project_label FROM control.project_publisher_groups g JOIN control.applied_projects p USING(team_id,project_key) WHERE g.id=$1 FOR UPDATE OF g`, groupID).Scan(&namespace, &domainID, &projectLabel); err != nil {
		return err
	}
	if namespace != "" {
		if domainID != group.DomainID {
			return ErrProjectManaged
		}
	} else {
		q := controlstatedb.New(tx)
		domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: group.DomainID, TeamID: text(r.TeamID)})
		if err != nil {
			return publisherLookupError(err, ErrProjectConfigurationInvalid)
		}
		var label, teamName string
		if err = tx.QueryRow(ctx, `SELECT managed_label,display_name FROM control.teams WHERE id=$1`, r.TeamID).Scan(&label, &teamName); err != nil {
			return err
		}
		owner := domain.CanonicalDomain
		if domain.Kind == "managed" {
			if d.managedURLMode == naming.ManagedURLModeSimple {
				label = teamName
			}
			owner = label + "." + owner
		}
		namespace, err = naming.GroupNamespace(name, projectLabel, owner)
		if err != nil {
			return ErrProjectConfigurationInvalid
		}
		var conflict bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.public_urls WHERE lifecycle_state<>'deleted' AND (canonical_hostname=$1 OR right(canonical_hostname,length($1)+1)='.'||$1))`, namespace).Scan(&conflict); err != nil {
			return err
		}
		if conflict {
			return ErrServiceConflict
		}
		// released claims may be reused only after their old authority has fully
		// retired. the claim itself, rather than a friendly name, owns this scope.
		var claimed string
		err = tx.QueryRow(ctx, `INSERT INTO control.service_namespace_claims(namespace,group_id,domain_id,created_at) VALUES($1,$2,$3,$4)
		    ON CONFLICT(namespace) DO UPDATE SET group_id=EXCLUDED.group_id,domain_id=EXCLUDED.domain_id,created_at=EXCLUDED.created_at,retired_at=NULL,reusable_after=NULL
		    WHERE control.service_namespace_claims.group_id=EXCLUDED.group_id AND control.service_namespace_claims.retired_at IS NULL
		      OR control.service_namespace_reusable(control.service_namespace_claims.namespace,$4)
		    RETURNING namespace`, namespace, groupID, group.DomainID, r.Now).Scan(&claimed)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrServiceConflict
		}
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE control.project_publisher_groups SET namespace=$2,domain_id=$3,public=$4 WHERE id=$1`, groupID, namespace, group.DomainID, group.Public)
	if err != nil {
		return err
	}
	return nil
}

func retireServiceNamespace(ctx context.Context, tx pgx.Tx, group string, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE control.service_namespace_claims claim SET retired_at=$2::timestamptz,reusable_after=GREATEST($2::timestamptz+interval '7 days',COALESCE((SELECT max(not_after) FROM control.acme_orders WHERE certificate_scope=claim.namespace),$2::timestamptz)) WHERE group_id=$1 AND retired_at IS NULL`, group, now)
	return err
}

func validProjectDNSLabel(label string) bool {
	canonical, err := naming.CanonicalizeHostname(label)
	return err == nil && canonical == label && len(label) <= 63 && !strings.Contains(label, ".")
}
