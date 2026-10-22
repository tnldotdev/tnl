package controlstate

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

// domain defaults are captured once. changing the team's default cannot rename
// an existing endpoint or move certificate authority to another domain.
func resolveManagedGroupDomains(ctx context.Context, tx pgx.Tx, team, project string, c ProjectConfiguration) (ProjectConfiguration, error) {
	q := controlstatedb.New(tx)
	for _, name := range sortedProjectKeys(c.Publishers) {
		group := c.Publishers[name]
		if group.DomainID == "" {
			if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT domain_id FROM control.project_publisher_groups WHERE team_id=$1 AND project_key=$2 AND name=$3 AND deleted_at IS NULL),default_domain_id) FROM control.teams WHERE id=$1 AND deleted_at IS NULL`, team, project, name).Scan(&group.DomainID); err != nil {
				return c, publisherLookupError(err, ErrProjectConfigurationInvalid)
			}
		}
		if _, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: group.DomainID, TeamID: text(team)}); err != nil {
			return c, publisherLookupError(err, ErrProjectConfigurationInvalid)
		}
		c.Publishers[name] = group
	}
	return c, nil
}

func (d *Database) ensureManagedGroupNamespace(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, groupID, name string, group ProjectPublisherGroup, namespaceLabel ...string) error {
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
		namespaceName := name
		if len(namespaceLabel) != 0 {
			namespaceName = namespaceLabel[0]
		}
		namespace, err = naming.ManagedGroupNamespace(namespaceName, projectLabel, owner)
		if err != nil {
			return ErrProjectConfigurationInvalid
		}
		var conflict bool
		if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.public_urls WHERE lifecycle_state<>'deleted' AND (canonical_hostname=$1 OR right(canonical_hostname,length($1)+1)='.'||$1))`, namespace).Scan(&conflict); err != nil {
			return err
		}
		if conflict {
			return ErrPrivateServiceConflict
		}
		// released claims may be reused only after their old authority has fully
		// retired. the claim itself, rather than a friendly name, owns this scope.
		var claimed string
		err = tx.QueryRow(ctx, `INSERT INTO control.managed_namespace_claims(namespace,group_id,domain_id,created_at) VALUES($1,$2,$3,$4)
		    ON CONFLICT(namespace) DO UPDATE SET group_id=EXCLUDED.group_id,domain_id=EXCLUDED.domain_id,created_at=EXCLUDED.created_at,retired_at=NULL,reusable_after=NULL
		    WHERE control.managed_namespace_claims.group_id=EXCLUDED.group_id AND control.managed_namespace_claims.retired_at IS NULL
		      OR control.managed_namespace_reusable(control.managed_namespace_claims.namespace,$4)
		    RETURNING namespace`, namespace, groupID, group.DomainID, r.Now).Scan(&claimed)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrPrivateServiceConflict
		}
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE control.project_publisher_groups SET namespace=$2,domain_id=$3,public=$4 WHERE id=$1`, groupID, namespace, group.DomainID, group.Public)
	if err != nil {
		return err
	}
	return claimPublisherGroupName(ctx, tx, r.TeamID, r.ProjectKey, name, groupID, r.Now)
}

func claimPublisherGroupName(ctx context.Context, tx pgx.Tx, team, project, name, group string, now time.Time) error {
	var owner string
	err := tx.QueryRow(ctx, `INSERT INTO control.publisher_group_names(team_id,project_key,name,group_id) VALUES($1,$2,$3,$4) ON CONFLICT(team_id,project_key,name) DO UPDATE SET group_id=EXCLUDED.group_id
	    WHERE control.publisher_group_names.group_id=EXCLUDED.group_id RETURNING group_id`, team, project, name, group).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrPrivateServiceConflict
	}
	return err
}

func retireManagedNamespace(ctx context.Context, tx pgx.Tx, group string, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE control.managed_namespace_claims claim SET retired_at=$2::timestamptz,reusable_after=GREATEST($2::timestamptz+interval '7 days',COALESCE((SELECT max(not_after) FROM control.acme_orders WHERE certificate_scope=claim.namespace),$2::timestamptz)) WHERE group_id=$1 AND retired_at IS NULL`, group, now)
	return err
}

func validProjectDNSLabel(label string) bool {
	canonical, err := naming.CanonicalizeHostname(label)
	return err == nil && canonical == label && len(label) <= 63 && !strings.Contains(label, ".")
}
