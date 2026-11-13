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

// domain defaults are captured once. changing the team's default cannot rename
// an existing endpoint or move certificate authority to another domain.
func resolveDeploymentDomain(ctx context.Context, tx pgx.Tx, team, project, name string, c ProjectConfiguration) (ProjectConfiguration, error) {
	if c.Settings == nil {
		return c, nil
	}
	q := controlstatedb.New(tx)
	if c.Settings.DomainID == "" {
		if err := tx.QueryRow(ctx, `SELECT COALESCE((SELECT domain_id FROM control.deployments WHERE team_id=$1 AND project_key=$2 AND name=$3 AND deleted_at IS NULL),default_domain_id) FROM control.teams WHERE id=$1 AND deleted_at IS NULL`, team, project, name).Scan(&c.Settings.DomainID); err != nil {
			return c, publisherLookupError(err, ErrProjectConfigurationInvalid)
		}
	}
	if _, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: c.Settings.DomainID, TeamID: text(team)}); err != nil {
		return c, publisherLookupError(err, ErrProjectConfigurationInvalid)
	}
	return c, nil
}

func (d *Database) ensureDeploymentNamespace(ctx context.Context, tx pgx.Tx, r ApplyProjectConfigurationRequest, deploymentID, name string, settings DeploymentSettings, namespaceLabel string) error {
	var namespace, domainID, projectLabel string
	if err := tx.QueryRow(ctx, `SELECT g.namespace,COALESCE(g.domain_id,''),p.project_label FROM control.deployments g JOIN control.applied_projects p USING(team_id,project_key) WHERE g.id=$1 FOR UPDATE OF g`, deploymentID).Scan(&namespace, &domainID, &projectLabel); err != nil {
		return err
	}
	if namespace != "" {
		if domainID != settings.DomainID {
			return ErrProjectManaged
		}
	} else {
		q := controlstatedb.New(tx)
		domain, err := q.GetPublisherDomain(ctx, controlstatedb.GetPublisherDomainParams{ID: settings.DomainID, TeamID: text(r.TeamID)})
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
		namespace, err = naming.DeploymentNamespace(namespaceLabel, projectLabel, owner)
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
		err = tx.QueryRow(ctx, `INSERT INTO control.service_namespace_claims(namespace,deployment_id,domain_id,created_at) VALUES($1,$2,$3,$4)
		    ON CONFLICT(namespace) DO UPDATE SET deployment_id=EXCLUDED.deployment_id,domain_id=EXCLUDED.domain_id,created_at=EXCLUDED.created_at,retired_at=NULL,reusable_after=NULL
		    WHERE control.service_namespace_claims.deployment_id=EXCLUDED.deployment_id AND control.service_namespace_claims.retired_at IS NULL
		      OR control.service_namespace_reusable(control.service_namespace_claims.namespace,$4)
		    RETURNING namespace`, namespace, deploymentID, settings.DomainID, r.Now).Scan(&claimed)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrServiceConflict
		}
		if err != nil {
			return err
		}
	}
	_, err := tx.Exec(ctx, `UPDATE control.deployments SET namespace=$2,domain_id=$3,public=$4 WHERE id=$1`, deploymentID, namespace, settings.DomainID, settings.Public)
	if err != nil {
		return err
	}
	return claimDeploymentName(ctx, tx, r.TeamID, r.ProjectKey, name, deploymentID, r.Now)
}

func claimDeploymentName(ctx context.Context, tx pgx.Tx, team, project, name, deploymentID string, now time.Time) error {
	var owner string
	err := tx.QueryRow(ctx, `INSERT INTO control.deployment_names(team_id,project_key,name,deployment_id) VALUES($1,$2,$3,$4) ON CONFLICT(team_id,project_key,name) DO UPDATE SET deployment_id=EXCLUDED.deployment_id
	    WHERE control.deployment_names.deployment_id=EXCLUDED.deployment_id RETURNING deployment_id`, team, project, name, deploymentID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrServiceConflict
	}
	return err
}

func retireServiceNamespace(ctx context.Context, tx pgx.Tx, deployment string, now time.Time) error {
	_, err := tx.Exec(ctx, `UPDATE control.service_namespace_claims claim SET retired_at=$2::timestamptz,reusable_after=GREATEST($2::timestamptz+interval '7 days',COALESCE((SELECT max(not_after) FROM control.acme_orders WHERE certificate_scope=claim.namespace),$2::timestamptz)) WHERE deployment_id=$1 AND retired_at IS NULL`, deployment, now)
	return err
}

func validProjectDNSLabel(label string) bool {
	canonical, err := naming.CanonicalizeHostname(label)
	return err == nil && canonical == label && len(label) <= 63 && !strings.Contains(label, ".")
}
