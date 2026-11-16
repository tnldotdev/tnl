package state

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

// the general publisher identity API and the scoped deployment API share this fact.
// nondeployment identities retain their existing audit behavior.
func recordDeploymentPublisherIdentityRevocation(ctx context.Context, tx pgx.Tx, publisher, actor string, now time.Time) error {
	var deployment string
	err := tx.QueryRow(ctx, `SELECT deployment_id FROM control.deployment_publisher_members WHERE publisher_identity_id=$1`, publisher).Scan(&deployment)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return recordDeploymentPublisherUpdate(ctx, tx, deployment, actor, publisher, "revoke-member/"+publisher, now)
}

func recordAppliedDeploymentChange(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor, publisher, request string, revision int64, now time.Time) error {
	id, kind := s.PublicURLID.String, "public_url"
	if s.ServiceID.Valid {
		id, kind = s.ServiceID.String, "service"
	}
	if id == "" {
		return nil
	}
	return RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: s.TeamID, ServiceID: id, ServiceKind: kind, EventType: "deployment.update", OccurredAt: now, ActorIdentityID: actor, PublisherIdentityID: publisher, ConfigurationRevision: revision}, request)
}

func recordDeploymentPublisherUpdate(ctx context.Context, tx pgx.Tx, deployment, actor, publisher, request string, now time.Time) error {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM control.deployments WHERE id=$1`, deployment).Scan(&revision); err != nil {
		return err
	}
	services, err := controlstatedb.New(tx).ListDeploymentPublisherServices(ctx, deployment)
	if err != nil {
		return err
	}
	for _, s := range services {
		if err = recordAppliedDeploymentChange(ctx, tx, s, actor, publisher, request, revision, now); err != nil {
			return err
		}
	}
	return nil
}

func recordAppliedDeploymentConfiguration(ctx context.Context, tx pgx.Tx, oldServices, newServices []controlstatedb.ControlAppliedProjectService, changed map[string]bool, actor string, revision int64, now time.Time) error {
	seen := map[string]bool{}
	for _, rows := range [][]controlstatedb.ControlAppliedProjectService{oldServices, newServices} {
		for _, s := range rows {
			if !changed[s.DeploymentID.String] {
				continue
			}
			key := s.DeploymentID.String + "/" + s.ServiceID.String + "/" + s.PublicURLID.String
			if seen[key] {
				continue
			}
			seen[key] = true
			if err := recordAppliedDeploymentChange(ctx, tx, s, actor, "", fmt.Sprintf("deployment/%s/configuration/%d", s.DeploymentID.String, revision), revision, now); err != nil {
				return err
			}
		}
	}
	return nil
}
