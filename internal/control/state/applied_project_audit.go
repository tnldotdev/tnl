package state

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
)

// the general publisher identity API and the scoped group API share this fact.
// nongroup identities retain their existing audit behavior.
func recordPublisherGroupMemberRevocation(ctx context.Context, tx pgx.Tx, publisher, actor string, now time.Time) error {
	var group string
	err := tx.QueryRow(ctx, `SELECT group_id FROM control.publisher_group_members WHERE publisher_identity_id=$1`, publisher).Scan(&group)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return recordPublisherGroupUpdate(ctx, tx, group, publisherIssuer{IdentityID: actor}, publisher, "revoke-member/"+publisher, now)
}

func recordAppliedGroupChange(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor publisherIssuer, publisher, request string, revision int64, now time.Time) error {
	id, kind := s.PublicURLID.String, "public_url"
	if s.ServiceID.Valid {
		id, kind = s.ServiceID.String, "service"
	}
	if id == "" {
		return nil
	}
	return RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: s.TeamID, ServiceID: id, ServiceKind: kind, EventType: "group.update", OccurredAt: now, ActorIdentityID: actor.IdentityID, ActorMachineID: actor.MachineID, ActorProvisioningGrantID: actor.ProvisioningGrantID, PublisherIdentityID: publisher, ConfigurationRevision: revision}, request)
}

func recordPublisherGroupUpdate(ctx context.Context, tx pgx.Tx, group string, actor publisherIssuer, publisher, request string, now time.Time) error {
	var team, project string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT owner.team_id,owner.project_key,owner.mutation_revision FROM control.project_publisher_groups assignment JOIN control.environments owner ON owner.id=assignment.environment_id AND owner.group_id=assignment.id AND owner.team_id=assignment.team_id AND owner.project_key=assignment.project_key WHERE assignment.id=$1`, group).Scan(&team, &project, &revision); err != nil {
		return err
	}
	services, err := controlstatedb.New(tx).ListAppliedProjectServices(ctx, controlstatedb.ListAppliedProjectServicesParams{TeamID: team, ProjectKey: project})
	if err != nil {
		return err
	}
	for _, s := range services {
		if s.GroupID.String == group {
			if err = recordAppliedGroupChange(ctx, tx, s, actor, publisher, request, revision, now); err != nil {
				return err
			}
		}
	}
	return nil
}
