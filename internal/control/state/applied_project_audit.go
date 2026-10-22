package controlstate

import (
	"context"
	"errors"
	"fmt"
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
	return recordPublisherGroupUpdate(ctx, tx, group, actor, publisher, "revoke-member/"+publisher, now)
}

func recordAppliedGroupChange(ctx context.Context, tx pgx.Tx, s controlstatedb.ControlAppliedProjectService, actor, publisher, request string, revision int64, now time.Time) error {
	id, kind := s.PublicURLID.String, "public_url"
	if s.PrivateServiceID.Valid {
		id, kind = s.PrivateServiceID.String, "private_service"
	}
	if id == "" {
		return nil
	}
	return RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: s.TeamID, ServiceID: id, ServiceKind: kind, EventType: "group.update", OccurredAt: now, ActorIdentityID: actor, PublisherIdentityID: publisher, ConfigurationRevision: revision}, request)
}

func recordPublisherGroupUpdate(ctx context.Context, tx pgx.Tx, group, actor, publisher, request string, now time.Time) error {
	var team, project string
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT g.team_id,g.project_key,p.revision FROM control.project_publisher_groups g JOIN control.applied_projects p ON p.team_id=g.team_id AND p.project_key=g.project_key WHERE g.id=$1`, group).Scan(&team, &project, &revision); err != nil {
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

func recordAppliedGroupConfiguration(ctx context.Context, tx pgx.Tx, oldServices, newServices []controlstatedb.ControlAppliedProjectService, changed map[string]bool, actor string, revision int64, now time.Time) error {
	seen := map[string]bool{}
	for _, rows := range [][]controlstatedb.ControlAppliedProjectService{oldServices, newServices} {
		for _, s := range rows {
			if !changed[s.GroupID.String] {
				continue
			}
			key := s.GroupID.String + "/" + s.PrivateServiceID.String + "/" + s.PublicURLID.String
			if seen[key] {
				continue
			}
			seen[key] = true
			if err := recordAppliedGroupChange(ctx, tx, s, actor, "", fmt.Sprintf("group/%s/configuration/%d", s.GroupID.String, revision), revision, now); err != nil {
				return err
			}
		}
	}
	return nil
}
