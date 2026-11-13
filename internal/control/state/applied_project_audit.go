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
	if s.ServiceID.Valid {
		id, kind = s.ServiceID.String, "service"
	}
	if id == "" {
		return nil
	}
	return RecordServiceAudit(ctx, tx, serviceaudit.Event{TeamID: s.TeamID, ServiceID: id, ServiceKind: kind, EventType: "group.update", OccurredAt: now, ActorIdentityID: actor, PublisherIdentityID: publisher, ConfigurationRevision: revision}, request)
}

func recordPublisherGroupUpdate(ctx context.Context, tx pgx.Tx, group, actor, publisher, request string, now time.Time) error {
	var revision int64
	if err := tx.QueryRow(ctx, `SELECT revision FROM control.project_publisher_groups WHERE id=$1`, group).Scan(&revision); err != nil {
		return err
	}
	services, err := controlstatedb.New(tx).ListPublisherGroupServices(ctx, group)
	if err != nil {
		return err
	}
	for _, s := range services {
		if err = recordAppliedGroupChange(ctx, tx, s, actor, publisher, request, revision, now); err != nil {
			return err
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
			key := s.GroupID.String + "/" + s.ServiceID.String + "/" + s.PublicURLID.String
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
