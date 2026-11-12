package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationCollectionDefaultAndCreationSerializeTheirPreconditions(t *testing.T) {
	for _, firstOperation := range []string{"default", "environment"} {
		t.Run(firstOperation, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "collection_default_race")
			r := appliedProjectRequest(t, d, now)
			d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
			d2 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "postgres"}})
			c, _ := createTestCollection(t, d, r, "serialized", d1.Revision)
			request := collectionEnvironmentRequest(r, c, "racing-member", "racing.internal:3000")
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockCollection(ctx, controlstatedb.LockCollectionParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ID: c.ID}); err != nil {
				t.Fatal(err)
			}
			defaultDone, environmentDone := make(chan error, 1), make(chan error, 1)
			var member Environment
			update := func() {
				_, err := d.UpdateCollectionDefault(ctx, UpdateCollectionDefaultRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, CollectionID: c.ID, ExpectedRevision: 1, DefinitionRevision: d2.Revision, Now: now})
				defaultDone <- err
			}
			create := func() {
				var err error
				member, err = d.CreateEnvironment(ctx, request)
				environmentDone <- err
			}
			first, second := defaultDone, environmentDone
			if firstOperation == "default" {
				workers.Go(update)
			} else {
				first, second = environmentDone, defaultDone
				workers.Go(create)
			}
			firstPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), first)
			if firstOperation == "default" {
				workers.Go(create)
			} else {
				workers.Go(update)
			}
			waitForPostgresBlock(t, ctx, d, firstPID, second)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, defaultDone); err != nil {
				t.Fatal("default update failed", err)
			}
			createErr := awaitIntegrationResult(t, ctx, environmentDone)
			if firstOperation == "default" {
				if !errors.Is(createErr, ErrCollectionStale) {
					t.Fatal("creation did not recheck the default revision after waiting", createErr)
				}
				var count int
				if err := d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.environments)+(SELECT count(*) FROM control.project_publisher_groups)+(SELECT count(*) FROM control.environment_creations)+(SELECT count(*) FROM control.services)`).Scan(&count); err != nil || count != 0 {
					t.Fatal("stale creation left membership or resource rows", count, err)
				}
			} else {
				if createErr != nil || member.AppliedDefinitionRevision != d1.Revision || member.CollectionID != c.ID || member.MutationRevision != 1 {
					t.Fatal("creation did not pin its serially selected default", member, createErr)
				}
				got, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, member.ID, r.ActorID)
				if err != nil || got.AppliedDefinitionRevision != d1.Revision || got.MutationRevision != 1 {
					t.Fatal("queued default update revised the newly installed member", got, err)
				}
			}
			if _, err := d.UpdateCollectionDefault(ctx, UpdateCollectionDefaultRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, CollectionID: c.ID, ExpectedRevision: 1, DefinitionRevision: d1.Revision, Now: now}); !errors.Is(err, ErrCollectionStale) {
				t.Fatal("losing default update ignored the committed revision", err)
			}
		})
	}
}
