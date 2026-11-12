package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationCollectionRequiresCurrentManagerForReadsMutationsAndReplays(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "collection_manager")
	r := retainedEnvironmentProject(t, d, now)
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	issuer, manager := retainedEnvironmentManager(t, d, r, "collection-manager")
	d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	c, creation := createTestCollection(t, d, issuer, "managed", d1.Revision)
	environmentRequest := collectionEnvironmentRequest(issuer, c, "installed", "installed.internal:3000")
	environment, err := d.CreateEnvironment(t.Context(), environmentRequest)
	if err != nil {
		t.Fatal(err)
	}
	member := enrollTestEnvironment(t, d, issuer, environment)
	access := environmentAssignmentAccess(t, d, member, member.assignments.Services[0], now)
	for _, loss := range []string{"demoted", "disabled", "removed"} {
		switch loss {
		case "demoted":
			_, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET role='member' WHERE id=$1`, manager.ID)
		case "disabled":
			_, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET role='admin' WHERE id=$1`, manager.ID)
			if err == nil {
				_, err = d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, manager.IdentityID, now)
			}
		case "removed":
			_, err = d.pool.Exec(t.Context(), `UPDATE control.identities SET disabled_at=NULL WHERE id=$1`, manager.IdentityID)
			if err == nil {
				_, err = d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET removed_at=$2,removed_by_identity_id=$3 WHERE id=$1`, manager.ID, now, r.ActorID)
			}
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Run(loss, func(t *testing.T) {
			fresh := creation
			fresh.Name = "fresh"
			freshEnvironment := environmentRequest
			freshEnvironment.Name, freshEnvironment.IdempotencyKey = "fresh", "fresh"
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"create", func() error { _, err := d.CreateCollection(t.Context(), fresh); return err }},
				{"create replay", func() error { _, err := d.CreateCollection(t.Context(), creation); return err }},
				{"get", func() error {
					_, err := d.GetCollection(t.Context(), r.TeamID, r.ProjectKey, c.ID, issuer.ActorID)
					return err
				}},
				{"list", func() error {
					_, err := d.ListCollections(t.Context(), r.TeamID, r.ProjectKey, issuer.ActorID)
					return err
				}},
				{"default update", func() error {
					_, err := d.UpdateCollectionDefault(t.Context(), UpdateCollectionDefaultRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: issuer.ActorID, CollectionID: c.ID, ExpectedRevision: 1, DefinitionRevision: d1.Revision, Now: now})
					return err
				}},
				{"environment create", func() error { _, err := d.CreateEnvironment(t.Context(), freshEnvironment); return err }},
				{"environment replay", func() error { _, err := d.CreateEnvironment(t.Context(), environmentRequest); return err }},
			} {
				if err := operation.run(); !errors.Is(err, ErrServiceAccess) {
					t.Errorf("%s manager retained %s: %v", loss, operation.name, err)
				}
			}
			if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
				t.Error("installed team publisher depended on the enrolling human", err)
			}
			if _, err := d.GetEnvironmentPublisherAssignments(t.Context(), member.lease.AccessToken, now); err != nil {
				t.Error("installed assignments depended on the enrolling human", err)
			}
		})
	}
	got, err := d.GetCollection(t.Context(), r.TeamID, r.ProjectKey, c.ID, r.ActorID)
	if err != nil || got != c {
		t.Fatal("denied operations changed the collection", got, err)
	}
}

func TestIntegrationCollectionMutationsRecheckAuthorityAfterLockWait(t *testing.T) {
	for _, operation := range []string{"create", "create replay", "default update", "environment create", "environment replay"} {
		for _, boundary := range []string{"team", "project"} {
			t.Run(operation+"/"+boundary, func(t *testing.T) {
				d, now := newControlStateIntegrationDatabase(t, "collection_authority_wait")
				r := retainedEnvironmentProject(t, d, now)
				if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
					t.Fatal(err)
				}
				manager := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "waiting-manager", TeamRoleAdmin)
				d1 := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
				c, creation := createTestCollection(t, d, r, "managed", d1.Revision)
				environmentRequest := collectionEnvironmentRequest(r, c, "managed", "managed.internal:3000")
				if _, err := d.CreateEnvironment(t.Context(), environmentRequest); err != nil {
					t.Fatal(err)
				}
				creation.ActorID, environmentRequest.ActorID = manager.IdentityID, manager.IdentityID
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				defer cancel()
				workers := newIntegrationWorkers(t, cancel)
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				q := controlstatedb.New(gate)
				if boundary == "team" {
					_, err = q.LockLocalTeamForMutation(ctx, r.TeamID)
				} else {
					_, err = q.LockAppliedProject(ctx, controlstatedb.LockAppliedProjectParams{TeamID: r.TeamID, ProjectKey: r.ProjectKey})
				}
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				workers.Go(func() {
					switch operation {
					case "create", "create replay":
						if operation == "create" {
							creation.Name = "new"
						}
						_, err := d.CreateCollection(ctx, creation)
						done <- err
					case "default update":
						_, err := d.UpdateCollectionDefault(ctx, UpdateCollectionDefaultRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: manager.IdentityID, CollectionID: c.ID, ExpectedRevision: c.MutationRevision, DefinitionRevision: d1.Revision, Now: now})
						done <- err
					case "environment create", "environment replay":
						if operation == "environment create" {
							environmentRequest.Name, environmentRequest.IdempotencyKey = "new", "new"
						}
						_, err := d.CreateEnvironment(ctx, environmentRequest)
						done <- err
					}
				})
				waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), done)
				// the project gate deliberately permits an identity change after the
				// first authorization check; the final check must roll back any work.
				if _, err := gate.Exec(ctx, `UPDATE control.identities SET disabled_at=$2 WHERE id=$1`, manager.IdentityID, now); err != nil {
					t.Fatal(err)
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("operation retained authority from before its lock wait", err)
				}
				var collections, environments, services int
				if err := d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.collections),(SELECT count(*) FROM control.environments),(SELECT count(*) FROM control.services)`).Scan(&collections, &environments, &services); err != nil || collections != 1 || environments != 1 || services != 1 {
					t.Fatal("authority rejection partially committed work", collections, environments, services, err)
				}
				got, err := d.GetCollection(ctx, r.TeamID, r.ProjectKey, c.ID, r.ActorID)
				if err != nil || got != c {
					t.Fatal("authority rejection advanced the collection", got, err)
				}
			})
		}
	}
}
