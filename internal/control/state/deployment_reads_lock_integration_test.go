package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationDeploymentReadersShareParents(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	d, project := f.d, f.project
	enrollment, err := testDeploymentPublisherEnrollment(d, t.Context(), project.TeamID, project.ProjectKey, "production", project.ActorID, 1, time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	member := enrollAppliedDeployment(t, d, project, enrollment, f.now)
	held, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, held)
	service := f.production.Services["web"].ID
	if err = lockServiceForRun(t.Context(), held, service); err != nil {
		t.Fatal(err)
	}
	if _, err = held.Exec(t.Context(), `SELECT id FROM control.deployments WHERE id=$1 FOR SHARE`, f.production.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = held.Exec(t.Context(), `SELECT project_key FROM control.applied_projects WHERE team_id=$1 AND project_key=$2 FOR SHARE`, project.TeamID, project.ProjectKey); err != nil {
		t.Fatal(err)
	}
	t.Run("assignments", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
		defer cancel()
		got, err := d.GetDeploymentPublisherAppAssignments(ctx, member.lease.AccessToken, f.now)
		if err != nil || len(got.Services) != 2 {
			t.Fatal("app assignments during sibling work", len(got.Services), err)
		}
	})
}

func TestIntegrationDeploymentReadersWaitForTeamMutation(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	d, project := f.d, f.project
	enrollment, err := testDeploymentPublisherEnrollment(d, t.Context(), project.TeamID, project.ProjectKey, "production", project.ActorID, 1, time.Hour, f.now)
	if err != nil {
		t.Fatal(err)
	}
	member := enrollAppliedDeployment(t, d, project, enrollment, f.now)
	for _, op := range []string{"lease deadline", "member"} {
		t.Run(op, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			edit, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, edit)
			if _, err := controlstatedb.New(edit).LockLocalTeamForMutation(ctx, project.TeamID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			workers.Go(func() {
				at := f.now
				if op == "lease deadline" {
					at = member.lease.ExpiresAt.Add(-100 * time.Millisecond)
				}
				got, err := d.GetDeploymentPublisherAssignments(ctx, member.lease.AccessToken, at)
				if !errors.Is(err, ErrDeploymentPublisher) || got.Member.PublisherIdentityID != "" {
					done <- errors.New("expired or revoked member received assignments or wrong denial")
					return
				}
				done <- nil
			})
			waitForPostgresBlock(t, ctx, d, int32(edit.Conn().PgConn().PID()), done)
			if op == "lease deadline" {
				// the wait graph proves the request has already started its clock.
				select {
				case <-time.After(110 * time.Millisecond):
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			} else {
				_, err = edit.Exec(ctx, `UPDATE control.publisher_identities SET revoked_at=$2 WHERE id=$1`, member.member.PublisherIdentityID, f.now)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := edit.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); err != nil {
				t.Fatal(err)
			}
		})
	}
}
