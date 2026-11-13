package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationDeploymentPublisherHealthRuntimeReplacement(t *testing.T) {
	for _, ordering := range []string{"equal", "reversed", "ack-first", "start-first"} {
		t.Run(ordering, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "deployment_health_"+ordering)
			r := appliedProjectRequest(t, d, now)
			r.Configuration.Settings = &DeploymentSettings{}
			r.Configuration.Services["web"] = ProjectServiceConfiguration{Target: "http://localhost:3000"}
			r = selectedProjectRequest(r, "remote")
			_, err := d.ApplyProjectConfiguration(t.Context(), r)
			if err != nil {
				t.Fatal(err)
			}
			e, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "remote", r.ActorID, 1, time.Hour, now)
			if err != nil {
				t.Fatal(err)
			}
			replica := enrollAppliedDeployment(t, d, r, e, now)
			request := func(run string, epoch int64, at time.Time) PublisherRuntimeRequest {
				t.Helper()
				v := PublisherRuntimeRequest{PublisherIdentityID: replica.member.PublisherIdentityID, ScopeID: replica.member.DeploymentID, ProcessRunID: run, ExpectedEpoch: epoch, Action: "start", Audience: "https://control.example/v1/publisher-runtime", Now: at}
				v.Assertion, err = publisherproof.Sign(v.PublisherIdentityID, replica.member.KeyID, publisherproof.RuntimeScope(v.ScopeID, v.Action, run, epoch, ""), v.Audience, replica.private, at)
				if err != nil {
					t.Fatal(err)
				}
				return v
			}
			first, err := d.PublisherRuntime(t.Context(), request(strings.Repeat("a", 32), 0, now))
			if err != nil {
				t.Fatal(err)
			}
			ackAt := now
			if ordering == "reversed" {
				ackAt = now.Add(time.Second)
			}
			ack := func(ctx context.Context) error {
				return d.AcknowledgeDeploymentPublisherConfiguration(ctx, first.DeploymentLease.AccessToken, replica.assignments.Revision, replica.assignments.ConfigurationHash, true, ackAt)
			}
			if err := ack(t.Context()); err != nil {
				t.Fatal(err)
			}
			status := func(want bool) {
				t.Helper()
				s, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "remote")
				if err != nil || len(s.Members) != 1 || s.Members[0].Healthy != want {
					t.Fatalf("health want %t: %+v %v", want, s.Members, err)
				}
				if (s.Members[0].AcknowledgedAt != nil) != want {
					t.Fatalf("acknowledgement survived its runtime: %+v", s.Members[0])
				}
			}
			status(true)
			startRequest := request(strings.Repeat("b", 32), 1, now)
			var replacement PublisherRuntimeResponse
			start := func(ctx context.Context) error {
				var err error
				replacement, err = d.PublisherRuntime(ctx, startRequest)
				return err
			}
			if ordering == "equal" || ordering == "reversed" {
				if err := start(t.Context()); err != nil {
					t.Fatal(err)
				}
			} else {
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				// block the first operation after it takes the team lock. the second
				// must wait for that operation, independent of request timestamps.
				query, args := `SELECT id FROM control.publisher_identities WHERE id=$1 FOR UPDATE`, []any{replica.member.PublisherIdentityID}
				firstOp, secondOp := start, ack
				if ordering == "ack-first" {
					query, args = `SELECT id FROM control.deployments WHERE id=$1 FOR UPDATE`, []any{replica.member.DeploymentID}
					firstOp, secondOp = ack, start
				}
				if _, err := gate.Exec(ctx, query, args...); err != nil {
					t.Fatal(err)
				}
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				one, two := make(chan error, 1), make(chan error, 1)
				workers.Go(func() { one <- firstOp(ctx) })
				pid := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), one)
				workers.Go(func() { two <- secondOp(ctx) })
				waitForPostgresBlock(t, ctx, d, pid, two)
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, one); err != nil {
					t.Fatal(err)
				}
				err = awaitIntegrationResult(t, ctx, two)
				if ordering == "start-first" {
					if !errors.Is(err, ErrDeploymentPublisher) {
						t.Fatal("old acknowledgement escaped replacement", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			status(false)
			// a current acknowledgement may have an earlier request clock. health
			// belongs to the serialized runtime, not its wall-clock ordering.
			if err := d.AcknowledgeDeploymentPublisherConfiguration(t.Context(), replacement.DeploymentLease.AccessToken, replica.assignments.Revision, replica.assignments.ConfigurationHash, true, now.Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			status(true)
			if _, err := d.PublisherRuntime(t.Context(), request(strings.Repeat("b", 32), 1, now)); err != nil {
				t.Fatal("lost start reply", err)
			}
			status(true)
		})
	}
}
