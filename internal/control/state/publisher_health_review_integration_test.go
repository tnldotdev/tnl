package state

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationPublisherGroupHealthRuntimeReplacement(t *testing.T) {
	for _, ordering := range []string{"equal", "reversed", "ack-first", "start-first"} {
		t.Run(ordering, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "group_health_"+ordering)
			r := retainedEnvironmentProject(t, d, now)
			applied, _ := retainedServiceEnvironment(t, d, r, "remote", map[string]EnvironmentServicePublication{"web": {Protocol: "http", Target: "localhost:3000"}})
			replica := enrollTestEnvironment(t, d, r, applied)
			request := func(run string, epoch int64, at time.Time) PublisherRuntimeRequest {
				t.Helper()
				v := PublisherRuntimeRequest{PublisherIdentityID: replica.member.PublisherIdentityID, ScopeID: replica.member.EnvironmentID, ProcessRunID: run, ExpectedEpoch: epoch, Action: "start", Audience: "https://control.example/v1/publisher-runtime", Now: at}
				var err error
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
				return d.AcknowledgeEnvironmentPublisher(ctx, first.EnvironmentLease.AccessToken, environmentPublicationForTest(applied), true, ackAt)
			}
			if err := ack(t.Context()); err != nil {
				t.Fatal(err)
			}
			status := func(want bool) {
				t.Helper()
				s, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, applied.ID, r.ActorID)
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
					query, args = `SELECT team_id FROM control.applied_projects WHERE team_id=$1 AND project_key=$2 FOR UPDATE`, []any{r.TeamID, r.ProjectKey}
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
					if !errors.Is(err, ErrEnvironmentPublisher) {
						t.Fatal("old acknowledgement escaped replacement", err)
					}
				} else if err != nil {
					t.Fatal(err)
				}
			}
			status(false)
			// a current acknowledgement may have an earlier request clock. health
			// belongs to the serialized runtime, not its wall-clock ordering.
			if err := d.AcknowledgeEnvironmentPublisher(t.Context(), replacement.EnvironmentLease.AccessToken, environmentPublicationForTest(applied), true, now.Add(-time.Second)); err != nil {
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
