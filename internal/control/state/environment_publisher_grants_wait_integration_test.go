package state

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func environmentPublisherGrantFacts(t *testing.T, f *environmentPublisherGrantFixture) []byte {
	t.Helper()
	var facts []byte
	err := f.d.pool.QueryRow(t.Context(), `SELECT jsonb_build_object(
		'grants',(SELECT jsonb_agg(to_jsonb(g) ORDER BY g.id) FROM control.publisher_grants g WHERE g.publisher_identity_id=$1),
		'mappings',(SELECT jsonb_agg(to_jsonb(m) ORDER BY m.service) FROM control.publisher_group_service_grants m WHERE m.publisher_identity_id=$1),
		'receipts',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.idempotency_key) FROM control.environment_publisher_grant_requests r WHERE r.environment_id=$2),
		'member',(SELECT to_jsonb(m) FROM control.publisher_group_members m WHERE m.publisher_identity_id=$1),
		'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY r.id) FROM control.service_runs r WHERE r.publisher_identity_id=$1),
		'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY a.cursor) FROM control.service_audit_events a WHERE a.team_id=$3)
	)::text`, f.publisher.member.PublisherIdentityID, f.environment.ID, f.r.TeamID).Scan(&facts)
	if err != nil {
		t.Fatal(err)
	}
	return facts
}

func TestIntegrationEnvironmentPublisherGrantsManagerLostWhileQueued(t *testing.T) {
	for _, operation := range []string{"new", "replay", "noop", "revoke", "inspect"} {
		t.Run(operation, func(t *testing.T) {
			f := newEnvironmentPublisherGrantFixture(t)
			f.grow(t)
			session := f.managerSession(t, TeamRoleAdmin)
			manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), session.AccessToken)
			if err != nil {
				t.Fatal(err)
			}
			request := f.request("queued-intent")
			var grant string
			if operation != "new" && operation != "inspect" {
				created, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				grant = created.Grant.ID
				if operation == "noop" {
					request.IdempotencyKey = "queued-active-noop"
					request.ExpectedPreviousGrantID = environmentPublisherGrantExpected(t, grant)
				}
			}
			request.Manager = manager
			before := environmentPublisherGrantFacts(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := f.d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockLocalTeamForMutation(ctx, f.r.TeamID); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch operation {
				case "inspect":
					_, err = f.d.GetEnvironmentPublisherGrant(ctx, request.InspectEnvironmentPublisherGrantRequest)
				case "revoke":
					err = f.d.RevokeEnvironmentPublisherGrant(ctx, RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: request.EnvironmentPublisherGrantMutation, GrantID: grant})
				default:
					_, err = f.d.AuthorizeEnvironmentPublisherService(ctx, request)
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
			if _, err := gate.Exec(ctx, `UPDATE control.team_memberships SET role='member' WHERE team_id=$1 AND identity_id=$2`, f.r.TeamID, session.Identity.Identity.ID); err != nil {
				t.Fatal(err)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("queued operation reused the manager's earlier role", err)
			}
			if !bytes.Equal(before, environmentPublisherGrantFacts(t, f)) {
				t.Fatal("denied queued operation changed authority, receipt, audit, health or runs")
			}
		})
	}
}

func TestIntegrationEnvironmentPublisherGrantsSessionAndFixedDeadlineWaits(t *testing.T) {
	for _, test := range []struct{ change, operation, boundary string }{
		{"revoke", "new", "service"},
		{"revoke", "revoke", "service"},
		{"rotate", "noop", "service"},
		{"deadline", "replay", "service"},
		{"deadline", "inspect", "service"},
		{"deadline", "new", "session"},
	} {
		t.Run(test.change+"/"+test.operation+"/"+test.boundary, func(t *testing.T) {
			f := newEnvironmentPublisherGrantFixture(t)
			f.grow(t)
			request := f.request("waiting-intent")
			var grant string
			if test.operation == "replay" || test.operation == "noop" || test.operation == "revoke" {
				created, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request)
				if err != nil {
					t.Fatal(err)
				}
				grant = created.Grant.ID
				if test.operation == "noop" {
					request.IdempotencyKey = "waiting-noop-intent"
					request.ExpectedPreviousGrantID = environmentPublisherGrantExpected(t, grant)
				}
			}
			if test.change == "deadline" {
				if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, f.session.SessionID, time.Now().Add(2*time.Second)); err != nil {
					t.Fatal(err)
				}
				manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), f.session.AccessToken)
				if err != nil {
					t.Fatal(err)
				}
				request.Manager = manager
			}
			before := environmentPublisherGrantFacts(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := f.d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if test.boundary == "service" {
				_, err = controlstatedb.New(gate).LockService(ctx, f.metrics.ServiceID)
			} else {
				_, err = gate.Exec(ctx, `SELECT id FROM control.control_sessions WHERE id=$1 FOR UPDATE`, f.session.SessionID)
			}
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch test.operation {
				case "inspect":
					_, err = f.d.GetEnvironmentPublisherGrant(ctx, request.InspectEnvironmentPublisherGrantRequest)
				case "revoke":
					err = f.d.RevokeEnvironmentPublisherGrant(ctx, RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: request.EnvironmentPublisherGrantMutation, GrantID: grant})
				default:
					_, err = f.d.AuthorizeEnvironmentPublisherService(ctx, request)
				}
				done <- err
			})
			pid := waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
			if test.boundary == "session" {
				var query string
				if err := f.d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil || !strings.Contains(query, "FOR SHARE OF session") {
					t.Fatal("operation did not reach its final session-lock check", query, err)
				}
			}
			switch test.change {
			case "revoke":
				if err := f.d.RevokeControlSession(ctx, ControlPrincipal{SessionID: f.session.SessionID, IdentityID: f.r.ActorID}, time.Now()); err != nil {
					t.Fatal(err)
				}
			case "rotate":
				if _, err := f.d.RefreshControlSession(ctx, f.session.RefreshToken, time.Hour, time.Now()); err != nil {
					t.Fatal(err)
				}
			case "deadline":
				// extend the database row while the request is blocked. the exact
				// credential captured by this request must keep its old deadline.
				if test.boundary == "session" {
					_, err = gate.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, f.session.SessionID, time.Now().Add(time.Hour))
				} else {
					_, err = f.d.pool.Exec(ctx, `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, f.session.SessionID, time.Now().Add(time.Hour))
				}
				if err != nil {
					t.Fatal(err)
				}
				timer := time.NewTimer(time.Until(request.Manager.deadline))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrControlAuthentication) {
				t.Fatal("operation reused revoked, rotated or expired session authority after waiting", err)
			}
			if !bytes.Equal(before, environmentPublisherGrantFacts(t, f)) {
				t.Fatal("expired operation partially saved grants, receipts, audit, health or runs")
			}
		})
	}
}

func TestIntegrationEnvironmentPublisherGrantsIssuerDoesNotOwnPublisherLifetime(t *testing.T) {
	f := newEnvironmentPublisherGrantFixture(t)
	f.grow(t)
	session := f.managerSession(t, TeamRoleAdmin)
	manager, err := f.d.AuthenticateEnvironmentPublisherManager(t.Context(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	request := f.request("manager-approved-metrics")
	request.Manager = manager
	created, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	run, access := f.start(t, f.publisher, "metrics", "issuer-independent-metrics")
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.team_memberships SET role='member' WHERE team_id=$1 AND identity_id=$2`, f.r.TeamID, session.Identity.Identity.ID); err != nil {
		t.Fatal(err)
	}
	if err := f.d.RevokeControlSession(t.Context(), ControlPrincipal{SessionID: session.SessionID, IdentityID: session.Identity.Identity.ID}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AuthorizeEnvironmentPublisherService(t.Context(), request); !errors.Is(err, ErrControlAuthentication) {
		t.Fatal("revoked manager session replayed a receipt", err)
	}
	if _, err := f.d.AuthenticatePublisherAccess(t.Context(), access.Token, "", f.now); err != nil {
		t.Fatal("installed publisher depended on the grant issuer's session", err)
	}
	if _, err := f.d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, f.now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal("installed publication depended on the grant issuer's current role", err)
	}
	for _, assignment := range f.assignments(t, f.publisher).Services {
		if assignment.ServiceID == f.metrics.ServiceID {
			if assignment.GrantID != created.Grant.ID {
				t.Fatal("issuer departure replaced installed authority")
			}
			environmentAssignmentAccess(t, f.d, f.publisher, assignment, f.now)
			return
		}
	}
	t.Fatal("issuer departure removed the existing publisher assignment")
}

func TestIntegrationEnvironmentPublisherGrantsConcurrentIntent(t *testing.T) {
	for _, sameIntent := range []bool{true, false} {
		name := "competing-intents"
		if sameIntent {
			name = "same-intent"
		}
		t.Run(name, func(t *testing.T) {
			f := newEnvironmentPublisherGrantFixture(t)
			f.grow(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			workers := newIntegrationWorkers(t, cancel)
			gate, err := f.d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockLocalTeamForMutation(ctx, f.r.TeamID); err != nil {
				t.Fatal(err)
			}
			type outcome struct {
				result EnvironmentPublisherGrantAuthorization
				err    error
			}
			results := make(chan outcome, 2)
			done := make(chan error, 2)
			for i := range 2 {
				request := f.request("concurrent-intent")
				if !sameIntent && i == 1 {
					request.IdempotencyKey = "other-concurrent-intent"
				}
				workers.Go(func() {
					result, err := f.d.AuthorizeEnvironmentPublisherService(ctx, request)
					results <- outcome{result, err}
					done <- err
				})
			}
			firstPID := waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
			tick := time.NewTicker(time.Millisecond)
			defer tick.Stop()
			for {
				var waiting int
				if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND pg_blocking_pids(pid) && $1::integer[]`, []int32{int32(gate.Conn().PgConn().PID()), firstPID}).Scan(&waiting); err != nil {
					t.Fatal(err)
				}
				if waiting == 2 {
					break
				}
				select {
				case <-tick.C:
				case <-ctx.Done():
					t.Fatal("concurrent requests did not both reach the team guard", ctx.Err())
				}
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			created, conflicts := 0, 0
			var grant string
			for range 2 {
				out := awaitIntegrationResult(t, ctx, results)
				if out.err != nil {
					if !errors.Is(out.err, ErrEnvironmentPublisherGrantConflict) {
						t.Fatal(out.err)
					}
					conflicts++
					continue
				}
				if out.result.Created {
					created++
				}
				if grant != "" && out.result.Grant.ID != grant {
					t.Fatal("concurrent replay produced another grant")
				}
				grant = out.result.Grant.ID
			}
			if created != 1 || sameIntent && conflicts != 0 || !sameIntent && conflicts != 1 {
				t.Fatal("intent/CAS race did not have exactly one creation", created, conflicts)
			}
			var count int
			if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1 AND service_id=$2`, f.publisher.member.PublisherIdentityID, f.metrics.ServiceID).Scan(&count); err != nil || count != 1 {
				t.Fatal("concurrent intent leaked a grant", count, err)
			}
		})
	}
}
