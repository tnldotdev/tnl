package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationPublisherAllocationRejectsUnrelatedExactServiceEnrollment(t *testing.T) {
	for _, kind := range []string{"namespace", "deployment"} {
		t.Run(kind, func(t *testing.T) {
			var d *Database
			var now time.Time
			var root PublisherIdentity
			var service ServiceRecord
			if kind == "namespace" {
				d, now = newControlStateIntegrationDatabase(t, "allocation_exact_enrollment")
				r := oidcRouteRequest(t, d, now)
				enrollment := publisherEnrollment(t, d, r, PublisherScope{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID}, now)
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				root, err = d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
				if err != nil {
					t.Fatal(err)
				}
				service, err = d.AllocatePublisherService(t.Context(), root, AllocateServiceRequest{Invocation: mustOpaqueID(t, opaqueid.InvocationPrefix), Configuration: ProjectServiceConfiguration{Target: "localhost:3000"}}, now)
				if err != nil {
					t.Fatal(err)
				}
			} else {
				f := newDeploymentPublicationFixture(t)
				d, now = f.d, f.now
				_, _, access, _ := f.approve(t, nil, "restricted")
				root = access.PublisherIdentity
				var err error
				service, err = d.AllocateDeploymentPublication(t.Context(), f.allocation(t, access))
				if err != nil {
					t.Fatal(err)
				}
			}
			member, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: service.TeamID, IdentityID: root.CreatorID})
			if err != nil {
				t.Fatal(err)
			}
			enrollment, err := d.IssuePublisherEnrollment(t.Context(), CreatePublisherEnrollmentRequest{
				Scope: PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID},
				Name:  "unrelated-exact", Kind: "installed", EditorID: root.CreatorID,
				EditorMembershipID: member.ActorMembershipID, PolicyRevision: uint64(member.PolicyRevision), Now: now,
			})
			if errors.Is(err, ErrPublisherIdentity) || errors.Is(err, ErrServiceAccess) || errors.Is(err, ErrProjectManaged) {
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			public, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			exact, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.RevokePublisherGrant(t.Context(), service.TeamID, root.ID, root.GrantID, root.CreatorID, now); err != nil {
				t.Fatal(err)
			}
			if _, err := d.GetServiceForPublisher(t.Context(), service.ID, exact, now); err == nil {
				t.Fatal("fresh human-issued exact-service enrollment bypassed revoked allocation root authority")
			}
		})
	}
}

func TestIntegrationPublisherAllocationRejectsUnrelatedExactServiceGrant(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "allocation_exact_grant")
	r := oidcRouteRequest(t, d, now)
	enrollment := publisherEnrollment(t, d, r, PublisherScope{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.AllocatePublisherService(t.Context(), root, AllocateServiceRequest{Invocation: mustOpaqueID(t, opaqueid.InvocationPrefix), Configuration: ProjectServiceConfiguration{Target: "localhost:3000"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	member, err := controlstatedb.New(d.pool).GetTeamActorContext(t.Context(), controlstatedb.GetTeamActorContextParams{TeamID: r.TeamID, IdentityID: r.ActingIdentityID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreatePublisherGrant(t.Context(), CreatePublisherGrantRequest{
		PublisherIdentityID: root.ID, Scope: PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: service.ID},
		EditorID: r.ActingIdentityID, EditorMembershipID: member.ActorMembershipID, PolicyRevision: uint64(member.PolicyRevision), Now: now,
	}); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("human management created a replacement exact-service allocation root", err)
	}
	// simulate a previously persisted exact grant to exercise the SQL fence
	// independently of the creation guard. this is not an allocation code path.
	staleID := mustOpaqueID(t, opaqueid.PublisherGrantPrefix)
	if _, err := controlstatedb.New(d.pool).InsertPublisherGrant(t.Context(), controlstatedb.InsertPublisherGrantParams{
		ID: staleID, PublisherIdentityID: root.ID, CreatedByIdentityID: text(r.ActingIdentityID),
		Kind: "service", ServiceID: text(service.ID), CreatedAt: timestamptz(now),
	}); err != nil {
		t.Fatal(err)
	}
	stale := root
	stale.GrantID, stale.Scope = staleID, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: service.ID}
	if _, err := d.GetServiceForPublisher(t.Context(), service.ID, stale, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("persisted exact grant bypassed the allocation's original root", err)
	}
}

func TestIntegrationDeploymentAllocationDeadlineAfterDeferredConstraints(t *testing.T) {
	testAllocationDeferredDeadline(t, false, false)
}

func TestIntegrationPublisherAllocationDeadlineAfterDeferredConstraints(t *testing.T) {
	testAllocationDeferredDeadline(t, true, false)
}

func TestIntegrationPublisherAllocationDeletionDeadlineAfterDeferredConstraints(t *testing.T) {
	for _, namespace := range []bool{false, true} {
		name := "deployment"
		if namespace {
			name = "namespace"
		}
		t.Run(name, func(t *testing.T) { testAllocationDeferredDeadline(t, namespace, true) })
	}
}

func testAllocationDeferredDeadline(t *testing.T, namespace, deletion bool) {
	t.Helper()
	for _, boundary := range []string{"grant", "caller"} {
		t.Run(boundary, func(t *testing.T) {
			f := newDeploymentPublicationFixture(t)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			var publisher PublisherIdentity
			var allocate func(AllocateServiceRequest) (ServiceRecord, error)
			if namespace {
				deployment, err := controlstatedb.New(f.d.pool).LockDeploymentByID(ctx, f.production.ID)
				if err != nil {
					t.Fatal(err)
				}
				actor := serviceTestAuthority{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID, DomainID: deployment.DomainID.String}
				enrollment := publisherEnrollment(t, f.d, actor, PublisherScope{Kind: "namespace", TeamID: actor.TeamID, DomainID: actor.DomainID}, f.now)
				public, _, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				publisher, err = f.d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, f.now)
				if err != nil {
					t.Fatal(err)
				}
				allocate = func(r AllocateServiceRequest) (ServiceRecord, error) {
					return f.d.AllocatePublisherService(ctx, publisher, r, f.now)
				}
			} else {
				_, _, access, _ := f.approve(t, nil, "restricted")
				publisher = access.PublisherIdentity
				allocate = func(r AllocateServiceRequest) (ServiceRecord, error) {
					return f.d.AllocateDeploymentPublication(ctx, AllocateDeploymentPublicationRequest{DeploymentScope: f.scope(access), Deployment: f.production.ID, AllocateServiceRequest: r, Now: f.now})
				}
			}
			request := AllocateServiceRequest{Invocation: mustOpaqueID(t, opaqueid.InvocationPrefix), Configuration: ProjectServiceConfiguration{Target: "localhost:3000"}}
			deadline := f.now.Add(200 * time.Millisecond)
			if boundary == "caller" {
				request.ExpiresAt = &deadline
			} else if _, err := f.d.pool.Exec(ctx, `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, publisher.GrantID, deadline); err != nil {
				t.Fatal(err)
			}
			var service ServiceRecord
			if deletion {
				var err error
				service, err = allocate(request)
				if err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() []byte {
				t.Helper()
				var data []byte
				if err := f.d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
					'services',(SELECT COALESCE(jsonb_agg(to_jsonb(service) ORDER BY service.id),'[]'::jsonb) FROM control.services service WHERE team_id=$1),
					'allocations',(SELECT COALESCE(jsonb_agg(to_jsonb(allocation) ORDER BY allocation.service_id),'[]'::jsonb) FROM control.publisher_namespace_allocations allocation JOIN control.services service ON service.id=allocation.service_id WHERE service.team_id=$1),
					'endpoints',(SELECT COALESCE(jsonb_agg(to_jsonb(endpoint) ORDER BY endpoint.hostname),'[]'::jsonb) FROM control.service_endpoints endpoint JOIN control.services service ON service.id=endpoint.service_id WHERE service.team_id=$1),
					'audit',(SELECT COALESCE(jsonb_agg(to_jsonb(event) ORDER BY event.id),'[]'::jsonb) FROM control.service_audit_events event WHERE team_id=$1))`, f.project.TeamID).Scan(&data); err != nil {
					t.Fatal(err)
				}
				return data
			}
			before := snapshot()
			gate, err := f.d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(7465)`); err != nil {
				t.Fatal(err)
			}
			trigger := `CREATE CONSTRAINT TRIGGER allocation_deadline_wait AFTER INSERT ON control.publisher_namespace_allocations`
			if deletion {
				trigger = `CREATE CONSTRAINT TRIGGER allocation_deadline_wait AFTER UPDATE ON control.services`
			}
			if _, err = f.d.pool.Exec(ctx, `CREATE FUNCTION control.allocation_deadline_wait() RETURNS trigger LANGUAGE plpgsql AS $$
				BEGIN PERFORM pg_advisory_xact_lock(7465); RETURN NEW; END $$;
				`+trigger+`
				DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.allocation_deadline_wait()`); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			entered := make(chan time.Time, 1)
			workers.Go(func() {
				entered <- time.Now()
				if deletion {
					done <- f.d.DeletePublisherService(ctx, publisher, service.ID, f.now)
					return
				}
				result, err := allocate(request)
				if err != nil && result.ID != "" {
					err = errors.Join(err, errors.New("denied allocation returned a service"))
				}
				done <- err
			})
			waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
			started := awaitIntegrationResult(t, ctx, entered)
			timer := time.NewTimer(max(0, time.Until(started.Add(250*time.Millisecond))))
			defer timer.Stop()
			select {
			case <-timer.C:
			case <-ctx.Done():
				t.Fatal(context.Cause(ctx))
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrPublisherIdentity) && !errors.Is(err, ErrServiceAccess) {
				t.Fatal("deferred constraints extended fixed allocation authority", err)
			}
			if !bytes.Equal(before, snapshot()) {
				t.Fatal("denied deferred allocation changed service, association, endpoint, protected intent, or audit rows")
			}
		})
	}
}
