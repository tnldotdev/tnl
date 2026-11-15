package state

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationPublisherVisitorPolicyDoesNotSerializeVisitorCapacity(t *testing.T) {
	for _, gateKind := range []string{"visitor-authorization", "other-ingress-admission"} {
		t.Run(gateKind, func(t *testing.T) {
			f := newNativeServiceAdmissionFixture(t)
			d, now, source := f.database, f.now, netip.MustParseAddr("192.0.2.30")
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
			certificate := newServiceAdmissionCertificate(t, f)
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			firstIngress := registerNativeServiceAdmissionIngress(t, ctx, f, "admission-lock-first")
			secondIngress := registerNativeServiceAdmissionIngress(t, ctx, f, "admission-lock-second")
			firstVisitor, secondVisitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
			admit := func(call context.Context, ingress IngressLease, visitor string) (PublicServiceVisitorAdmission, error) {
				return d.AdmitPublicServiceVisitor(call, ingress.IngressLeaseIdentity, PrimaryIngressPoolID,
					visitor, f.service.Endpoint.Port, source, now)
			}
			// both visitors have real ready service/run bindings. the second is
			// always on another ingress, with no row or lease held by the gate.
			if _, err := admit(ctx, secondIngress, secondVisitor); err != nil {
				t.Fatal(err)
			}
			if gateKind == "visitor-authorization" {
				if _, err := admit(ctx, firstIngress, firstVisitor); err != nil {
					t.Fatal(err)
				}
			}
			authorize := func(visitor string) (ServiceVisitorValidity, error) {
				return d.AuthorizeServiceClientCertificate(ctx, f.service.ID, f.run.RunID, f.run.Token, visitor,
					f.run.RunNumber, source, f.service.Endpoint.Port, certificate, now)
			}
			before, err := authorize(secondVisitor)
			if err != nil || !before.Allowed || before.Admitted {
				t.Fatal("unblocked authorization fixture", before, err)
			}
			policyBefore, err := d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
			if err != nil {
				t.Fatal("unblocked policy fixture", err)
			}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if gateKind == "visitor-authorization" {
				_, err = gate.Exec(ctx, `SELECT visitor_connection_id FROM control.public_service_visitors WHERE visitor_connection_id=$1 FOR UPDATE`, firstVisitor)
			} else {
				_, err = gate.Exec(ctx, `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE`, firstIngress.IngressID)
			}
			if err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			first := make(chan error, 1)
			workers.Go(func() {
				if gateKind == "visitor-authorization" {
					_, err := authorize(firstVisitor)
					first <- err
				} else {
					_, err := admit(ctx, firstIngress, firstVisitor)
					first <- err
				}
			})
			firstPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), first)
			var firstQuery string
			if err := d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, firstPID).Scan(&firstQuery); err != nil {
				t.Fatal(err)
			}
			expected := "UPDATE control.public_service_visitors SET identity_id="
			if gateKind == "other-ingress-admission" {
				expected = "-- name: LockIngressLease"
			}
			if !strings.Contains(firstQuery, expected) {
				t.Fatalf("first operation blocked at an unexpected dependency: %s", firstQuery)
			}
			t.Logf("backend %d waits on gate %d: %s", firstPID, gate.Conn().PgConn().PID(), strings.Join(strings.Fields(firstQuery), " "))
			second := make(chan error, 1)
			var policyAfter controlv1.VisitorPolicyUpdate
			workers.Go(func() {
				var err error
				policyAfter, err = d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
				second <- err
			})
			blockedQuery := observePublisherVisitorPolicyProgress(t, ctx, d, firstPID, second)
			if blockedQuery != "" {
				t.Errorf("read-only publisher policy blocked behind %s at: %s", gateKind, blockedQuery)
			}
			// release and join both calls even when the regression fails, so a
			// lock-scope failure cannot hide worker or transaction cleanup errors.
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, first); err != nil {
				t.Fatal(err)
			}
			if blockedQuery != "" {
				if err := awaitIntegrationResult(t, ctx, second); err != nil {
					t.Fatal(err)
				}
			}
			if policyAfter.Policy.Resource != policyBefore.Policy.Resource ||
				policyAfter.Policy.Hostname != policyBefore.Policy.Hostname ||
				policyAfter.Policy.VisitorPolicyRevision != policyBefore.Policy.VisitorPolicyRevision ||
				policyAfter.Policy.KeyRevision != policyBefore.Policy.KeyRevision ||
				!policyAfter.Policy.ValidUntil.Equal(policyBefore.Policy.ValidUntil) {
				t.Fatal("capacity contention changed policy authority or its fixed observation deadline", policyBefore, policyAfter)
			}
			var after ServiceVisitorValidity
			var promoted bool
			if err := d.pool.QueryRow(ctx, `SELECT identity_id IS NOT NULL,promoted_at IS NOT NULL,valid_until
				FROM control.public_service_visitors WHERE visitor_connection_id=$1`, secondVisitor).
				Scan(&after.Allowed, &promoted, &after.ValidUntil); err != nil {
				t.Fatal(err)
			}
			if !after.Allowed || promoted || !after.ValidUntil.Equal(before.ValidUntil) {
				t.Fatal("policy observation changed the existing visitor's deadline or promotion state", before, after)
			}
			var reserved, authorized int
			if err := d.pool.QueryRow(ctx, `SELECT count(*),count(identity_id) FROM control.public_service_visitors
				WHERE service_id=$1 AND service_run_id=$2 AND closed_at IS NULL AND valid_until>$3`,
				f.service.ID, f.run.RunID, now).Scan(&reserved, &authorized); err != nil {
				t.Fatal(err)
			}
			wantAuthorized := 2
			if gateKind == "other-ingress-admission" {
				wantAuthorized = 1
			}
			if reserved != 2 || authorized != wantAuthorized {
				t.Fatalf("visitor-specific authorization changed capacity: reserved=%d authorized=%d", reserved, authorized)
			}
		})
	}
}

func TestIntegrationPublisherVisitorPolicyRetainsAuthorityAndRunGuards(t *testing.T) {
	for _, operation := range []string{"service-disable", "run-close", "run-renewal"} {
		t.Run(operation, func(t *testing.T) {
			f := newPublicServiceHTTPAdmissionFixture(t)
			d, now := f.database, f.now
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			// stop the actual observation after it holds owner, service, and
			// run authority. this table lock changes no policy or serving fact.
			if _, err := gate.Exec(ctx, `LOCK TABLE control.visitor_policy_events IN ACCESS EXCLUSIVE MODE`); err != nil {
				t.Fatal(err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			observed := make(chan error, 1)
			var observation controlv1.VisitorPolicyUpdate
			workers.Go(func() {
				var err error
				observation, err = d.ReadPublisherVisitorPolicy(ctx, f.auth().Subject, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
				observed <- err
			})
			observerPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), observed)
			assertServiceHTTPAdmissionBlockedQuery(t, ctx, d, observerPID, "-- name: ReadVisitorPolicyEvents")
			written := make(chan error, 1)
			workers.Go(func() {
				var err error
				switch operation {
				case "service-disable":
					_, err = d.SetServiceEnabled(ctx, f.service.ID, f.project.ActorID, false, now)
				case "run-close":
					err = d.CloseServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token, now)
				case "run-renewal":
					_, err = d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token,
						now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64})
				}
				written <- err
			})
			writerPID := waitForPostgresBlock(t, ctx, d, observerPID, written)
			expected := "FOR UPDATE"
			if operation == "service-disable" {
				expected = "-- name: LockLocalTeamForMutation"
			}
			if operation == "run-renewal" {
				expected = "-- name: LockServiceRun"
			}
			assertServiceHTTPAdmissionBlockedQuery(t, ctx, d, writerPID, expected)
			var enabled, closed bool
			var expires time.Time
			if err := d.pool.QueryRow(ctx, `SELECT s.enabled,r.closed_at IS NOT NULL,r.publisher_expires_at
				FROM control.services s JOIN control.service_runs r ON r.service_id=s.id WHERE s.id=$1 AND r.id=$2`,
				f.service.ID, f.run.RunID).Scan(&enabled, &closed, &expires); err != nil {
				t.Fatal(err)
			}
			if !enabled || closed || !expires.Equal(f.run.ExpiresAt) {
				t.Fatal("writer changed authority before the observation released its guards", enabled, closed, expires)
			}
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, observed); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, written); err != nil {
				t.Fatal(err)
			}
			if !observation.Policy.Enabled {
				t.Fatal("observation lost the authority it held before the writer")
			}
			_, err = d.ReadPublisherVisitorPolicy(ctx, f.auth().Subject, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
			if operation == "run-renewal" {
				if err != nil {
					t.Fatal("renewal invalidated current run authority", err)
				}
				if err := d.pool.QueryRow(ctx, `SELECT publisher_expires_at FROM control.service_runs WHERE id=$1`, f.run.RunID).
					Scan(&expires); err != nil || !expires.Equal(now.Add(46*time.Second)) {
					t.Fatal("joined renewal did not durably extend the exact run", expires, err)
				}
			} else if !errors.Is(err, ErrServiceAccess) {
				t.Fatal("observation reused revoked service/run authority", err)
			}
		})
	}
}

func TestIntegrationPublicServiceVisitorCapacityWritersSerialize(t *testing.T) {
	for _, firstOperation := range []string{"admission", "authorization", "status"} {
		for _, secondOperation := range []string{"admission", "authorization", "status"} {
			t.Run(firstOperation+"/"+secondOperation, func(t *testing.T) {
				f := newNativeServiceAdmissionFixture(t)
				d, now, source := f.database, f.now, netip.MustParseAddr("192.0.2.30")
				certificate := newServiceAdmissionCertificate(t, f)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				defer cancel()
				firstIngress := registerNativeServiceAdmissionIngress(t, ctx, f, "capacity-first")
				secondIngress := registerNativeServiceAdmissionIngress(t, ctx, f, "capacity-second")
				firstVisitor, secondVisitor := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
				firstNew, secondNew := mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), mustOpaqueID(t, opaqueid.VisitorConnectionPrefix)
				admit := func(ingress IngressLease, visitor string) (PublicServiceVisitorAdmission, error) {
					return d.AdmitPublicServiceVisitor(ctx, ingress.IngressLeaseIdentity, PrimaryIngressPoolID,
						visitor, f.service.Endpoint.Port, source, now)
				}
				authorize := func(visitor string) (ServiceVisitorValidity, error) {
					return d.AuthorizeServiceClientCertificate(ctx, f.service.ID, f.run.RunID, f.run.Token, visitor,
						f.run.RunNumber, source, f.service.Endpoint.Port, certificate, now)
				}
				for _, visitor := range []struct {
					ingress IngressLease
					id      string
				}{{firstIngress, firstVisitor}, {secondIngress, secondVisitor}} {
					if _, err := admit(visitor.ingress, visitor.id); err != nil {
						t.Fatal(err)
					}
					if _, err := authorize(visitor.id); err != nil {
						t.Fatal(err)
					}
				}
				var originalDeadline time.Time
				if err := d.pool.QueryRow(ctx, `SELECT valid_until FROM control.public_service_visitors
					WHERE visitor_connection_id=$1`, firstVisitor).Scan(&originalDeadline); err != nil {
					t.Fatal(err)
				}
				// renewal makes an actual validity extension available to both
				// existing visitors; pending new visitors still count as capacity.
				capacity := int32(64)
				lastSlot := firstOperation == "admission" && secondOperation == "admission"
				if lastSlot {
					capacity = 3
				}
				if _, err := d.HeartbeatServiceRun(ctx, f.service.ID, f.run.RunID, f.run.Token,
					now.Add(30*time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: capacity}); err != nil {
					t.Fatal(err)
				}
				gate, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if firstOperation == "admission" {
					_, err = gate.Exec(ctx, `SELECT ingress_id FROM control.ingress_leases WHERE ingress_id=$1 FOR UPDATE`, firstIngress.IngressID)
				} else {
					_, err = gate.Exec(ctx, `SELECT visitor_connection_id FROM control.public_service_visitors WHERE visitor_connection_id=$1 FOR UPDATE`, firstVisitor)
				}
				if err != nil {
					t.Fatal(err)
				}
				write := func(operation string, ingress IngressLease, visitor, newVisitor string) (time.Time, error) {
					switch operation {
					case "admission":
						admission, err := admit(ingress, newVisitor)
						return admission.ExpiresAt, err
					case "authorization":
						validity, err := authorize(visitor)
						if err == nil && (!validity.Allowed || validity.Admitted) {
							err = fmt.Errorf("authorization changed permission/promotion state: %+v", validity)
						}
						return validity.ValidUntil, err
					case "status":
						status, err := d.PublicServiceVisitorStatus(ctx, ingress.IngressLeaseIdentity, visitor, now)
						if err == nil && status.State != PublicServiceVisitorAuthenticated {
							err = fmt.Errorf("status lost the authorized, unpromoted visitor: %+v", status)
						}
						return status.ValidUntil, err
					default:
						return time.Time{}, fmt.Errorf("unexpected capacity operation: %s", operation)
					}
				}
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				first := make(chan error, 1)
				var firstDeadline, secondDeadline time.Time
				workers.Go(func() {
					var err error
					firstDeadline, err = write(firstOperation, firstIngress, firstVisitor, firstNew)
					first <- err
				})
				firstPID := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), first)
				expected := "-- name: LockIngressLease"
				if firstOperation == "authorization" {
					expected = "UPDATE control.public_service_visitors SET identity_id="
				} else if firstOperation == "status" {
					expected = "UPDATE control.public_service_visitors SET identity_id="
				}
				assertServiceHTTPAdmissionBlockedQuery(t, ctx, d, firstPID, expected)
				second := make(chan error, 1)
				workers.Go(func() {
					var err error
					secondDeadline, err = write(secondOperation, secondIngress, secondVisitor, secondNew)
					second <- err
				})
				secondPID := waitForPostgresBlock(t, ctx, d, firstPID, second)
				assertServiceHTTPAdmissionBlockedQuery(t, ctx, d, secondPID,
					"SELECT id FROM control.services WHERE id = $1 AND enabled AND deleted_at IS NULL FOR NO KEY UPDATE")
				var reserved int
				var untouchedDeadline time.Time
				if err := d.pool.QueryRow(ctx, `SELECT
					(SELECT count(*) FROM control.service_visitor_capacity WHERE service_run_id=$1 AND closed_at IS NULL AND valid_until>$2),
					(SELECT valid_until FROM control.public_service_visitors WHERE visitor_connection_id=$3)`,
					f.run.RunID, now, secondVisitor).Scan(&reserved, &untouchedDeadline); err != nil {
					t.Fatal(err)
				}
				if reserved != 2 || !untouchedDeadline.Equal(originalDeadline) {
					t.Fatal("waiting capacity writer changed reservations or validity", reserved, untouchedDeadline)
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, first); err != nil {
					t.Fatal(err)
				}
				secondErr := awaitIntegrationResult(t, ctx, second)
				if lastSlot {
					if !errors.Is(secondErr, ErrServiceAccess) {
						t.Fatal("both admissions reserved the last run capacity", secondErr)
					}
				} else if secondErr != nil {
					t.Fatal(secondErr)
				}
				if firstOperation != "admission" && !firstDeadline.After(originalDeadline) {
					t.Fatal("first capacity writer did not exercise a validity extension", originalDeadline, firstDeadline)
				}
				if secondOperation != "admission" && !secondDeadline.After(originalDeadline) {
					t.Fatal("second capacity writer did not exercise a validity extension", originalDeadline, secondDeadline)
				}
				firstStoredDeadline, secondStoredDeadline := originalDeadline, originalDeadline
				if firstOperation != "admission" {
					firstStoredDeadline = firstDeadline
				} else if !firstDeadline.Equal(now.Add(10 * time.Second)) {
					t.Fatal("admission lock wait changed the fixed setup deadline", firstDeadline)
				}
				if secondOperation != "admission" {
					secondStoredDeadline = secondDeadline
				} else if !lastSlot && !secondDeadline.Equal(now.Add(10*time.Second)) {
					t.Fatal("queued admission changed the fixed setup deadline", secondDeadline)
				}
				var storedFirst, storedSecond time.Time
				if err := d.pool.QueryRow(ctx, `SELECT
					(SELECT valid_until FROM control.public_service_visitors WHERE visitor_connection_id=$1),
					(SELECT valid_until FROM control.public_service_visitors WHERE visitor_connection_id=$2)`,
					firstVisitor, secondVisitor).Scan(&storedFirst, &storedSecond); err != nil {
					t.Fatal(err)
				}
				if !storedFirst.Equal(firstStoredDeadline) || !storedSecond.Equal(secondStoredDeadline) {
					t.Fatal("joined capacity writes did not durably preserve their exact validity", storedFirst, storedSecond)
				}
				wantReserved := 2
				if firstOperation == "admission" {
					wantReserved++
				}
				if secondOperation == "admission" && !lastSlot {
					wantReserved++
				}
				var authorized, promoted int
				if err := d.pool.QueryRow(ctx, `SELECT count(*),count(identity_id),count(promoted_at)
					FROM control.public_service_visitors WHERE service_run_id=$1 AND closed_at IS NULL AND valid_until>$2`,
					f.run.RunID, now).Scan(&reserved, &authorized, &promoted); err != nil {
					t.Fatal(err)
				}
				if reserved != wantReserved || authorized != 2 || promoted != 0 {
					t.Fatal("serialized writes changed capacity or promotion accounting", reserved, authorized, promoted)
				}
			})
		}
	}
}

func newNativeServiceAdmissionFixture(t *testing.T) servicePublicationFixture {
	t.Helper()
	d, now, project, _, service := serviceReleaseProject(t, "tcp", false)
	if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	f := servicePublicationFixture{database: d, now: now, service: service,
		publisher: serviceReleasePublisher(t, d, project, now), leases: make(map[string]RelayLease)}
	rows, err := d.pool.Query(t.Context(), `SELECT relay_service_id,relay_id,relay_run_id,relay_lease_revision,lease_expires_at FROM control.relay_leases`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var lease RelayLease
		if err := rows.Scan(&lease.RelayServiceID, &lease.RelayID, &lease.RelayRunID, &lease.RelayLeaseRevision, &lease.LeaseExpiresAt); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		f.leases[lease.RelayServiceID] = lease
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	f.start(t, "capacity", now)
	prepareServingPublisher(t, f)
	return f
}

func registerNativeServiceAdmissionIngress(t *testing.T, ctx context.Context, f servicePublicationFixture, id string) IngressLease {
	t.Helper()
	lease, err := f.database.RegisterIngress(ctx, IngressRegistration{
		IngressID: id, IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, ServicePorts: []int32{int32(f.service.Endpoint.Port)},
		ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func newServiceAdmissionCertificate(t *testing.T, f servicePublicationFixture) []byte {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	actor := f.actor(t)
	device, err := f.database.EnrollVisitorDevice(t.Context(), actor, public, f.now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := f.database.IssueServiceClientCertificate(t.Context(), f.service.ID, actor, device.ID, csr, f.now)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(certificate.CertificatePEM))
	if block == nil {
		t.Fatal("missing service admission certificate")
	}
	return block.Bytes
}

func newPublicServiceHTTPAdmissionFixture(t *testing.T) serviceHTTPFixture {
	t.Helper()
	f := newServiceHTTPFixture(t)
	local, err := f.database.RealizeLocalProjectService(t.Context(), RealizeLocalProjectServiceRequest{
		TeamID: f.project.TeamID, ActorID: f.project.ActorID, ProjectKey: f.project.ProjectKey,
		SourceFingerprint: f.project.SourceFingerprint, Service: "web", WorktreeKey: "review",
		Configuration: ProjectServiceConfiguration{Target: "localhost:3000", Public: new(true)}, Now: f.now,
	})
	if err != nil {
		t.Fatal(err)
	}
	f.service, err = f.database.GetService(t.Context(), local.ServiceID, f.project.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	f.run = f.publish(t, f.service)
	return f
}

func registerServiceHTTPAdmissionIngress(t *testing.T, ctx context.Context, f serviceHTTPFixture, id string) IngressLease {
	t.Helper()
	lease, err := f.database.RegisterIngress(ctx, IngressRegistration{
		IngressID: id, IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, HTTPS: true, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
	}, f.now, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	return lease
}

func assertServiceHTTPAdmissionBlockedQuery(t *testing.T, ctx context.Context, d *Database, pid int32, expected string) {
	t.Helper()
	var query string
	if err := d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity WHERE pid=$1`, pid).Scan(&query); err != nil {
		t.Fatal(err)
	}
	query = strings.Join(strings.Fields(query), " ")
	if !strings.Contains(query, expected) {
		t.Fatalf("backend %d blocked at an unexpected boundary: %s", pid, query)
	}
	t.Logf("backend %d waits at: %s", pid, query)
}

// observe either completion or a demonstrated dependency, without using a
// scheduling delay as proof that the second operation reached its guard.
func observePublisherVisitorPolicyProgress(t *testing.T, ctx context.Context, d *Database, blocker int32, done <-chan error) string {
	t.Helper()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return ""
		default:
		}
		var query string
		err := d.pool.QueryRow(ctx, `SELECT query FROM pg_stat_activity
			WHERE datname=current_database() AND $1=ANY(pg_blocking_pids(pid))`, blocker).Scan(&query)
		if err == nil {
			return strings.Join(strings.Fields(query), " ")
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatal(err)
		}
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return ""
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-tick.C:
		}
	}
}
