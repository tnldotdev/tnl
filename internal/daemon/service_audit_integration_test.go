package tnldruntime

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	tcpconnect "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/control/maintenance"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/publisher"
	nativeauth "github.com/tnldotdev/tnl/internal/publisher/identity"
	privatepublisher "github.com/tnldotdev/tnl/internal/publisher/managed"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type auditPublicRuntimeFixture interface {
	connectors() (muxsession.Connector, muxsession.Connector)
	waitReady(*testing.T, *integrationPublisher) publisher.Event
}

func TestIntegrationServiceAuditRuntimePublic(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		t.Run(fmt.Sprintf("standalone=%t", standalone), func(t *testing.T) {
			var fixture auditPublicRuntimeFixture
			var inspect *sql.DB
			var visitor *integrationVisitor
			var process *integrationProcess
			var owner *runtimeTopology
			var identity *integrationPublishingIdentity
			var pebbleLog string
			if standalone {
				f := newStandalonePublishFixture(t, "audit-public")
				fixture, inspect, visitor, process, owner = f, f.inspect, f.visitor, f.process, f.owner
				identity, pebbleLog = f.identity, f.pebble.logPath
			} else {
				f := newSplitPublishFixture(t, "audit-public")
				fixture, inspect, visitor, process, owner = f, f.inspect, f.visitor, f.ingress, f.owner
				identity, pebbleLog = f.identity, f.pebble.logPath
			}
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "audit response") }))
			cleanupIntegrationHTTPServer(t, target, owner)
			quic, tcp := fixture.connectors()
			config := identity.publisherConfig(target.URL, quic, tcp)
			visited := make(chan string, 1)
			config.AdmitVisitor = func(_ context.Context, v publisher.Visitor) error {
				if !v.Readiness {
					select {
					case visited <- v.Header.VisitorConnectionID:
					default:
					}
				}
				return nil
			}
			handle := startOwnedIntegrationPublisher(t, owner, config, func() string { return integrationPublisherDiagnostics(inspect, pebbleLog) })
			ready := fixture.waitReady(t, handle)
			r, _ := http.NewRequest(http.MethodGet, ready.PublicURL+"/never-audit-path?private-token=never-audit-query", nil)
			response, body, err := visitor.request(r)
			if err != nil || response.StatusCode != 200 || string(body) != "audit response" {
				t.Fatalf("actual public visitor failed: %v", err)
			}
			var visitorID string
			select {
			case visitorID = <-visited:
			case <-time.After(time.Second):
				t.Fatal("real HTTP request did not reach its visitor admission hook")
			}
			visitor.transport.CloseIdleConnections()
			// the publisher closes its run before ingress's final shutdown flush.
			stopIntegrationPublisher(t, handle)
			stopIntegrationProcess(t, process)
			var pairs int
			err = inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.service_audit_events opened JOIN control.service_audit_events closed
		    ON closed.visitor_connection_id=opened.visitor_connection_id AND closed.service_id=opened.service_id AND closed.run_id=opened.run_id
		    WHERE opened.service_id=$1 AND opened.event_type='connection.open' AND opened.outcome='forwarded'
		    AND closed.event_type='connection.close' AND opened.source_ip='127.0.0.1' AND closed.source_ip=opened.source_ip
		    AND opened.visitor_connection_id=$2`, ready.PublicURLID, visitorID).Scan(&pairs)
			if err != nil || pairs < 1 {
				t.Fatalf("real public producer not flushed into audit: %d %v", pairs, err)
			}
		})
	}
}

func TestIntegrationServiceAuditRuntimePrivate(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	for _, standalone := range []bool{false, true} {
		t.Run(fmt.Sprintf("standalone=%t", standalone), func(t *testing.T) {
			opened := make(chan privateObservation, 8)
			f := newPrivateRuntimeFixture(t, standalone, opened)
			var runtimes []*ingressRuntime
			if standalone {
				runtimes = f.composed.ingresses
			} else {
				for index := range 2 {
					d := startSeparatedPrivateIngress(t, f, index, "quic", opened)
					runtimes = append(runtimes, d.ingresses[0])
				}
			}
			service, err := f.identity.routes.CreatePrivateService(t.Context(), f.identity.teamID, "audit-private", "audit-private")
			if err != nil {
				t.Fatal(err)
			}
			e, err := f.identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: service.TeamId, PrivateServiceId: &service.Id, Kind: "installed", Name: "audit-publisher"})
			if err != nil {
				t.Fatal(err)
			}
			native, identity, err := nativeauth.EnrollNative(t.Context(), f.identity.state, f.identity.routes, f.identity.authority, e.EnrollmentKey)
			if err != nil {
				t.Fatal(err)
			}
			target := startPrivateEchoTarget(t)
			quic, tcp := f.connectors()
			pubCtx, stopPub := context.WithCancel(t.Context())
			ready, pubDone := make(chan struct{}), make(chan error, 1)
			go func() {
				pubDone <- privatepublisher.Publish(pubCtx, privatepublisher.RunConfig{Control: f.identity.routes, State: f.identity.state, Access: native.Access, Identity: identity, PrivateServiceID: service.Id, Target: target.address,
					Metadata: controlv1.PrivateServiceMetadata{Protocol: service.Protocol, TargetTls: service.TargetTls, TrustRevision: service.TrustRevision, PublisherPool: service.PublisherPool}, HeartbeatInterval: 100 * time.Millisecond, Ready: func() error { close(ready); return nil }, Connect: func(ctx context.Context, bound *privatepublisher.Bound, slot uint8) (privatepublisher.SlotSession, error) {
						return bound.ConnectSlotWithTransports(ctx, slot, false, quic, tcp)
					}})
			}()
			t.Cleanup(func() {
				stopPub()
				select {
				case err := <-pubDone:
					if err != nil {
						t.Error(err)
					}
				case <-time.After(12 * time.Second):
					t.Error("publisher did not join")
				}
			})
			select {
			case <-ready:
			case <-time.After(15 * time.Second):
				t.Fatal("publisher never became ready")
			}
			person, err := f.identity.authority.IdentityContext(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			production, err := tcpconnect.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
			if err != nil {
				t.Fatal(err)
			}
			control := &separatedVisitorControl{Control: production}
			if standalone {
				control.dialAddress = f.sharedQUIC
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			visitCtx, stopVisit := context.WithCancel(t.Context())
			visitorReady, visitDone := make(chan struct{}), make(chan error, 1)
			go func() {
				visitDone <- tcpconnect.Serve(visitCtx, listener, tcpconnect.Config{Control: control, PrivateServiceID: service.Id, IdentityID: person.Identity.Id, Protocol: "tcp", TrustRevision: service.TrustRevision, ManagedTLS: service.ManagedTls, ServiceTLS: f.visitorRoots, Ready: func() error { close(visitorReady); return nil }})
			}()
			joined := false
			t.Cleanup(func() {
				stopVisit()
				if !joined {
					select {
					case err := <-visitDone:
						if err != nil {
							t.Error(err)
						}
					case <-time.After(5 * time.Second):
						t.Error("visitor did not join")
					}
				}
			})
			select {
			case <-visitorReady:
			case <-time.After(10 * time.Second):
				t.Fatal("visitor did not bind two ingresses")
			}
			probe := connectorReadinessObservation(t, opened)
			visitorIDs := []string{probe.header.VisitorConnectionID}
			var connections []net.Conn
			t.Cleanup(func() {
				for _, c := range connections {
					_ = c.Close()
				}
			})
			ids := map[string]string{}
			for i := range 2 {
				c, err := net.DialTimeout("tcp", listener.Addr().String(), time.Second)
				if err != nil {
					t.Fatal(err)
				}
				connections = append(connections, c)
				_ = c.SetDeadline(time.Now().Add(5 * time.Second))
				payload := fmt.Sprintf("private-command-never-audit-%d\n", i)
				if _, err = io.WriteString(c, payload); err != nil {
					t.Fatal(err)
				}
				reply := make([]byte, len(payload))
				if _, err = io.ReadFull(c, reply); err != nil || string(reply) != payload {
					t.Fatal("private payload did not reach target", err)
				}
				select {
				case seen := <-opened:
					ids[seen.ingress] = seen.header.VisitorConnectionID
					visitorIDs = append(visitorIDs, seen.header.VisitorConnectionID)
				case <-time.After(time.Second):
					t.Fatal("private stream not forwarded")
				}
			}
			if len(ids) != 2 {
				t.Fatalf("did not exercise both exact ingress leases: %v", ids)
			}
			for _, c := range connections {
				_ = c.Close()
			}
			stopVisit()
			select {
			case err := <-visitDone:
				joined = true
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("visitor did not join")
			}
			privateWait(t, 5*time.Second, func(ctx context.Context) (bool, error) {
				var count int
				err := f.inspect.QueryRowContext(ctx, `SELECT count(*) FROM control.private_visitor_streams WHERE private_service_id=$1 AND closed_at IS NOT NULL`, service.Id).Scan(&count)
				return count == 3, err
			})
			for _, runtime := range runtimes {
				flush, cancel := context.WithTimeout(t.Context(), 5*time.Second)
				err := runtime.audit.Close(flush)
				cancel()
				if err != nil {
					t.Fatal("private audit flush", err)
				}
			}
			for _, visitorID := range visitorIDs {
				var count int
				err = f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.service_audit_events WHERE service_id=$1 AND visitor_connection_id=$2 AND event_type IN('connection.open','connection.close') AND actor_identity_id=$3 AND publisher_identity_id=$4 AND device_id IS NOT NULL AND source_ip='127.0.0.1'`, service.Id, visitorID, person.Identity.Id, identity.ClientId).Scan(&count)
				if err != nil || count != 2 {
					t.Fatalf("real private producer not flushed: %d %v", count, err)
				}
			}
			if standalone {
				oldID := serviceaudit.NewID()
				_, err = f.inspect.ExecContext(t.Context(), `INSERT INTO control.service_audit_events(id,team_id,service_id,service_kind,event_type,occurred_at,received_at)
				    VALUES($1,$2,$3,'private_service','connection.close',$4,$4)`, oldID, service.TeamId, service.Id, time.Now().Add(-serviceaudit.Retention-time.Hour))
				if err != nil {
					t.Fatal(err)
				}
				cleanupCtx, stopCleanup := context.WithCancel(t.Context())
				cleanupDone := make(chan error, 1)
				cleanupJoined := false
				t.Cleanup(func() {
					stopCleanup()
					if !cleanupJoined {
						select {
						case <-cleanupDone:
						case <-time.After(5 * time.Second):
							t.Error("audit cleanup did not join")
						}
					}
				})
				go func() { cleanupDone <- maintenance.RunServiceAuditCleanup(cleanupCtx, f.composed.database) }()
				privateWait(t, 5*time.Second, func(ctx context.Context) (bool, error) {
					var count int
					err := f.inspect.QueryRowContext(ctx, `SELECT count(*) FROM control.service_audit_events WHERE id=$1`, oldID).Scan(&count)
					return count == 0, err
				})
				stopCleanup()
				cleanupErr := <-cleanupDone
				cleanupJoined = true
				if cleanupErr != nil {
					t.Fatal("audit cleanup worker did not join", cleanupErr)
				}
			}
			rows, err := f.inspect.QueryContext(t.Context(), `SELECT event_type,source_ip::text,reason FROM control.service_audit_events WHERE service_id=$1`, service.Id)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			for rows.Next() {
				var kind string
				var source, reason sql.NullString
				if err = rows.Scan(&kind, &source, &reason); err != nil {
					t.Fatal(err)
				}
				encoded, _ := json.Marshal([]any{kind, source.String, reason.String})
				if strings.Contains(string(encoded), "never-audit") {
					t.Fatal("private command reached service audit")
				}
			}
		})
	}
}
