package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestIntegrationServiceBrowserCaptureUsesCurrentPublisherSigningKey(t *testing.T) {
	for _, kind := range []string{"service", "namespace", "deployment"} {
		t.Run(kind, func(t *testing.T) {
			var f serviceHTTPFixture
			var access PublisherAccess
			if kind == "deployment" {
				deployment := newDeploymentPublicationFixture(t)
				_, _, _, leases := publishRunPrerequisitesInDatabase(t, deployment.d, deployment.now, nil)
				_, _, registered, _ := deployment.approve(t, nil, "restricted")
				f.database, f.now, f.project, f.leases = deployment.d, deployment.now, deployment.project, leases
				run := startAllocatedServiceRun(t, deployment, registered)
				readyDeploymentServiceRun(t, f.database, run, leases, f.now)
				f.service, f.run, access = run.service, run.run, registered
			} else {
				f = newServiceHTTPFixture(t)
				scope := PublisherScope{TeamID: f.project.TeamID, Kind: "service", ServiceID: f.service.ID}
				if kind == "namespace" {
					scope = PublisherScope{TeamID: f.project.TeamID, Kind: "namespace", DomainID: f.service.DomainID}
				}
				enrollment := publisherEnrollment(t, f.database, serviceTestAuthority{TeamID: f.project.TeamID, ActingIdentityID: f.project.ActorID}, scope, f.now)
				public, key, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				publisher, err := f.database.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, f.now)
				if err != nil {
					t.Fatal(err)
				}
				access = publisherAccess(t, f.database, publisher, key, "192.0.2.10", f.now)
				if kind == "namespace" {
					f.service, err = f.database.AllocatePublisherService(t.Context(), access.PublisherIdentity, AllocateServiceRequest{
						Invocation: mustOpaqueID(t, opaqueid.InvocationPrefix), Configuration: ProjectServiceConfiguration{Target: "localhost:3000"},
					}, f.now)
					if err != nil {
						t.Fatal(err)
					}
				}
				f.run = readyAppliedServiceRun(t, f.database, access, key, f.service, netip.MustParseAddr("192.0.2.10"), f.leases, f.now)
			}
			if err := f.database.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, f.now); err != nil {
				t.Fatal(err)
			}
			secret := []byte("0123456789abcdefghijklmnopqrstuv")
			share := f.share(t, "", "capture-issuer", secret, f.service)
			redemption, err := f.database.RedeemShare(t.Context(), f.auth(), share.ID, secret, nil, f.now)
			if err != nil {
				t.Fatal(err)
			}
			handoff, _ := f.browser(t, "", f.project.ActorID)
			browser, err := f.database.RedeemServiceBrowserHandoff(t.Context(), f.auth(), handoff.Token, f.now)
			if err != nil {
				t.Fatal(err)
			}
			q := controlstatedb.New(f.database.pool)
			check := func(want bool) {
				t.Helper()
				endpoint, err := q.ServiceHTTPBrowserEndpoint(t.Context(), controlstatedb.ServiceHTTPBrowserEndpointParams{ServiceID: f.service.ID, Now: timestamptz(f.now)})
				if err != nil || slices.Contains(endpoint.RunIds, f.run.RunID) != want {
					t.Fatal("browser endpoint disagrees with current run signing-key authority", want, endpoint.RunIds, err)
				}
				hosts, err := q.ReadyServiceBrowserHosts(t.Context(), controlstatedb.ReadyServiceBrowserHostsParams{ServiceID: f.service.ID, Now: timestamptz(f.now)})
				if err != nil || (len(hosts) != 0 && slices.Contains(hosts[0].RunIds, f.run.RunID)) != want {
					t.Fatal("browser handoff captured a stale signing-key replica", want, err)
				}
				shared, err := q.ListReadyShareServices(t.Context(), controlstatedb.ListReadyShareServicesParams{ShareID: share.ID, Now: timestamptz(f.now)})
				if err != nil || (len(shared) != 0 && slices.Contains(shared[0].RunIds, f.run.RunID)) != want {
					t.Fatal("share handoff captured a stale signing-key replica", want, err)
				}
				for _, source := range []VisitorTokenSource{
					ShareSessionTokenSource{ShareID: share.ID, Secret: redemption.CookieSecret, RunID: f.run.RunID},
					BrowserSessionTokenSource{Secret: browser.CookieSecret},
				} {
					_, err := f.database.IssueVisitorToken(t.Context(), testVisitorIssuer, f.auth().Subject, source, f.now)
					if (err == nil) != want || err != nil && !errors.Is(err, ErrVisitorPermission) {
						t.Fatalf("captured %T renewal disagrees with current publisher authority: want %t, %v", source, want, err)
					}
				}
			}
			check(true)
			// retain a ready row while key retirement propagates. capture must
			// apply the same exact-grant recovery rule as final run admission.
			if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.publisher_identity_keys SET retired_at=$2 WHERE id=$1`, access.KeyID, f.now.Add(-time.Second)); err != nil {
				t.Fatal(err)
			}
			check(kind == "service")
			if _, err := f.database.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, access.GrantID, f.now); err != nil {
				t.Fatal(err)
			}
			check(false)
		})
	}
}
