package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/netip"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationServiceHTTPAccessIsIndependentOfPlacementAndExposure(t *testing.T) {
	for _, deployment := range []string{"local", "production"} {
		for _, public := range []bool{false, true} {
			name := deployment + "/connector-only"
			if public {
				name = deployment + "/public"
			}
			t.Run(name, func(t *testing.T) {
				d, now, _, _ := newPublishRunPrerequisites(t)
				ctx := t.Context()
				if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
					t.Fatal(err)
				}
				r := appliedProjectRequest(t, d, now)
				configuration := ProjectServiceConfiguration{
					Target: "http://app.internal:3000", Public: new(public),
					HTTP: &config.HTTPService{Access: &config.Access{IP: []string{"192.0.2.10"}}},
				}
				r.Configuration.Services["web"] = configuration
				r = selectedProjectRequest(r, deployment)
				realize := RealizeLocalProjectServiceRequest{
					TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
					Service: "web", WorktreeKey: "checkout", WorktreeLabel: "feature",
					ActorID: r.ActorID, Configuration: configuration, Now: now,
				}
				id := ""
				if deployment == "local" {
					local, err := d.RealizeLocalProjectService(ctx, realize)
					if err != nil {
						t.Fatal(err)
					}
					id = local.ServiceID
				} else {
					applied, err := d.ApplyProjectConfiguration(ctx, r)
					if err != nil {
						t.Fatal(err)
					}
					id, r.ExpectedRevision = applied.Services[0].ServiceID, applied.Revision
				}
				saved, err := d.GetService(ctx, id, r.ActorID)
				if err != nil || saved.Endpoint == nil || saved.Endpoint.Public != public || saved.Endpoint.Port != 443 {
					t.Fatal("visitor policy changed endpoint reachability", err)
				}
				endpoint := *saved.Endpoint
				scope := visitorscope.Scope{Kind: visitorscope.Service, ID: id}
				policy, err := visitorlease.New(scope, nil)
				if err != nil {
					t.Fatal(err)
				}
				defer policy.Close()
				refresh := func(wantAnonymous bool) {
					t.Helper()
					tx, err := d.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
					if err != nil {
						t.Fatal(err)
					}
					defer tx.Rollback(ctx)
					result, err := d.readVisitorPolicy(ctx, tx, scope, 0, now)
					if err != nil {
						t.Fatal(err)
					}
					if !result.Policy.Enabled || result.Policy.Anonymous != wantAnonymous || result.Policy.Port != endpoint.Port || result.Policy.Hostname != endpoint.Hostname {
						t.Fatal("service policy lost its exact access or endpoint")
					}
					update, err := visitorlease.Decode(result)
					if err != nil {
						t.Fatal(err)
					}
					if err := policy.Apply(policy.Begin(), update); err != nil {
						t.Fatal(err)
					}
					if err := tx.Commit(ctx); err != nil {
						t.Fatal(err)
					}
				}
				refresh(false)
				allowed := netip.MustParseAddr("192.0.2.10")
				if _, err := policy.BindAnonymous(allowed, func() {}); err == nil {
					t.Fatal("default service access admitted an anonymous visitor")
				}
				setMode := func(mode string) {
					t.Helper()
					configuration.HTTP = &config.HTTPService{Access: &config.Access{Mode: mode, IP: []string{"192.0.2.10"}}}
					if deployment == "local" {
						realize.Configuration = configuration
						local, err := d.RealizeLocalProjectService(ctx, realize)
						if err != nil || local.ServiceID != id {
							t.Fatal("HTTP access replaced local service identity", err)
						}
					} else {
						r.Configuration.Services["web"] = configuration
						applied, err := d.ApplyProjectConfiguration(ctx, r)
						if err != nil || applied.Services[0].ServiceID != id {
							t.Fatal("HTTP access replaced deployment service identity", err)
						}
						r.ExpectedRevision = applied.Revision
					}
					current, err := d.GetService(ctx, id, r.ActorID)
					if err != nil || current.Endpoint == nil || *current.Endpoint != endpoint {
						t.Fatal("HTTP access changed the saved service endpoint", err)
					}
				}
				setMode("anonymous")
				refresh(true)
				stopped := make(chan struct{})
				guard, err := policy.BindAnonymous(allowed, func() { close(stopped) })
				if err != nil {
					t.Fatal("explicit anonymous HTTP access was rejected", err)
				}
				defer guard.Close()
				if _, err := policy.BindAnonymous(netip.MustParseAddr("203.0.113.10"), func() {}); err == nil {
					t.Fatal("anonymous HTTP access bypassed the IP policy")
				}
				// anonymous HTTP access never creates a native connector permission.
				tx, err := d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				_, _, accessErr := privateVisitorAccess(ctx, tx, id, "ungranted-identity", now)
				_ = tx.Rollback(ctx)
				if !errors.Is(accessErr, ErrServiceAccess) {
					t.Fatal("anonymous HTTP access granted connector access", accessErr)
				}
				setMode("restricted")
				refresh(false)
				select {
				case <-stopped:
				default:
					t.Fatal("restricting service access retained an anonymous request")
				}
				if _, err := policy.BindAnonymous(allowed, func() {}); err == nil {
					t.Fatal("restricted service retained anonymous admission")
				}
			})
		}
	}
}

func TestIntegrationLocalServiceHTTPAnonymousPolicyReachesPublisher(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	local, err := d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now,
		Configuration: ProjectServiceConfiguration{Target: "app", HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	creation := oidcRouteRequest(t, d, now)
	enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: local.ServiceID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	preparation, err := d.PrepareServiceRun(ctx, local.ServiceID, access, "anonymous-http", now, ServiceRunRequest{Metadata: *local.Metadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, local.ServiceID, preparation.RunID, preparation.RunNumber, access, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: local.ServiceID}
	result, err := d.ReadPublisherVisitorPolicy(ctx, scope, run.RunID, run.RunNumber, run.Token, 0, now)
	if err != nil || !result.Policy.Anonymous || result.Policy.Port != 443 {
		t.Fatal("publisher did not receive connector-only service's HTTP policy", err)
	}
	if _, err := d.ReadPublisherVisitorPolicy(ctx, scope, run.RunID, run.RunNumber+1, run.Token, 0, now); err == nil {
		t.Fatal("HTTP policy bypassed service run authentication")
	}
}
