package invocation

import (
	"context"
	"errors"
	"net/http"
	"reflect"
	"testing"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestProjectAliasPreparesAnExactNativePublisherOnlyForTheSelectedReadyReceiver(t *testing.T) {
	for _, prefixes := range [][]string{nil, {"192.0.2.1/32"}} {
		name := "no IP policy"
		if prefixes != nil {
			name = "explicit IP policy"
		}
		t.Run(name, func(t *testing.T) {
			f := newServiceSetupFixture(t, "review.member.example")
			project, target := t.TempDir(), "https://127.0.0.1:3000"
			group := clientstate.IntegrationScope{PrimaryProjectRoot: project, Namespace: "member.example"}
			trust, err := targettrust.NewDeclaration("web.internal", nil)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := trust.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			f.parent = controlv1.Service{Id: serviceTestID(t, opaqueid.ServicePrefix), TeamId: f.saved.TeamId, DomainId: f.saved.DomainId,
				Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1, TargetTls: publisheridentity.ServiceTargetTLS(snapshot),
				RequirePostQuantum: true, HttpLimits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(6)},
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.member.example", Public: true, Port: 443}}
			tunnel, err := f.state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
				Server: f.services.authenticated.ServerEndpoint, Project: project, Service: "web", ServiceID: f.parent.Id, Target: target, IntegrationScope: group})
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Finish(context.Background(), nil)
			if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
				t.Fatal(err)
			}
			f.services.membershipID, f.services.namespace = "member_fixture", group.Namespace
			scope := clientstate.AliasScope{Server: f.services.authenticated.ServerEndpoint, ProjectKey: project, TeamID: f.saved.TeamId,
				MembershipID: f.services.membershipID, Namespace: group.Namespace, Name: "review"}
			selection, err := f.state.RegisterAlias(t.Context(), clientstate.AliasRegistration{Scope: scope,
				Hostname: f.saved.Endpoint.Hostname, Service: "web", TunnelID: tunnel.ID(), IntegrationScope: group})
			if err != nil {
				t.Fatal(err)
			}
			admissions, responses, captures := 0, 0, 0
			base := publisherservice.RunConfig{Control: f.services.routes, Access: func(context.Context) (string, error) { return "parent-access", nil },
				ServiceID: f.parent.Id, Target: "127.0.0.1:3000", Metadata: publisheridentity.ServiceMetadata(f.parent),
				Mounts: []publisherproxy.Mount{{Prefix: "/api", Target: "http://127.0.0.1:4000"}}, Feedback: true, PreviewID: "parent-preview",
				ResolveHTTPTarget: func(*http.Request) (string, string, error) { captures++; return target, "app-instance", nil },
				AdmitRequest: func(r *http.Request) error {
					admissions++
					state, err := f.state.SnapshotProject(r.Context(), project)
					if err != nil {
						return err
					}
					if len(state.Tunnels) != 1 || state.Tunnels[0].ServiceID != f.parent.Id || state.Tunnels[0].PublishRunNumber != 1 {
						t.Error("alias lost its captured entry-service admission")
					}
					return nil
				},
				HTTPResponseHooks: func(run publisherservice.HTTPRun) httpstream.ResponseHooks {
					return httpstream.ResponseHooks{Observe: func(*http.Response) error {
						responses++
						if run.ServiceID != f.saved.Id {
							t.Error("alias response was attributed to the parent's service")
						}
						return nil
					}}
				}}
			worker := projectAliasPublisher(f.state, f.services, selection, tunnel.ID(), base, resolvedVisitorAccess{access: controlv1.Restricted, prefixes: prefixes}, nil)
			if eligible, err := worker.Eligible(t.Context()); err != nil || eligible {
				t.Fatal("unready alias was eligible", eligible, err)
			}
			if _, err := worker.Prepare(t.Context()); !errors.Is(err, clientstate.ErrAliasReceiverUnavailable) || f.requests != 0 {
				t.Fatal("unready alias acquired remote state", f.requests, err)
			}
			if err := tunnel.SetReady(t.Context(), "https://"+f.parent.Endpoint.Hostname, 1); err != nil {
				t.Fatal(err)
			}
			for range 2 {
				prepared, err := worker.Prepare(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if f.declaration.Http == nil || f.declaration.Http.Access == nil || f.declaration.Http.Access.Mode == nil ||
					*f.declaration.Http.Access.Mode != controlv1.Restricted ||
					prefixes == nil && f.declaration.Http.Access.Ip != nil ||
					prefixes != nil && (f.declaration.Http.Access.Ip == nil || !reflect.DeepEqual(*f.declaration.Http.Access.Ip, prefixes)) {
					t.Fatal("alias changed its selected IP policy or sent an empty filter")
				}
				cfg := prepared.Config
				if cfg.ServiceID != f.saved.Id || cfg.PublisherIdentityID != f.identity.ClientId ||
					cfg.PublisherGrantID != f.identity.GrantId || cfg.PublisherKeyID != f.identity.KeyId ||
					cfg.Target != base.Target || cfg.Feedback || cfg.PreviewID != "" ||
					!reflect.DeepEqual(cfg.Metadata.TargetTls, base.Metadata.TargetTls) ||
					len(cfg.Mounts) != 1 || cfg.Mounts[0].Target != base.Mounts[0].Target ||
					!prepared.Service.RequirePostQuantum || prepared.Service.HttpLimits.Concurrency == nil || *prepared.Service.HttpLimits.Concurrency != 6 {
					t.Fatal("alias lost its actual grant, captured target/trust, mounts, PQ, or HTTP budget", cfg)
				}
				request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+f.saved.Endpoint.Hostname+"/", nil)
				if err := cfg.AdmitRequest(request); err != nil {
					t.Fatal(err)
				}
				if address, identity, err := cfg.ResolveHTTPTarget(request); err != nil || address != target || identity != "app-instance" {
					t.Fatal("alias lost the captured dynamic target identity", address, identity, err)
				}
				if err := cfg.HTTPResponseHooks(publisherservice.HTTPRun{ServiceID: cfg.ServiceID, Hostname: f.saved.Endpoint.Hostname}).Observe(&http.Response{Request: request}); err != nil {
					t.Fatal(err)
				}
				if _, broad := cfg.Control.(interface {
					ConfigureService(context.Context, string, controlv1.UpdateServiceRequest) (controlv1.Service, error)
				}); broad {
					t.Fatal("alias runtime retained management authority")
				}
				access, err := cfg.Access(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cfg.Control.PrepareServiceRun(t.Context(), cfg.ServiceID, serviceTestID(t, opaqueid.IdempotencyPrefix), access,
					publisheridentity.ServiceDeclaration(prepared.Service)); !errors.Is(err, clientcontrol.ErrUnavailable) {
					t.Fatal("alias run did not use its signed exact-service authority", err)
				}
			}
			if f.creates != 1 || f.enrollments != 1 || f.redemptions != 1 || f.runs != 2 || admissions != 2 || responses != 2 || captures != 2 {
				t.Fatal("alias retried with another service/key or lost app callbacks", f.creates, f.enrollments, f.redemptions, f.runs, admissions, responses, captures)
			}
		})
	}
}
