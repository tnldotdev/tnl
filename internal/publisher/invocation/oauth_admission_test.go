package invocation

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestRuntimeOAuthAdmissionSurvivesDisabledIntegrationOnReplacement(t *testing.T) {
	for _, replace := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "replacement"}[replace], func(t *testing.T) {
			f := newServiceSetupFixture(t, "api.member.example")
			server := f.services.authenticated.ServerEndpoint
			group := clientstate.IntegrationScope{PrimaryProjectRoot: t.TempDir(), Namespace: "member.example"}
			tunnel, err := f.state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish,
				Server: server, ServiceID: f.saved.Id, Project: group.PrimaryProjectRoot, Target: "3000", IntegrationScope: group})
			if err != nil {
				t.Fatal(err)
			}
			defer tunnel.Finish(context.Background(), nil)
			if err := tunnel.SetReady(t.Context(), "https://"+f.saved.Endpoint.Hostname, 1); err != nil {
				t.Fatal(err)
			}
			const oauthHost = "oauth.member.example"
			if err := f.state.SaveOAuthCallback(t.Context(), clientstate.SaveOAuthCallbackInput{
				Scope:       clientstate.OAuthCallbackScope{Server: server, Hostname: oauthHost, IntegrationScope: group},
				Origin:      clientstate.OAuthRedirectOrigin{Hostname: f.saved.Endpoint.Hostname, ServiceID: f.saved.Id, RunNumber: 1},
				Destination: clientstate.OAuthCallbackDestination{TunnelID: tunnel.ID(), Path: "/callback"}, State: "between-hops",
			}); err != nil {
				t.Fatal(err)
			}
			const query = "state=between-hops&code=a%2fb%2Bc+z&provider=&provider=x%2Fy"
			redirect := httptest.NewRecorder()
			integrations.OAuthHandler(f.state, server, oauthHost, nil).ServeHTTP(redirect,
				httptest.NewRequest(http.MethodGet, "https://"+oauthHost+"/callback?"+query, nil))
			if redirect.Code != http.StatusSeeOther {
				t.Fatal("initiating callback did not redirect", redirect.Code)
			}
			run := publisherservice.HTTPRun{ServiceID: f.saved.Id, Hostname: f.saved.Endpoint.Hostname,
				RunID: serviceTestID(t, opaqueid.ServiceRunPrefix), Number: 1}
			if replace {
				run.Number++
				if err := tunnel.SetReady(t.Context(), "https://"+run.Hostname, uint64(run.Number)); err != nil {
					t.Fatal(err)
				}
			}
			prior := 0
			cfg := publisherservice.RunConfig{Control: f.services.routes, Metadata: controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP},
				HTTPPrepareRequest: func(*http.Request, publisherservice.HTTPRun) (func(context.Context) error, error) {
					prior++
					return nil, nil
				}}
			// use the actual runtime attachment with OAuth disabled. retained
			// returns must still be checked before an ordinary app can receive them.
			stop, err := attachRuntimeIntegrations(t.Context(), f.state, clientproject.Project{}, publisherapp.Service{}, tunnel, &cfg)
			if err != nil || stop != nil || cfg.HTTPPrepareRequest == nil || cfg.Prepared != nil {
				t.Fatal("runtime did not attach run-fact admission independently of integration workers", err)
			}
			request := httptest.NewRequest(http.MethodGet, redirect.Header().Get("Location"), nil)
			consume, err := cfg.HTTPPrepareRequest(request, run)
			if replace {
				if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.OAuthCallbackExpired {
					t.Fatal("replacement received a callback after disabling OAuth", err)
				}
			} else if err != nil {
				t.Fatal("current app lost its callback", err)
			} else {
				if _, err := cfg.HTTPPrepareRequest(request, run); err != nil {
					t.Fatal("read-only validation consumed the callback", err)
				}
				if consume == nil || consume(request.Context()) != nil {
					t.Fatal("current app could not consume its callback")
				}
			}
			if _, err := cfg.HTTPPrepareRequest(request, run); err == nil {
				t.Fatal("runtime admitted a replayed or replaced callback")
			}
			if request.URL.RawQuery != query {
				t.Fatal("runtime rewrote the provider's query bytes")
			}
			request.URL.RawQuery = "state=unknown&code=app-owned"
			wantPrior := 3
			if !replace {
				wantPrior++
			}
			if consume, err := cfg.HTTPPrepareRequest(request, run); err != nil || consume != nil || prior != wantPrior {
				t.Fatal("runtime took over app OAuth validation or dropped the prior hook", err, prior)
			}
		})
	}
}
