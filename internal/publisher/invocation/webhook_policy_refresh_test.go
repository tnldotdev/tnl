package invocation

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/integrations"
)

type webhookRefreshFixture struct {
	available bool
	refresh   func(context.Context, func(context.Context, []string) error) error
}

func (h *webhookRefreshFixture) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusServiceUnavailable)
}
func (h *webhookRefreshFixture) PolicyStatus(string) string { return "source policy fixture" }
func (h *webhookRefreshFixture) HasAvailablePolicy() bool   { return h.available }
func (h *webhookRefreshFixture) RefreshPolicies(ctx context.Context, install func(context.Context, []string) error) error {
	return h.refresh(ctx, install)
}

func TestWebhookPublisherRefreshesCoarseUnionWithoutReplacingItsHandler(t *testing.T) {
	for _, available := range []bool{false, true} {
		t.Run(map[bool]string{false: "no source", true: "running source"}[available], func(t *testing.T) {
			f := newServiceSetupFixture(t, "hooks.member.example")
			scope := clientstate.IntegrationScope{PrimaryProjectRoot: t.TempDir(), Namespace: "member.example"}
			tunnel, err := f.state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{
				Command: clientstate.TunnelCommandPublish, Server: f.services.authenticated.ServerEndpoint,
				ServiceID: f.saved.Id, Service: "api", Project: scope.PrimaryProjectRoot,
				Target: "http://127.0.0.1:3000", IntegrationScope: scope,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = tunnel.Finish(context.Background(), nil) })
			encoded, _, err := integrations.DefinitionBytes(config.Webhook{Service: "api", Path: "/stripe", Provider: "stripe"})
			if err != nil {
				t.Fatal(err)
			}
			if err := tunnel.RegisterWebhookEndpoint(t.Context(), "stripe", encoded); err != nil {
				t.Fatal(err)
			}
			source := &webhookRefreshFixture{available: available}
			prepares, refreshes := 0, 0
			publisher := webhookURLPublisher(f.state, f.services, scope,
				meta.IntegrationOrigin{Hostname: f.services.hostname, URL: "https://" + f.services.hostname},
				tunnel, &Presentation{}, func(context.Context, map[string]config.Webhook, func(string, string, string)) (webhookSourceHandler, []string, error) {
					prepares++
					if !available {
						return source, nil, nil
					}
					return source, []string{"192.0.2.0/24"}, nil
				})
			snapshot, err := publisher.Prepare(t.Context())
			if !available {
				if err == nil || f.creates != 0 || f.enrollments != 0 || f.updates != 0 {
					t.Fatal("empty provider union minted an unrestricted integration service", err)
				}
				return
			}
			if err != nil || snapshot.Config.Handler != source {
				t.Fatal("source owner was not installed as the actual handler", err)
			}
			creates, enrollments, changes := f.creates, f.enrollments, f.changes
			source.refresh = func(ctx context.Context, install func(context.Context, []string) error) error {
				refreshes++
				return install(ctx, []string{"192.0.2.0/25", "198.51.100.0/24"})
			}
			revision, err := publisher.Revision(t.Context())
			if err != nil || revision != snapshot.Revision || prepares != 1 || refreshes != 1 ||
				f.creates != creates || f.enrollments != enrollments || f.changes != changes+1 ||
				f.declaration.Http == nil || f.declaration.Http.Access == nil || f.declaration.Http.Access.Ip == nil ||
				!slices.Equal(*f.declaration.Http.Access.Ip, []string{"192.0.2.0/25", "198.51.100.0/24"}) {
				t.Fatal("provider refresh replaced publication intent or failed to update the existing service union", revision, err)
			}
			source.refresh = func(context.Context, func(context.Context, []string) error) error {
				return errors.New("source-union management unavailable")
			}
			if revision, err := publisher.Revision(t.Context()); err != nil || revision != snapshot.Revision {
				t.Fatal("one source-union refresh failure restarted independent endpoints", err)
			}
		})
	}
}
