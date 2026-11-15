package invocation

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestNativeIntegrationConfigCreatesUpdatesAndReloadsWithoutTarget(t *testing.T) {
	for _, hostname := range []string{"oauth.member.example", "hooks.member.example"} {
		t.Run(hostname, func(t *testing.T) {
			f := newServiceSetupFixture(t, hostname)
			// reopen the same private state after every preparation to exercise
			// the persisted service grant and signing key, not a native cache.
			root := filepath.Join(t.TempDir(), "persistent")
			state, err := clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = state.Close() }()
			for _, desired := range [][]string{{}, {"192.0.2.1/32"}, nil, {}} {
				f.services.state, err = state.Server(t.Context(), f.services.authenticated.ServerEndpoint)
				if err != nil {
					t.Fatal(err)
				}
				cfg, saved, err := nativeIntegrationConfig(t.Context(), f.services, hostname, desired)
				if err != nil {
					t.Fatal(err)
				}
				if cfg.Target != "" || cfg.ServiceID != f.saved.Id || saved.Ephemeral ||
					cfg.PublisherIdentityID != f.identity.ClientId || cfg.PublisherGrantID != f.identity.GrantId || cfg.PublisherKeyID != f.identity.KeyId {
					t.Fatal("integration replaced its service, grant, or key, or invented a TCP target", cfg, saved)
				}
				http := f.declaration.Http
				if f.declaration.Target != "app" || f.declaration.Traffic != nil || http == nil ||
					http.Access == nil || http.Access.Mode == nil || *http.Access.Mode != controlv1.Anonymous ||
					(http.Access.Ip == nil) != (len(desired) == 0) ||
					http.Access.Ip != nil && !slices.Equal(*http.Access.Ip, desired) ||
					http.Limits == nil || http.Limits.Concurrency == nil || *http.Limits.Concurrency != 32 {
					t.Fatal("integration changed its handler declaration, source policy, or independent HTTP budget", f.declaration)
				}
				encoded, err := json.Marshal(http)
				if err != nil {
					t.Fatal(err)
				}
				var settings config.HTTPService
				if err := json.Unmarshal(encoded, &settings); err != nil || settings.Access == nil || settings.Access.Validate() != nil {
					t.Fatal("integration emitted an invalid HTTP access declaration", err)
				}
				access, err := cfg.Access(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				if scoped, err := cfg.Control.GetPublisherService(t.Context(), cfg.ServiceID, access); err != nil || scoped.Id != saved.Id {
					t.Fatal("exact integration publisher could not read its actual service", scoped, err)
				}
				if err := state.Close(); err != nil {
					t.Fatal(err)
				}
				state, err = clientstate.OpenWithOptions(t.Context(), root, clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
				if err != nil {
					t.Fatal(err)
				}
			}
			if f.creates != 1 || f.changes != 2 || f.enrollments != 1 || f.redemptions != 1 {
				t.Fatal("integration re-enrolled or recreated its saved service", f.creates, f.changes, f.enrollments, f.redemptions)
			}
			f.saved.Endpoint.Hostname = "different.member.example"
			_, _, err = nativeIntegrationConfig(t.Context(), f.services, hostname, nil)
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid {
				t.Fatal("integration adopted a service at a different endpoint", err)
			}
		})
	}
}
