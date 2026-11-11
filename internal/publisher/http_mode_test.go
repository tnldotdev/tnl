package publisher

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"path/filepath"
	"slices"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublicURLHTTPModeRejectsConflictingConfiguration(t *testing.T) {
	for _, test := range []struct {
		name      string
		configure func(*PublicURLServerConfig)
	}{
		{"target", func(c *PublicURLServerConfig) { c.Target = "http://127.0.0.1:3000" }},
		{"resolver", func(c *PublicURLServerConfig) {
			c.ResolveTarget = func(context.Context) (string, string, error) {
				t.Fatal("handler resolved a target")
				return "", "", nil
			}
		}},
		{"mount", func(c *PublicURLServerConfig) {
			c.Mounts = []publisherproxy.Mount{{Prefix: "/api", Target: "http://127.0.0.1:3000"}}
		}},
		{"tls name", func(c *PublicURLServerConfig) { c.TargetTLSName = "target.internal" }},
		{"tls options name", func(c *PublicURLServerConfig) { c.TargetOptions.ServerName = "target.internal" }},
		{"tls roots", func(c *PublicURLServerConfig) { c.TargetOptions.RootCAs = x509.NewCertPool() }},
		{"missing proxy target", func(c *PublicURLServerConfig) { c.Handler = nil }},
		{"integration proxy", func(c *PublicURLServerConfig) {
			c.Handler = nil
			c.Target = "http://127.0.0.1:3000"
			c.Purpose = controlv1.Oauth
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			config := PublicURLServerConfig{Hostname: "route.example", Handler: http.NotFoundHandler()}
			test.configure(&config)
			_, err := NewPublicURLServer(config)
			if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.TargetInvalid {
				t.Fatalf("invalid HTTP mode classification = %v", err)
			}
		})
	}
}

func TestRunHandlerBackedIntegrationSkipsTargetPreflightAndReloads(t *testing.T) {
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	store, err := state.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, purpose := range []controlv1.PublicURLPurpose{controlv1.Oauth, controlv1.Webhooks} {
		t.Run(string(purpose), func(t *testing.T) {
			stop := errors.New("stop at publish run")
			control := &publisherControlStub{allowed: []string{"lookup", "create", "create_session"}, publishRunErr: stop}
			config := Config{Control: control, State: store, Hostname: "integration.example", TeamID: "team_1", DomainID: "domain_1", PublicURLScope: controlv1.Shared, Purpose: purpose,
				Handler: http.NotFoundHandler(), InspectionMode: inspection.None}
			for range 2 {
				if err := Run(t.Context(), config); !errors.Is(err, stop) {
					t.Fatalf("handler mode did not reach control without a target: %v", err)
				}
			}
			if control.created == nil || control.created.Target != "" || control.created.Ephemeral != nil || !slices.Equal(control.calls, []string{"lookup", "create", "create_session", "lookup", "create_session"}) {
				t.Fatalf("handler integration create/reload = %+v, calls=%v", control.created, control.calls)
			}
			control.routes[0].Target = "http://127.0.0.1:3000"
			if code, ok := diagnostic.CodeOf(Run(t.Context(), config)); !ok || code != diagnostic.PublicURLConflict {
				t.Fatalf("loaded a nonempty integration target: code=%s, classified=%t", code, ok)
			}
			config.Ephemeral = true
			if code, ok := diagnostic.CodeOf(Run(t.Context(), config)); !ok || code != diagnostic.PublicURLInvalid {
				t.Fatalf("ephemeral integration classification = %s, classified=%t", code, ok)
			}
		})
	}
}

func TestTargetlessSavedPublicURLReconciliationKeepsLocalTargetOnPolicyChanges(t *testing.T) {
	for _, purpose := range []controlv1.PublicURLPurpose{controlv1.App, controlv1.Alias, controlv1.Oauth, controlv1.Webhooks} {
		t.Run(string(purpose), func(t *testing.T) {
			current := []string{"192.0.2.1/32"}
			control := &publisherControlStub{allowed: []string{"lookup", "update"}, routes: []controlv1.PublicURL{{Id: "public_url_1", TeamId: "team_1", DomainId: "domain_1", PublicUrlScope: controlv1.Shared, Purpose: purpose, CanonicalHostname: "app.example", LifecycleState: controlv1.Enabled, AllowedIpPrefixes: &current}}}
			config := Config{Control: control, Hostname: "app.example", TeamID: "team_1", DomainID: "domain_1", PublicURLScope: controlv1.Shared, Purpose: purpose, PreserveSavedPublicURLTarget: true, Target: "http://127.0.0.1:3000"}
			if purpose == controlv1.Oauth || purpose == controlv1.Webhooks {
				config.Target = ""
			}
			for _, policy := range [][]string{{"198.51.100.1/32"}, {}} {
				config.AllowedIPPrefixes = policy
				got, _, err := createOrLoadPublicURL(t.Context(), config)
				if err != nil || got.Target != "" || control.updated == nil || control.updated.Target != "" || !slices.Equal(control.updated.AllowedIpPrefixes, policy) {
					t.Fatalf("policy reconciliation changed target ownership: %+v, %+v, %v", got, control.updated, err)
				}
			}
			if purpose == controlv1.Oauth || purpose == controlv1.Webhooks {
				control.routes[0].AllowedIpPrefixes = &current
				config.AllowedIPPrefixes = nil
				got, _, err := createOrLoadPublicURL(t.Context(), config)
				if err != nil || got.Target != "" || control.updated.Target != "" || control.updated.AllowedIpPrefixes == nil || len(control.updated.AllowedIpPrefixes) != 0 {
					t.Fatalf("integration policy did not clear to an empty array: %+v, %+v, %v", got, control.updated, err)
				}
			}
		})
	}
}
