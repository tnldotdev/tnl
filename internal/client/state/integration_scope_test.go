package state

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationScopeRejectsMalformedComponentsAtStateBoundaries(t *testing.T) {
	database, _ := aliasTestDatabase(t)
	const server = "https://control.example.test"
	project := t.TempDir()
	tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{
		Command: TunnelCommandPublish, Server: server, Target: "3000", Project: project, ServiceProtocol: controlv1.Http,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunnel.Finish(t.Context(), nil) })
	for name, scope := range map[string]IntegrationScope{
		"empty":             {},
		"missing project":   {Namespace: "member.example.test"},
		"relative project":  {PrimaryProjectRoot: "project", Namespace: "member.example.test"},
		"unclean project":   {PrimaryProjectRoot: project + "/../project", Namespace: "member.example.test"},
		"nul project":       {PrimaryProjectRoot: project + "\x00other", Namespace: "member.example.test"},
		"oversized project": {PrimaryProjectRoot: "/" + strings.Repeat("x", 1024), Namespace: "member.example.test"},
		"missing namespace": {PrimaryProjectRoot: project},
		"nul namespace":     {PrimaryProjectRoot: project, Namespace: "member.example.test\x00other"},
		"uppercase":         {PrimaryProjectRoot: project, Namespace: "Member.example.test"},
		"trailing dot":      {PrimaryProjectRoot: project, Namespace: "member.example.test."},
		"namespace port":    {PrimaryProjectRoot: project, Namespace: "member.example.test:443"},
	} {
		t.Run(name, func(t *testing.T) {
			assertInvalid := func(err error) {
				t.Helper()
				if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ProjectConfigInvalid {
					t.Fatalf("malformed integration scope = %v", err)
				}
			}
			assertInvalid(scope.Validate())
			if !scope.IsZero() {
				_, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: server,
					Target: "3000", Project: project, ServiceProtocol: controlv1.Http, IntegrationScope: scope})
				assertInvalid(err)
			}
			assertInvalid(tunnel.SetIntegrationScope(t.Context(), scope))
			_, err := database.ActiveWebhookDefinitions(t.Context(), server, scope)
			assertInvalid(err)
			_, err = database.WebhookReceivers(t.Context(), server, scope, "event", [32]byte{})
			assertInvalid(err)
			assertInvalid(database.ClaimWebhookReceiver(t.Context(), server, scope, "event", tunnel.ID(), [32]byte{}, false))
			assertInvalid(database.ReleaseWebhookReceiver(t.Context(), server, scope, "event", tunnel.ID()))
			_, err = database.ExclusiveWebhookReceiver(t.Context(), server, scope, "event", [32]byte{})
			assertInvalid(err)
			_, err = database.WebhookHostname(t.Context(), server, scope)
			assertInvalid(err)
			assertInvalid(database.SaveOAuthCallback(t.Context(), SaveOAuthCallbackInput{Scope: OAuthCallbackScope{IntegrationScope: scope}}))
			_, err = database.RegisterAlias(t.Context(), AliasRegistration{Scope: AliasScope{Server: server, ProjectKey: project,
				TeamID: "team_fixture", MembershipID: "member_fixture", Namespace: "member.example.test", Name: "review"},
				Hostname: "review.member.example.test", Service: "api", TunnelID: tunnel.ID(), IntegrationScope: scope})
			assertInvalid(err)
		})
	}
	var primary, namespace sql.NullString
	if err := database.db.QueryRowContext(t.Context(), `SELECT primary_project_root, integration_namespace FROM local_tunnels WHERE id = ?`, tunnel.ID()).Scan(&primary, &namespace); err != nil || primary.Valid || namespace.Valid {
		t.Fatalf("unscoped tunnel did not retain NULL components: %v / %v: %v", primary, namespace, err)
	}
	valid := IntegrationScope{PrimaryProjectRoot: project, Namespace: "member.example.test"}
	if err := tunnel.SetIntegrationScope(t.Context(), valid); err != nil {
		t.Fatal(err)
	}
	snapshot, err := database.Snapshot(t.Context())
	if err != nil || len(snapshot.Tunnels) != 1 || snapshot.Tunnels[0].IntegrationScope != valid {
		t.Fatalf("scope did not round-trip: %#v, %v", snapshot.Tunnels, err)
	}
}

func TestIntegrationScopeMatchesBothComponentsAndServer(t *testing.T) {
	database, _ := aliasTestDatabase(t)
	const server = "https://control.example.test"
	primary := filepath.Join(t.TempDir(), "project")
	base := IntegrationScope{PrimaryProjectRoot: primary, Namespace: "member.example.test"}
	fixtures := []struct {
		server string
		scope  IntegrationScope
	}{
		{server, base},
		{server, IntegrationScope{PrimaryProjectRoot: primary + "-other", Namespace: base.Namespace}},
		{server, IntegrationScope{PrimaryProjectRoot: primary, Namespace: "other.member.example.test"}},
		{"https://other.example.test", base},
	}
	definition := config.Webhook{Service: "api", Path: "/hooks/event", Provider: "custom", Delivery: "selected"}
	var tunnels []*Tunnel
	var receivers []TunnelInfo
	var digests [][32]byte
	for _, fixture := range fixtures {
		// the same endpoint name may have a different policy in another scope.
		definition.Path = "/hooks/event" + strings.Repeat("-other", len(tunnels))
		encoded, digest, err := definition.DefinitionBytes()
		if err != nil {
			t.Fatal(err)
		}
		tunnel, err := database.BeginTunnel(t.Context(), BeginTunnelOptions{Command: TunnelCommandPublish, Server: fixture.server,
			Target: "3000", Project: t.TempDir(), Service: "api", ServiceProtocol: controlv1.Http, IntegrationScope: fixture.scope})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = tunnel.Finish(t.Context(), nil) })
		id, err := opaqueid.New(opaqueid.PublicURLPrefix)
		if err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetPublicURL(t.Context(), id, "https://api."+fixture.scope.Namespace); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.SetReady(t.Context(), "https://api."+fixture.scope.Namespace, 1); err != nil {
			t.Fatal(err)
		}
		if err := tunnel.RegisterWebhookEndpoint(t.Context(), "event", encoded); err != nil {
			t.Fatal(err)
		}
		if err := database.ClaimWebhookReceiver(t.Context(), fixture.server, fixture.scope, "event", tunnel.ID(), digest, false); err != nil {
			t.Fatal(err)
		}
		if _, err := database.IntegrationURLHostname(t.Context(), fixture.server, fixture.scope.PrimaryProjectRoot, fixture.scope.Namespace, "hooks", "hooks."+fixture.scope.Namespace); err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, tunnel)
		digests = append(digests, digest)
	}
	for index, fixture := range fixtures {
		found, err := database.WebhookReceivers(t.Context(), fixture.server, fixture.scope, "event", digests[index])
		if err != nil || len(found) != 1 || found[0].ID != tunnels[index].ID() || found[0].IntegrationScope != fixture.scope {
			t.Fatalf("scope %d matched another receiver: %#v, %v", index, found, err)
		}
		receivers = append(receivers, found[0])
		owner, err := database.ExclusiveWebhookReceiver(t.Context(), fixture.server, fixture.scope, "event", digests[index])
		if err != nil || owner.ID != tunnels[index].ID() || owner.IntegrationScope != fixture.scope {
			t.Fatalf("scope %d matched another owner: %#v, %v", index, owner, err)
		}
		hostname, err := database.WebhookHostname(t.Context(), fixture.server, fixture.scope)
		if err != nil || hostname != "hooks."+fixture.scope.Namespace {
			t.Fatalf("scope %d matched another hostname: %q, %v", index, hostname, err)
		}
		definitions, err := database.ActiveWebhookDefinitions(t.Context(), fixture.server, fixture.scope)
		if err != nil || len(definitions) != 1 || definitions["event"].Path != "/hooks/event"+strings.Repeat("-other", index) {
			t.Fatalf("scope %d matched another definition: %#v, %v", index, definitions, err)
		}
		if index != 0 {
			if err := database.ClaimWebhookReceiver(t.Context(), fixture.server, fixture.scope, "event", tunnels[0].ID(), digests[index], true); !errors.Is(err, ErrWebhookReceiverUnavailable) {
				t.Fatalf("forced claim crossed scope %d: %v", index, err)
			}
			if err := database.ReleaseWebhookReceiver(t.Context(), fixture.server, fixture.scope, "event", tunnels[0].ID()); !errors.Is(err, ErrWebhookNotSelected) {
				t.Fatalf("release crossed scope %d: %v", index, err)
			}
			owner, err := database.ExclusiveWebhookReceiver(t.Context(), fixture.server, fixture.scope, "event", digests[index])
			if err != nil || owner.ID != tunnels[index].ID() {
				t.Fatalf("rejected claim changed scope %d's owner: %#v, %v", index, owner, err)
			}
		}
	}
	for index, fixture := range fixtures {
		input := SaveOAuthCallbackInput{Scope: OAuthCallbackScope{Server: fixture.server, Hostname: "oauth.member.example.test", IntegrationScope: fixture.scope},
			Origin:      OAuthRedirectOrigin{PublicURLID: receivers[0].PublicURLID, PublishRunNumber: 1},
			Destination: OAuthCallbackDestination{TunnelID: tunnels[0].ID(), Path: "/callback"}, State: "opaque-state" + strings.Repeat("-other", index)}
		err := database.SaveOAuthCallback(t.Context(), input)
		if index == 0 && err != nil || index != 0 && err == nil {
			t.Fatalf("OAuth scope %d match = %v", index, err)
		}
	}
	if _, err := database.db.ExecContext(t.Context(), `INSERT INTO webhook_owners (server_origin, primary_project_root, integration_namespace, name, tunnel_id) VALUES (?, ?, ?, 'event', ?)`,
		server, base.PrimaryProjectRoot, base.Namespace, tunnels[0].ID()); err == nil {
		t.Fatal("duplicate owner bypassed the explicit scope's unique constraint")
	}
}
