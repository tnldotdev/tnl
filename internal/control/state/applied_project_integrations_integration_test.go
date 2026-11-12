package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationAppliedProjectRootIntegrationsAndRemoteGroups(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_root_integrations")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := retainedEnvironmentProject(t, d, now)
	initial := config.TNL{}
	if err := config.ValidateDocument(config.Document{Version: new(1), TNL: &initial}); err != nil {
		t.Fatal("empty local configuration", err)
	}
	initial.OAuth = true
	if err := config.ValidateDocument(config.Document{Version: new(1), TNL: &initial}); err != nil {
		t.Fatal("OAuth-only local configuration", err)
	}
	configured, _ := retainedServiceEnvironment(t, d, r, "eks", map[string]EnvironmentServicePublication{"remote": {Protocol: "http", Target: "eks.internal:8443", TargetTLS: appliedTargetTrust(t, "eks.internal")}})
	local := appliedWebhookConfiguration()
	if err := config.ValidateWebhooks(local.Services, local.Webhooks); err != nil {
		t.Fatal(err)
	}
	beforeLocal, _ := json.Marshal(local)
	var publicURLs, implicitIntegrations int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER(WHERE purpose IN('oauth','webhooks')) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&publicURLs, &implicitIntegrations); err != nil || publicURLs != 0 || implicitIntegrations != 0 {
		t.Fatal("environment implicitly published app integrations", err)
	}
	var encrypted []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT bindings_ciphertext FROM control.publisher_group_bindings WHERE group_id=(SELECT group_id FROM control.environments WHERE id=$1)`, configured.ID).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("eks.internal")) || bytes.Contains(encrypted, []byte("/hooks/payments")) {
		t.Fatal("target snapshot exposed local declarations or plaintext target", err)
	}
	replica := enrollTestEnvironment(t, d, r, configured)
	if len(replica.assignments.Services) != 1 || replica.assignments.Services[0].Service != "remote" {
		t.Fatal("local service assigned to remote environment")
	}
	wire, err := json.Marshal(replica.assignments)
	if err != nil || bytes.Contains(wire, []byte("webhooks")) || bytes.Contains(wire, []byte("/hooks/payments")) {
		t.Fatal("remote assignment exposed local handlers", err)
	}
	access := environmentAssignmentAccess(t, d, replica, replica.assignments.Services[0], now)
	local.OAuth = false
	endpoint := local.Webhooks["payments"]
	endpoint.Path = "/hooks/payments-v2"
	local.Webhooks["payments"] = endpoint
	if err := config.ValidateWebhooks(local.Services, local.Webhooks); err != nil {
		t.Fatal(err)
	}
	afterLocal, _ := json.Marshal(local)
	if bytes.Equal(beforeLocal, afterLocal) {
		t.Fatal("local integration edit lost")
	}
	current, err := d.GetEnvironmentPublisherAssignments(t.Context(), replica.lease.AccessToken, now)
	if err != nil || !reflect.DeepEqual(current, replica.assignments) {
		t.Fatal("local edit changed remote publication or grants", err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatal("local metadata edit revoked unrelated publisher", err)
	}
	if err := d.AcknowledgeEnvironmentPublisher(t.Context(), replica.lease.AccessToken, current.Environment, false, now); err != nil {
		t.Fatal("local edit incorrectly invalidated exact environment acknowledgement", err)
	}
	stale := current.Environment
	stale.MutationRevision++
	if err := d.AcknowledgeEnvironmentPublisher(t.Context(), replica.lease.AccessToken, stale, false, now); !errors.Is(err, ErrEnvironmentStale) {
		t.Fatal("inexact acknowledgement accepted", err)
	}
	collision := r
	collision.SourceFingerprint = strings.Repeat("b", 64)
	if _, err := d.CreateServiceDefinition(t.Context(), CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: collision.SourceFingerprint, ActorID: r.ActorID, Definition: ServiceDefinition{Services: map[string]ServiceDefinitionService{"remote": {Protocol: "http"}}}, Now: now}); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("source collision bypassed", err)
	}
	// app root fields are rejected, rather than retained as a second remote
	// configuration authority. receiver validation stays with config authoring.
	for _, field := range []string{`"oauth":true`, `"webhooks":{"remote":{"service":"remote","path":"/hooks/remote","provider":"custom"}}`} {
		if _, err := decodeServiceDefinition([]byte(`{"services":{"remote":{"protocol":"http"}},`+field+`}`), strings.Repeat("a", 64)); !errors.Is(err, ErrServiceDefinitionInvalid) {
			t.Fatal("shared definition accepted app integration authority", err)
		}
	}
	bad := appliedWebhookConfiguration()
	bad.Webhooks = map[string]config.Webhook{"remote": {Service: "remote", Path: "/hooks/remote", Provider: "custom"}}
	if err := config.ValidateWebhooks(bad.Services, bad.Webhooks); err == nil {
		t.Fatal("remote handler accepted")
	}
	bad = appliedWebhookConfiguration()
	delete(bad.Services, "app")
	if err := config.ValidateWebhooks(bad.Services, bad.Webhooks); err == nil {
		t.Fatal("dangling receiver accepted")
	}
	local.Services = config.Services{}
	local.Webhooks = map[string]config.Webhook{}
	if err := config.ValidateWebhooks(local.Services, local.Webhooks); err != nil {
		t.Fatal("removing local declarations failed", err)
	}
	status, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, configured.ID, r.ActorID)
	if err != nil || status.ConfigurationHash != configured.ConfigurationHash || status.MutationRevision != configured.MutationRevision || len(status.Services) != 1 {
		t.Fatal("local edit changed remote desired state", err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatal("removing local declarations disturbed remote publisher", err)
	}
}
