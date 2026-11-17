package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationAppliedProjectRootIntegrationsAndRemoteDeployments(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_root_integrations")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{}
	initial, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if initial.Revision != 1 || len(initial.Services) != 0 || initial.Configuration.OAuth || initial.Configuration.Webhooks == nil {
		t.Fatal("empty normalized root state is incomplete")
	}
	r.ExpectedRevision = 1
	r.Configuration.OAuth = true
	oauth, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if oauth.Revision != 1 || oauth.Configuration.OAuth || len(oauth.Services) != 0 || oauth.ConfigurationHash != initial.ConfigurationHash {
		t.Fatal("OAuth-only apply changed shared desired state")
	}
	if replay, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil || replay.Revision != 1 {
		t.Fatal("OAuth-only retry was not content-idempotent", err)
	}
	stale := r
	stale.ExpectedRevision = 0
	stale.Configuration.OAuth = false
	stale.Configuration.Services = map[string]ProjectServiceConfiguration{"web": {Target: "app"}}
	if _, err = d.ApplyProjectConfiguration(t.Context(), stale); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("stale root metadata replaced desired state", err)
	}
	collision := r
	collision.SourceFingerprint = strings.Repeat("b", 64)
	if _, err = d.ApplyProjectConfiguration(t.Context(), collision); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("root metadata replay bypassed source collision checks", err)
	}
	r.ExpectedRevision = 1
	r.Configuration = appliedWebhookConfiguration()
	r.Configuration.Services["remote"] = ProjectServiceConfiguration{Target: "https://eks.internal:8443", TargetTLS: appliedTargetTrust(t, "eks.internal")}
	remote := projectServiceSelection(r, "eks", "remote")
	remote.Configuration.Settings.Description = "externally operated replicas"
	r = projectServiceSelection(r, "local", "app")
	configured, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if configured.Revision != 2 || configured.Configuration.OAuth || len(configured.Configuration.Webhooks) != 0 {
		t.Fatal("publisher integration handlers reached shared state")
	}
	remote.ExpectedRevision = configured.Revision
	remoteApplied, err := d.ApplyProjectConfiguration(t.Context(), remote)
	if err != nil {
		t.Fatal(err)
	}
	var services, localRealizations int
	if err = d.pool.QueryRow(t.Context(), `SELECT
	    (SELECT count(*) FROM control.services WHERE team_id=$1),
	    (SELECT count(*) FROM control.local_project_services WHERE team_id=$1)`, r.TeamID).Scan(&services, &localRealizations); err != nil || services != 1 || localRealizations != 0 {
		t.Fatalf("apply allocated more than the declared remote service: services=%d local=%d %v", services, localRealizations, err)
	}
	var encrypted []byte
	if err = d.pool.QueryRow(t.Context(), `SELECT configuration_ciphertext FROM control.applied_projects WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("/hooks/payments")) {
		t.Fatal("root declaration was not encrypted with the complete configuration", err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "eks", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	if len(replica.assignments.Services) != 1 || replica.assignments.Services[0].Service != "remote" {
		t.Fatal("local integration service was assigned to the remote deployment")
	}
	wire, err := json.Marshal(replica.assignments)
	if err != nil || bytes.Contains(wire, []byte("webhooks")) || bytes.Contains(wire, []byte("/hooks/payments")) {
		t.Fatal("remote assignment received local integration handler declarations", err)
	}
	access := deploymentAssignmentAccess(t, d, replica, replica.assignments.Services[0], now)
	r.ExpectedRevision = remoteApplied.Revision
	r.Configuration.OAuth = false
	endpoint := r.Configuration.Webhooks["payments"]
	endpoint.Path = "/hooks/payments-v2"
	r.Configuration.Webhooks["payments"] = endpoint
	changed, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Revision != remoteApplied.Revision || changed.Configuration.OAuth || len(changed.Configuration.Webhooks) != 0 {
		t.Fatal("local-only integration edit changed shared state")
	}
	current, err := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != replica.assignments.Revision || current.ConfigurationHash != replica.assignments.ConfigurationHash || current.Services[0].ServiceID != replica.assignments.Services[0].ServiceID || current.Services[0].GrantID != replica.assignments.Services[0].GrantID {
		t.Fatal("local metadata edit replaced unrelated deployment publication grants")
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatal("local metadata edit revoked an unrelated native deployment grant", err)
	}
	if err = d.AcknowledgeDeploymentPublisherConfiguration(t.Context(), replica.lease.AccessToken, configured.Revision, configured.ConfigurationHash, false, now); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("deployment acknowledgement accepted project-level configuration facts", err)
	}
	if err = d.AcknowledgeDeploymentPublisherConfiguration(t.Context(), replica.lease.AccessToken, current.Revision, current.ConfigurationHash, false, now); err != nil {
		t.Fatal(err)
	}
	bad := r
	bad.ExpectedRevision = changed.Revision
	bad.Configuration.Webhooks = map[string]ProjectWebhook{"remote": {Service: "remote", Path: "/hooks/remote", Provider: "custom"}}
	if _, err = d.ApplyProjectConfiguration(t.Context(), bad); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("remote webhook handler was implicitly accepted", err)
	}
	bad = r
	bad.ExpectedRevision = changed.Revision
	bad.Configuration.Services = map[string]ProjectServiceConfiguration{}
	if _, err = d.ApplyProjectConfiguration(t.Context(), bad); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("removing the declared local receiver left dangling endpoints", err)
	}
	status, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "local")
	if err != nil || status.Revision != changed.Revision || status.ConfigurationHash != changed.ConfigurationHash {
		t.Fatal("invalid endpoint apply changed desired state", err)
	}
	r.ExpectedRevision = changed.Revision
	delete(r.Configuration.Services, "app")
	r.Configuration.Webhooks = map[string]ProjectWebhook{}
	removed, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Revision != changed.Revision+1 || len(removed.Configuration.Webhooks) != 0 || len(removed.Services) != 0 {
		t.Fatal("removing local declarations did not reconcile the complete desired root")
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatal("removing local declarations disturbed the externally operated deployment", err)
	}
}
