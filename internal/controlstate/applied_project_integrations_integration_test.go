package controlstate

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationAppliedProjectRootIntegrationsAndRemoteGroups(t *testing.T) {
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
	if oauth.Revision != 2 || !oauth.Configuration.OAuth || len(oauth.Services) != 0 || oauth.ConfigurationHash == initial.ConfigurationHash {
		t.Fatal("OAuth-only apply did not advance desired state")
	}
	if replay, err := d.ApplyProjectConfiguration(t.Context(), r); err != nil || replay.Revision != 2 {
		t.Fatal("OAuth-only retry was not content-idempotent", err)
	}
	stale := r
	stale.ExpectedRevision = 0
	stale.Configuration.OAuth = false
	if _, err = d.ApplyProjectConfiguration(t.Context(), stale); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("stale root metadata replaced desired state", err)
	}
	collision := r
	collision.SourceFingerprint = strings.Repeat("b", 64)
	if _, err = d.ApplyProjectConfiguration(t.Context(), collision); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("root metadata replay bypassed source collision checks", err)
	}
	r.ExpectedRevision = 2
	r.Configuration = appliedWebhookConfiguration()
	r.Configuration.Publishers = map[string]ProjectPublisherGroup{"eks": {Description: "externally operated replicas"}}
	r.Configuration.Services["remote"] = ProjectServiceConfiguration{Publisher: "eks", Target: "https://eks.internal:8443", TargetTLS: appliedTargetTrust(t, "eks.internal"), PublicURL: &ProjectServicePublicURL{}}
	configured, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if configured.Revision != 3 || !configured.Configuration.OAuth || len(configured.Configuration.Webhooks) != 2 || configured.Configuration.Webhooks["chat"].Delivery != "selected" {
		t.Fatal("root declarations were not normalized and stored")
	}
	var publicURLs, implicitIntegrations int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*),count(*) FILTER(WHERE purpose IN('oauth','webhooks')) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&publicURLs, &implicitIntegrations); err != nil || publicURLs != 0 || implicitIntegrations != 0 {
		t.Fatalf("apply implicitly published local integrations: URLs=%d integrations=%d %v", publicURLs, implicitIntegrations, err)
	}
	var encrypted []byte
	if err = d.pool.QueryRow(t.Context(), `SELECT configuration_ciphertext FROM control.applied_projects WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&encrypted); err != nil || bytes.Contains(encrypted, []byte("/hooks/payments")) {
		t.Fatal("root declaration was not encrypted with the complete configuration", err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "eks", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	if len(replica.assignments.Services) != 1 || replica.assignments.Services[0].Service != "remote" {
		t.Fatal("local integration service was assigned to the remote group")
	}
	wire, err := json.Marshal(replica.assignments)
	if err != nil || bytes.Contains(wire, []byte("webhooks")) || bytes.Contains(wire, []byte("/hooks/payments")) {
		t.Fatal("remote assignment received local integration handler declarations", err)
	}
	access := groupAssignmentAccess(t, d, replica, replica.assignments.Services[0], now)
	r.ExpectedRevision = 3
	r.Configuration.OAuth = false
	endpoint := r.Configuration.Webhooks["payments"]
	endpoint.Path = "/hooks/payments-v2"
	r.Configuration.Webhooks["payments"] = endpoint
	changed, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Revision != 4 || changed.Configuration.OAuth || changed.Configuration.Webhooks["payments"].Path != endpoint.Path {
		t.Fatal("local-only integration edit did not update status")
	}
	current, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if current.Revision != 4 || current.ConfigurationHash != changed.ConfigurationHash || current.Services[0].ServiceID != replica.assignments.Services[0].ServiceID || current.Services[0].GrantID != replica.assignments.Services[0].GrantID {
		t.Fatal("local metadata edit replaced unrelated group publication grants")
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatal("local metadata edit revoked an unrelated native group grant", err)
	}
	if err = d.AcknowledgePublisherGroupConfiguration(t.Context(), replica.lease.AccessToken, 3, configured.ConfigurationHash, false, now); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("root metadata edit accepted a stale group acknowledgement", err)
	}
	if err = d.AcknowledgePublisherGroupConfiguration(t.Context(), replica.lease.AccessToken, 4, changed.ConfigurationHash, false, now); err != nil {
		t.Fatal(err)
	}
	bad := r
	bad.ExpectedRevision = 4
	bad.Configuration.Webhooks = map[string]ProjectWebhook{"remote": {Service: "remote", Path: "/hooks/remote", Provider: "custom"}}
	if _, err = d.ApplyProjectConfiguration(t.Context(), bad); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("remote webhook handler was implicitly accepted", err)
	}
	bad = r
	bad.ExpectedRevision = 4
	bad.Configuration.Services = map[string]ProjectServiceConfiguration{"remote": r.Configuration.Services["remote"]}
	if _, err = d.ApplyProjectConfiguration(t.Context(), bad); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("removing the declared local receiver left dangling endpoints", err)
	}
	status, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || status.Revision != 4 || status.ConfigurationHash != changed.ConfigurationHash {
		t.Fatal("invalid endpoint apply changed desired state", err)
	}
	r.ExpectedRevision = 4
	delete(r.Configuration.Services, "app")
	r.Configuration.Webhooks = map[string]ProjectWebhook{}
	removed, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if removed.Revision != 5 || len(removed.Configuration.Webhooks) != 0 || len(removed.Services) != 1 {
		t.Fatal("removing local declarations did not reconcile the complete desired root")
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); err != nil {
		t.Fatal("removing local declarations disturbed the externally operated group", err)
	}
}
