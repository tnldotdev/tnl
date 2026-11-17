package state

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationLocalProjectConfigurationPrivacy(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_configuration_privacy")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	shared := &config.HTTPService{Access: &config.Access{Mode: "anonymous"}, Limits: &config.WorkLimits{Concurrency: new(4)},
		Readiness: &config.Readiness{Path: "/private-health"}, Open: new(true), Paths: map[string]config.PathMount{"/private-mount": {Service: "api"}}}
	r.Configuration = ProjectConfiguration{OAuth: true, Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "https://private.internal:8443", TargetTLS: appliedTargetTrust(t, "approved.internal"), Public: new(true), HTTP: shared},
		"api": {Target: "docker:private-container:3001"},
	}, Webhooks: map[string]ProjectWebhook{"review": {Service: "web", Path: "/private-hook", Provider: "custom"}}}
	r = selectedProjectRequest(r, "local")
	first, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivate := func(value any) {
		t.Helper()
		raw, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"private.internal", "private-container", "/private-health", "/private-mount", "/private-hook"} {
			if bytes.Contains(raw, []byte(secret)) {
				t.Fatal("control retained local publisher configuration", secret)
			}
		}
	}
	assertPrivate(first)
	web := first.Configuration.Services["web"]
	if web.Target != "app" || web.TargetTLS == nil || web.TargetTLS.Hostname != "approved.internal" || web.HTTP == nil ||
		web.HTTP.Access.Mode != "anonymous" || *web.HTTP.Limits.Concurrency != 4 {
		t.Fatal("local projection lost required trust or visitor policy")
	}
	request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint,
		Service: "web", WorktreeKey: "checkout", ActorID: r.ActorID, Now: now, Configuration: r.Configuration.Services["web"]}
	realized, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	before, err := q.GetServiceConfiguration(ctx, realized.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	current, err := d.serviceConfiguration(ctx, q, realized.ServiceID)
	if err != nil {
		t.Fatal(err)
	}
	assertPrivate(current)
	// local listener changes are neither shared configuration changes nor new
	// target trust. the exact local binding and its encrypted policy stay stable.
	request.Configuration.Target = "https://another-private.internal:9443"
	request.Configuration.HTTP.Readiness.Path = "/another-private-health"
	retry, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || retry.ServiceID != realized.ServiceID || retry.Metadata.TrustRevision != realized.Metadata.TrustRevision {
		t.Fatal("local listener edit changed shared identity or trust", err)
	}
	after, err := q.GetServiceConfiguration(ctx, realized.ServiceID)
	if err != nil || !bytes.Equal(before.ConfigurationCiphertext, after.ConfigurationCiphertext) {
		t.Fatal("local listener edit rewrote saved policy", err)
	}
	r.ExpectedRevision = first.Revision
	next, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || next.Revision != first.Revision || next.ConfigurationHash != first.ConfigurationHash {
		t.Fatal("local listener edit advanced shared configuration", err)
	}
	assertPrivate(next)
}
