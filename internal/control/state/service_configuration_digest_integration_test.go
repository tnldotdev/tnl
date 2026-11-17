package state

import (
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestServiceConfigurationDigestInputBounds(t *testing.T) {
	valid := "sha256:" + strings.Repeat("a", 64)
	empty, err := serviceConfigurationDigest(nil)
	repeated, repeatedErr := serviceConfigurationDigest(nil)
	if err != nil || repeatedErr != nil || empty != repeated || !ValidServiceConfigurationDigest(empty) {
		t.Fatal("absent declaration digest is not deterministic", err, repeatedErr)
	}
	for _, bad := range []string{valid[:70], valid + "a", strings.ToUpper(valid), `"` + valid + `"`, "W/\"" + valid + "\"", "sha256:" + strings.Repeat("g", 64)} {
		if ValidServiceConfigurationDigest(bad) {
			t.Fatal("accepted a malformed digest")
		}
		var d *Database
		if _, err := d.ConfigureService(t.Context(), "service", "actor", ServiceMetadata{Protocol: "http"},
			&ProjectServiceConfiguration{Target: "localhost:3000"}, ServiceUpdateConditions{ConfigurationDigest: bad}, time.Now()); !errors.Is(err, ErrProjectConfigurationInvalid) {
			t.Fatal("malformed digest reached service storage", err)
		}
	}
	var d *Database
	if _, err := d.ConfigureService(t.Context(), "service", "actor", ServiceMetadata{Protocol: "http"}, nil, ServiceUpdateConditions{ConfigurationDigest: valid}, time.Now()); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("accepted a configuration condition without a replacement", err)
	}
	for _, test := range []struct {
		name          string
		configuration *ProjectServiceConfiguration
		conditions    ServiceUpdateConditions
	}{
		{"missing condition", &ProjectServiceConfiguration{Target: "localhost:3000"}, ServiceUpdateConditions{}},
		{"both conditions", &ProjectServiceConfiguration{Target: "localhost:3000"}, ServiceUpdateConditions{ConfigurationDigest: valid, UnconditionalConfiguration: true}},
		{"unconditional without replacement", nil, ServiceUpdateConditions{UnconditionalConfiguration: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := d.ConfigureService(t.Context(), "service", "actor", ServiceMetadata{Protocol: "http"},
				test.configuration, test.conditions, time.Now()); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("invalid configuration condition reached service storage", err)
			}
		})
	}
}

func TestIntegrationServiceConfigurationConditionalReplacement(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "configuration_digest")
	actor := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	configuration := ProjectServiceConfiguration{
		Target: "https://private-listener.internal:8443", TargetTLS: appliedTargetTrust(t, "private-listener.internal"),
		RequirePostQuantum: new(true), HTTP: &config.HTTPService{
			Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.10"}},
			Limits: &config.WorkLimits{Total: new(100)},
		},
	}
	service, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "conditional", "conditional",
		ServicePlacement{}, now, ServiceMetadata{}, &configuration)
	if err != nil {
		t.Fatal(err)
	}
	current, digest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
	if err != nil || current == nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(d.pool)
	key := service.ID
	beforeRevision, err := q.ReadVisitorPolicyRevision(ctx, key)
	if err != nil {
		t.Fatal(err)
	}
	var replacements [2]*ProjectServiceConfiguration
	for i := range replacements {
		replacements[i], err = normalizeServiceConfiguration(service.Name, current)
		if err != nil {
			t.Fatal(err)
		}
		replacements[i].HTTP.Limits.Total = new(101 + i)
	}
	type result struct {
		index int
		value ServiceRecord
		err   error
	}
	start, results := make(chan struct{}), make(chan result, 2)
	for i := range replacements {
		go func() {
			<-start
			value, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, service.ServiceMetadata, replacements[i], ServiceUpdateConditions{ConfigurationDigest: digest}, now)
			results <- result{i, value, err}
		}()
	}
	close(start)
	completed := []result{<-results, <-results}
	winner, conflicts := -1, 0
	for _, result := range completed {
		switch {
		case result.err == nil:
			if winner != -1 || result.value.ID != service.ID || result.value.TrustRevision != service.TrustRevision ||
				result.value.EndpointRevision != service.EndpointRevision {
				t.Fatal("concurrent policy edits both committed or changed trust/endpoint identity")
			}
			winner = result.index
		case errors.Is(result.err, ErrServiceConflict):
			conflicts++
		default:
			t.Fatal("unexpected conditional replacement failure", result.err)
		}
	}
	if winner < 0 || conflicts != 1 {
		t.Fatal("old digest did not reject exactly one concurrent replacement")
	}
	saved, nextDigest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
	if err != nil || nextDigest == digest || !reflect.DeepEqual(saved, replacements[winner]) {
		t.Fatal("conditional edit lost canonical target, HTTP, or target-trust fields", err)
	}
	afterRevision, err := q.ReadVisitorPolicyRevision(ctx, key)
	if err != nil || afterRevision != beforeRevision+1 {
		t.Fatal("rejected replacement changed visitor policy", err)
	}
	if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, service.ServiceMetadata, saved, ServiceUpdateConditions{ConfigurationDigest: digest}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("old digest bypassed comparison for identical desired intent", err)
	}
	if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, service.ServiceMetadata, saved, ServiceUpdateConditions{ConfigurationDigest: nextDigest}, now); err != nil {
		t.Fatal("reread after a lost response could not retry current intent", err)
	}
	if revision, err := q.ReadVisitorPolicyRevision(ctx, key); err != nil || revision != afterRevision {
		t.Fatal("exact conditional retry reset visitor policy", err)
	}
	snapshot := func() string {
		t.Helper()
		var snapshot string
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
		    'service',(SELECT to_jsonb(s) FROM control.services s WHERE id=$1),
		    'runs',(SELECT jsonb_agg(to_jsonb(r) ORDER BY id) FROM control.service_runs r WHERE service_id=$1),
		    'policy',(SELECT revision FROM control.visitor_policies WHERE resource_id=$1),
		    'endpoints',(SELECT jsonb_agg(to_jsonb(e) ORDER BY hostname) FROM control.service_endpoints e WHERE service_id=$1),
		    'audit',(SELECT jsonb_agg(to_jsonb(a) ORDER BY cursor) FROM control.service_audit_events a WHERE service_id=$1))::text`,
			service.ID).Scan(&snapshot); err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	beforeRejected := snapshot()
	staleReplacement, err := normalizeServiceConfiguration(service.Name, current)
	if err != nil {
		t.Fatal(err)
	}
	staleReplacement.Target = "replacement.internal:8443"
	staleReplacement.HTTP = nil
	staleReplacement.Ephemeral = true
	staleMetadata := service.ServiceMetadata
	staleMetadata.PublisherPool = true
	for _, test := range []struct {
		name       string
		conditions ServiceUpdateConditions
		want       error
	}{
		{"missing fingerprint", ServiceUpdateConditions{}, ErrProjectConfigurationInvalid},
		{"stale fingerprint", ServiceUpdateConditions{ConfigurationDigest: digest}, ErrServiceConflict},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, staleMetadata, staleReplacement, test.conditions, now); !errors.Is(err, test.want) {
				t.Fatal("configuration replacement bypassed its full fingerprint", err)
			}
			if snapshot() != beforeRejected {
				t.Fatal("rejected configuration partially changed metadata, declaration, policy, runs, endpoints, or audit")
			}
		})
	}
	staleTrust := service.ServiceMetadata
	staleTrust.TrustRevision++
	if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, staleTrust, saved, ServiceUpdateConditions{ConfigurationDigest: nextDigest}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("matching digest bypassed the independent trust condition", err)
	}
	if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, staleTrust, staleReplacement, ServiceUpdateConditions{UnconditionalConfiguration: true}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("unconditional configuration bypassed the trust revision condition", err)
	}
	if snapshot() != beforeRejected {
		t.Fatal("rejected trust condition changed saved configuration state")
	}
	forced, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, service.ServiceMetadata, staleReplacement, ServiceUpdateConditions{UnconditionalConfiguration: true}, now)
	if err != nil || forced.TrustRevision != service.TrustRevision {
		t.Fatal("explicit unconditional replacement failed or changed target trust", err)
	}
	forcedSaved, forcedDigest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
	if err != nil || forcedDigest == nextDigest || !reflect.DeepEqual(forcedSaved, staleReplacement) {
		t.Fatal("unconditional replacement retained the newer declaration", err)
	}
}

func TestIntegrationServiceConfigurationOmissionResetsDefaults(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "configuration_defaults")
	actor := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	for _, test := range []struct {
		name string
		http *config.HTTPService
	}{
		{"http-omitted", nil},
		{"http-empty", &config.HTTPService{}},
		{"access-empty", &config.HTTPService{Access: &config.Access{}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			original := ProjectServiceConfiguration{
				Target: "localhost:3000", RequirePostQuantum: new(true),
				HTTP: &config.HTTPService{
					RequestBodyIdleTimeout: new(config.Duration(45 * time.Second)),
					Access:                 &config.Access{Mode: "anonymous", IP: []string{"192.0.2.10"}},
					Limits:                 &config.WorkLimits{Total: new(100), Concurrency: new(2)},
				},
			}
			service, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, test.name, test.name,
				ServicePlacement{}, now, ServiceMetadata{}, &original)
			if err != nil {
				t.Fatal(err)
			}
			_, digest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
			if err != nil {
				t.Fatal(err)
			}
			replacement := ProjectServiceConfiguration{Target: "localhost:4000", HTTP: test.http}
			updated, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, service.ServiceMetadata, &replacement,
				ServiceUpdateConditions{ConfigurationDigest: digest}, now)
			if err != nil || updated.RequirePostQuantum || updated.TrustRevision != service.TrustRevision {
				t.Fatal("replacement retained omitted post-quantum setting or changed target trust", err)
			}
			want, err := normalizeServiceConfiguration(service.Name, &replacement)
			if err != nil {
				t.Fatal(err)
			}
			saved, nextDigest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
			if err != nil || nextDigest == digest || !reflect.DeepEqual(saved, want) {
				t.Fatal("replacement merged old configuration into omitted settings", err)
			}
			q := controlstatedb.New(d.pool)
			settings, err := d.serviceHTTPSettings(ctx, q, service.ID)
			if err != nil || settings != nil && (settings.Limits != nil || settings.RequestBodyIdleTimeout != nil) {
				t.Fatal("omitted request limits retained the old override", err)
			}
			for _, source := range []string{"192.0.2.10", "203.0.113.10"} {
				mode, err := d.serviceHTTPSourcePolicy(ctx, q, service.ID, netip.MustParseAddr(source))
				if err != nil || mode != VisitorAccessRestricted {
					t.Fatal("omitted access did not reset to restricted with no IP filter", mode, err)
				}
			}
		})
	}
}
