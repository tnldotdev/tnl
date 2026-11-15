package state

import (
	"errors"
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
	key := controlstatedb.ReadVisitorPolicyRevisionParams{ResourceKind: "service", ResourceID: service.ID}
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
	staleTrust := service.ServiceMetadata
	staleTrust.TrustRevision++
	if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, staleTrust, saved, ServiceUpdateConditions{ConfigurationDigest: nextDigest}, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("matching digest bypassed the independent trust condition", err)
	}
}
