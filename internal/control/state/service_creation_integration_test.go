package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestIntegrationCreateServiceDeclaration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "create_declaration")
	actor := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	configuration := ProjectServiceConfiguration{
		Target: "https://origin.internal:8443", TargetTLS: appliedTargetTrust(t, "origin.internal"),
		Hostname: actor.CanonicalHostname, DomainID: actor.DomainID,
		Public: new(true), Ephemeral: true, RequirePostQuantum: new(true),
		Traffic: &trafficlimits.Selection{Connections: new(7), Rate: new(2), RatePer: new("2000ms")},
		HTTP: &config.HTTPService{
			Access: &config.Access{Mode: "anonymous", IP: []string{"192.0.2.10"}},
			Limits: &config.WorkLimits{Concurrency: new(3), Total: new(100)},
		},
	}
	before, err := json.Marshal(configuration)
	if err != nil {
		t.Fatal(err)
	}
	created, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "declared", "create", ServicePlacement{}, now, ServiceMetadata{}, &configuration)
	if err != nil {
		t.Fatal(err)
	}
	after, err := json.Marshal(configuration)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("creation mutated the caller's declaration", err)
	}
	if created.Protocol != "http" || !created.Ephemeral || !created.RequirePostQuantum || created.Endpoint == nil ||
		!created.Endpoint.Public || created.Endpoint.Hostname != configuration.Hostname || created.Endpoint.Port != 443 ||
		created.DomainID != configuration.DomainID || created.Source != nil {
		t.Fatal("declaration did not select the exact service endpoint and lifecycle", created)
	}
	q := controlstatedb.New(d.pool)
	saved, err := q.GetServiceConfiguration(ctx, created.ID)
	if err != nil || saved.LocalOwned || saved.DeploymentOwned || saved.AllocationOwned || len(saved.ConfigurationCiphertext) == 0 || !saved.StorageKeyID.Valid {
		t.Fatal("creation did not save one service-owned encrypted declaration", err)
	}
	for _, secret := range []string{"origin.internal", "192.0.2.10", "BEGIN CERTIFICATE", `"traffic"`} {
		if bytes.Contains(saved.ConfigurationCiphertext, []byte(secret)) {
			t.Fatal("declaration was stored as plaintext")
		}
	}
	normalized, err := d.serviceConfiguration(ctx, q, created.ID)
	if err != nil || normalized == nil || normalized.Name != "declared" || normalized.Target != "origin.internal:8443" ||
		normalized.Protocol != "http" || *normalized.Traffic.RatePer != "2s" || normalized.HTTP.Access.IP[0] != "192.0.2.10/32" {
		t.Fatal("creation did not persist the canonical normalized declaration", err)
	}
	mode, err := d.serviceHTTPSourcePolicy(ctx, q, created.ID, netip.MustParseAddr("192.0.2.10"))
	if err != nil || mode != VisitorAccessAnonymous {
		t.Fatal("creation lost its HTTP access policy", mode, err)
	}
	if _, err := d.serviceHTTPSourcePolicy(ctx, q, created.ID, netip.MustParseAddr("203.0.113.10")); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("creation lost its source policy", err)
	}
	settings, err := d.serviceHTTPSettings(ctx, q, created.ID)
	if err != nil || settings == nil || settings.Limits == nil || *settings.Limits.Concurrency != 3 || *settings.Limits.Total != 100 {
		t.Fatal("HTTP request budgets were replaced by ingress traffic", err)
	}
	equivalent := *normalized
	recovered, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "declared", "create", ServicePlacement{}, now, ServiceMetadata{}, &equivalent)
	if err != nil || recovered.ID != created.ID || recovered.EndpointRevision != created.EndpointRevision {
		t.Fatal("normalized retry did not recover the exact service", err)
	}
	stillSaved, err := q.GetServiceConfiguration(ctx, created.ID)
	if err != nil || !reflect.DeepEqual(saved, stillSaved) {
		t.Fatal("exact retry rewrote encrypted intent", err)
	}
	for name, change := range map[string]func(*ProjectServiceConfiguration){
		"target":    func(s *ProjectServiceConfiguration) { s.Target = "different.internal:8443" },
		"public":    func(s *ProjectServiceConfiguration) { s.Public = new(false) },
		"ephemeral": func(s *ProjectServiceConfiguration) { s.Ephemeral = false },
		"pq":        func(s *ProjectServiceConfiguration) { s.RequirePostQuantum = new(false) },
		"hostname":  func(s *ProjectServiceConfiguration) { s.Hostname = "changed." + actor.CanonicalHostname },
		"tls":       func(s *ProjectServiceConfiguration) { s.TargetTLS = appliedTargetTrust(t, "different.internal") },
		"traffic":   func(s *ProjectServiceConfiguration) { s.Traffic = &trafficlimits.Selection{Connections: new(8)} },
		"http policy": func(s *ProjectServiceConfiguration) {
			s.HTTP = &config.HTTPService{Access: &config.Access{Mode: "restricted"}}
		},
		"http limits": func(s *ProjectServiceConfiguration) {
			s.HTTP = &config.HTTPService{Limits: &config.WorkLimits{Total: new(101)}}
		},
		"protocol": func(s *ProjectServiceConfiguration) { s.Protocol, s.HTTP = "tcp", nil },
	} {
		t.Run(name, func(t *testing.T) {
			changed := equivalent
			change(&changed)
			if _, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "declared", "create", ServicePlacement{}, now, ServiceMetadata{}, &changed); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("create retry changed saved intent", err)
			}
		})
	}
	if _, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "declared", "create", ServicePlacement{}, now, created.ServiceMetadata, nil); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("metadata-only retry discarded a saved declaration", err)
	}
	if err := d.DeleteService(ctx, created.ID, actor.ActingIdentityID, observedServiceDeletion(t, d, created.ID), now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "declared", "create", ServicePlacement{}, now, ServiceMetadata{}, &equivalent); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("create retry revived a deleted service", err)
	}
}

func TestIntegrationCreatePlainServiceRemainsDeclarationFree(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "create_plain_service")
	actor := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	metadata := ServiceMetadata{Protocol: "tcp"}
	created, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "plain", "plain", ServicePlacement{}, now, metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	if created.Endpoint == nil || created.Endpoint.Public || created.Endpoint.Port != 0 || created.Ephemeral || created.RequirePostQuantum || created.Source != nil {
		t.Fatal("plain metadata-only creation changed", created)
	}
	q := controlstatedb.New(d.pool)
	if declaration, err := d.serviceConfiguration(ctx, q, created.ID); err != nil || declaration != nil {
		t.Fatal("plain creation acquired a declaration", err)
	}
	recovered, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "plain", "plain", ServicePlacement{}, now, metadata, nil)
	if err != nil || recovered.ID != created.ID {
		t.Fatal("plain create retry changed", err)
	}
	configuration := &ProjectServiceConfiguration{Protocol: "tcp", Target: "database.internal:5432"}
	if _, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "plain", "plain", ServicePlacement{}, now, metadata, configuration); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("create retry attached another declaration", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.services SET name_scope='deployment/other' WHERE id=$1`, created.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "plain", "plain", ServicePlacement{}, now, metadata, nil); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("create retry adopted another ownership scope", err)
	}
}

func TestIntegrationCreateServiceDeclarationRejectsContradictoryMetadataUpdates(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "create_declaration_metadata")
	actor := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	for _, id := range []string{"declaration-a", "declaration-b"} {
		if _, err := d.RegisterRelay(ctx, relayLifecycleRegistration(id), now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	configuration := &ProjectServiceConfiguration{
		Target: "https://origin.internal:8443", TargetTLS: appliedTargetTrust(t, "origin.internal"),
		Public: new(true), HTTP: &config.HTTPService{
			Access: &config.Access{Mode: "anonymous"},
			Limits: &config.WorkLimits{Concurrency: new(3)},
		},
		Traffic: &trafficlimits.Selection{Connections: new(7)},
	}
	service, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "immutable", "immutable", ServicePlacement{}, now, ServiceMetadata{}, configuration)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: service.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "current-run", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if err := d.CloseServiceRun(cleanup, service.ID, run.RunID, run.Token, now); err != nil {
			t.Error(err)
		}
	})
	q := controlstatedb.New(d.pool)
	stored, err := q.GetServiceConfiguration(ctx, service.ID)
	if err != nil {
		t.Fatal(err)
	}
	declaration, err := d.serviceConfiguration(ctx, q, service.ID)
	if err != nil {
		t.Fatal(err)
	}
	projection, err := d.GetServiceForPublisher(ctx, service.ID, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	policyKey := service.ID
	policyRevision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
	if err != nil {
		t.Fatal(err)
	}
	authority := func() []byte {
		t.Helper()
		var data []byte
		if err := d.pool.QueryRow(ctx, `SELECT jsonb_build_object(
		    'runs',(SELECT jsonb_agg(to_jsonb(run) ORDER BY run.id) FROM control.service_runs run WHERE run.service_id=$1),
		    'slots',(SELECT jsonb_agg(to_jsonb(slot) ORDER BY slot.publisher_connection_id) FROM control.service_connection_slots slot WHERE slot.service_id=$1))`,
			service.ID).Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	}
	beforeAuthority := authority()
	changedTrust, err := appliedServiceTargetTrust(appliedTargetTrust(t, "different.internal"))
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*ServiceMetadata){
		"remove trust": func(m *ServiceMetadata) { m.TLS = nil },
		"change trust": func(m *ServiceMetadata) { m.TLS = changedTrust },
		"protocol":     func(m *ServiceMetadata) { m.Protocol = "tcp" },
	} {
		t.Run(name, func(t *testing.T) {
			metadata := service.ServiceMetadata
			change(&metadata)
			if _, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, metadata, nil, ServiceUpdateConditions{}, now); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("metadata-only update contradicted a service-owned declaration", err)
			}
			currentStored, err := q.GetServiceConfiguration(ctx, service.ID)
			if err != nil || !reflect.DeepEqual(stored, currentStored) {
				t.Fatal("rejected metadata update changed encrypted declaration storage", err)
			}
			currentDeclaration, err := d.serviceConfiguration(ctx, q, service.ID)
			if err != nil || !reflect.DeepEqual(declaration, currentDeclaration) {
				t.Fatal("rejected metadata update changed the canonical declaration", err)
			}
			currentProjection, err := d.GetServiceForPublisher(ctx, service.ID, publisher, now)
			if err != nil || !reflect.DeepEqual(projection, currentProjection) {
				t.Fatal("rejected metadata update changed endpoint, trust revision, or publisher HTTP limits", err)
			}
			currentRevision, err := q.ReadVisitorPolicyRevision(ctx, policyKey)
			if err != nil || currentRevision != policyRevision || !bytes.Equal(beforeAuthority, authority()) {
				t.Fatal("rejected metadata update changed visitor policy, run token, lease, or relay assignments", err)
			}
		})
	}
	if unchanged, err := d.ConfigureService(ctx, service.ID, actor.ActingIdentityID, service.ServiceMetadata, nil, ServiceUpdateConditions{}, now); err != nil ||
		!reflect.DeepEqual(unchanged.ServiceMetadata, service.ServiceMetadata) {
		t.Fatal("matching metadata could not retain the declaration", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 1}); err != nil {
		t.Fatal("rejected metadata updates revoked the existing run's authority", err)
	}
	plain, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "ordinary", "ordinary", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	plainMetadata := plain.ServiceMetadata
	plainMetadata.Protocol = "postgres"
	updated, err := d.ConfigureService(ctx, plain.ID, actor.ActingIdentityID, plainMetadata, nil, ServiceUpdateConditions{}, now)
	if err != nil || updated.Protocol != "postgres" || updated.TrustRevision != plain.TrustRevision+1 || updated.Endpoint == nil || updated.Endpoint.Public {
		t.Fatal("declaration guard changed ordinary metadata-only service updates", err)
	}
	if declaration, err := d.serviceConfiguration(ctx, q, plain.ID); err != nil || declaration != nil {
		t.Fatal("ordinary metadata update invented a declaration", err)
	}
}

func TestCreateServiceDeclarationRejectsConflictingSelectors(t *testing.T) {
	for name, change := range map[string]func(*ServiceMetadata, *ServicePlacement, *ProjectServiceConfiguration){
		"protocol": func(m *ServiceMetadata, _ *ServicePlacement, _ *ProjectServiceConfiguration) { m.Protocol = "tcp" },
		"trust": func(m *ServiceMetadata, _ *ServicePlacement, _ *ProjectServiceConfiguration) {
			m.TLS = &ServiceTargetTLS{Hostname: "other.internal"}
		},
		"hostname": func(_ *ServiceMetadata, p *ServicePlacement, s *ProjectServiceConfiguration) {
			p.Hostname, s.Hostname = "a.example.test", "b.example.test"
		},
		"domain": func(_ *ServiceMetadata, p *ServicePlacement, s *ProjectServiceConfiguration) {
			p.DomainID, s.DomainID = "dom_0123456789ABCDEFGHIJKL", "dom_1123456789ABCDEFGHIJKL"
		},
	} {
		t.Run(name, func(t *testing.T) {
			metadata, placement := ServiceMetadata{}, ServicePlacement{}
			configuration := ProjectServiceConfiguration{Target: "http://origin.internal:8080"}
			change(&metadata, &placement, &configuration)
			// disagreement must fail before opening a transaction.
			var d *Database
			if _, err := d.CreateServiceAt(t.Context(), "team", "actor", "web", "create", placement, time.Now(), metadata, &configuration); !errors.Is(err, ErrServiceConflict) {
				t.Fatal("conflicting selectors were merged", err)
			}
		})
	}
}
