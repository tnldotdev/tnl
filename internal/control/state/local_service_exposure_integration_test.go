package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationLocalServiceExposureRetainsIdentityAndRuns(t *testing.T) {
	for _, protocol := range []string{"http", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			d, now, _, _ := newPublishRunPrerequisites(t)
			ctx := t.Context()
			if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
				t.Fatal(err)
			}
			r := appliedProjectRequest(t, d, now)
			r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
				"app": {Protocol: protocol, Target: "localhost:3000", Access: &ProjectServiceAccess{Team: true}},
			}}
			r = selectedProjectRequest(r, "local")
			request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "app", WorktreeKey: "checkout-a", WorktreeLabel: "feature-a", ActorID: r.ActorID, Configuration: r.Configuration.Services["app"], Now: now}
			privatePort, publicPort := 0, 25443
			if protocol == "http" {
				privatePort, publicPort = 443, 443
			}
			private, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil || private.Metadata == nil || private.Metadata.Endpoint == nil || private.Metadata.Endpoint.Public || private.Metadata.Endpoint.Port != privatePort {
				t.Fatal("private realization consumed capacity", private, err)
			}
			endpoint := *private.Metadata.Endpoint
			creation := oidcRouteRequest(t, d, now)
			enrollment := publisherEnrollment(t, d, creation, PublisherScope{TeamID: r.TeamID, Kind: "service", ServiceID: private.ServiceID}, now)
			key, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			access, err := d.RedeemPublisherEnrollment(ctx, enrollment.Key, key, now)
			if err != nil {
				t.Fatal(err)
			}
			oldRun, err := d.PrepareServiceRun(ctx, private.ServiceID, access, "local-private", now, ServiceRunRequest{Metadata: *private.Metadata})
			if err != nil {
				t.Fatal(err)
			}
			applied, err := d.ApplyProjectConfiguration(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			setPublic := func(public bool) {
				service := r.Configuration.Services["app"]
				service.Public = new(public)
				r.Configuration.Services["app"] = service
			}
			setPublic(true)
			r.ExpectedRevision = applied.Revision
			public, err := d.ApplyProjectConfiguration(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			record, err := d.GetService(ctx, private.ServiceID, r.ActorID)
			if err != nil || record.Endpoint == nil || !record.Endpoint.Public || record.Endpoint.Port != publicPort || record.Endpoint.Hostname != endpoint.Hostname || record.TrustRevision != private.Metadata.TrustRevision {
				t.Fatal("first public binding lost captured identity or fencing", record, err)
			}
			started, err := d.StartServiceRun(ctx, oldRun.ServiceID, oldRun.RunID, oldRun.RunNumber, access, now)
			if err != nil {
				t.Fatal("first exposure changed the wrong run authority", err)
			}
			if err := d.CloseServiceRun(ctx, oldRun.ServiceID, oldRun.RunID, started.Token, now); err != nil {
				t.Fatal(err)
			}
			next, err := d.PrepareServiceRun(ctx, private.ServiceID, access, "local-public", now, ServiceRunRequest{Metadata: record.ServiceMetadata})
			if err != nil || next.Hostname != record.Endpoint.Hostname {
				t.Fatal("publisher lost its grant or binding", next, err)
			}
			revision := public.Revision
			for _, enabled := range []bool{false, true} {
				setPublic(enabled)
				r.ExpectedRevision = revision
				changed, err := d.ApplyProjectConfiguration(ctx, r)
				if err != nil {
					t.Fatal(err)
				}
				revision = changed.Revision
				current, err := d.GetService(ctx, private.ServiceID, r.ActorID)
				if err != nil || current.Endpoint.Port != record.Endpoint.Port || current.Endpoint.Hostname != endpoint.Hostname || current.Endpoint.Public != enabled || current.TrustRevision != record.TrustRevision {
					t.Fatal("retained exposure changed identity or run authority", current, err)
				}
			}
			if _, err := d.StartServiceRun(ctx, next.ServiceID, next.RunID, next.RunNumber, access, now); err != nil {
				t.Fatal("retained exposure closed the prepared run", err)
			}
			request.Configuration = r.Configuration.Services["app"]
			retry, err := d.RealizeLocalProjectService(ctx, request)
			if err != nil || retry.ServiceID != private.ServiceID || *retry.Metadata.Endpoint != *record.Endpoint {
				t.Fatal("app restart changed its captured endpoint", retry, err)
			}
			projection, err := d.GetProjectPublicMetadata(ctx, r.TeamID, r.ProjectKey, r.ActorID, now)
			if err != nil || protocol == "http" && (len(projection.Services) != 1 || projection.Services[0].ServiceID != private.ServiceID || projection.Services[0].Port != 443 || !opaqueid.Valid(projection.Services[0].ServiceID, opaqueid.ServicePrefix)) || protocol != "http" && len(projection.Services) != 0 {
				t.Fatal("local public projection lost resource identity or exposed a database", projection, err)
			}
		})
	}
}

func TestIntegrationLocalServiceExposureAtomicAcrossWorktrees(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{"app": {Protocol: "postgres", Target: "localhost:5432"}}}
	r = selectedProjectRequest(r, "local")
	request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "app", WorktreeKey: "checkout-a", ActorID: r.ActorID, Configuration: r.Configuration.Services["app"], Now: now}
	first, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	request.WorktreeKey = "checkout-b"
	second, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || first.ServiceID == second.ServiceID {
		t.Fatal("worktrees share a service", second, err)
	}
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	binding := r.Configuration.Services["app"]
	binding.Public = new(true)
	r.Configuration.Services["app"] = binding
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("two worktrees shared one public reservation", err)
	}
	current, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "local")
	if err != nil || current.Revision != applied.Revision || current.Configuration.Services["app"].Public != nil {
		t.Fatal("failed apply committed desired exposure", current, err)
	}
	for _, local := range []LocalProjectService{first, second} {
		saved, err := d.GetService(ctx, local.ServiceID, r.ActorID)
		if err != nil || saved.Endpoint.Public || saved.Endpoint.Port != 0 || saved.TrustRevision != local.Metadata.TrustRevision {
			t.Fatal("failed apply partially changed a worktree", saved, err)
		}
	}
	var claims int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_port_claims`).Scan(&claims); err != nil || claims != 0 {
		t.Fatal("failed apply consumed public capacity", claims, err)
	}
}

func readyLocalExposureRun(t *testing.T, d *Database, local LocalProjectService, actor serviceTestAuthority, leases map[string]RelayLease, now time.Time) (ServiceRunPreparation, ServiceRunState) {
	t.Helper()
	service, err := d.GetService(t.Context(), local.ServiceID, actor.ActingIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, actor, PublisherScope{TeamID: service.TeamID, Kind: "service", ServiceID: service.ID}, now)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, fmt.Sprintf("local-%s", service.ID), now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
			t.Fatal(err)
		}
		if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal(err)
		}
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("local exposure run was not ready", state, err)
	}
	return prepared, run
}

func TestIntegrationLocalServiceExposureFencesDNSWork(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	request := RealizeLocalProjectServiceRequest{
		TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "api", WorktreeKey: "checkout", ActorID: r.ActorID,
		Configuration: ProjectServiceConfiguration{Target: "app"}, DNSAutomation: true, Now: now,
	}
	first, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "private-worker", now, time.Minute); err != nil || found {
		t.Fatal("local private DNS was queued for publication", found, err)
	}

	request.Configuration.Public, request.Now = new(true), now.Add(time.Second)
	public, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || !public.Metadata.Endpoint.Public || public.Metadata.Endpoint.Port != 443 {
		t.Fatal("public startup did not use shared HTTPS", public, err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "public-worker", request.Now, time.Minute); err != nil || found {
		t.Fatal("public DNS published before a routable publisher", found, err)
	}
	if _, err = d.RegisterIngress(ctx, IngressRegistration{
		IngressID: "local-exposure-ingress", IngressRunID: "local-exposure-ingress-run", ProtocolVersion: 1,
		ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID, HTTPS: true,
	}, request.Now, time.Hour); err != nil {
		t.Fatal(err)
	}
	_, run := readyLocalExposureRun(t, d, public, serviceTestAuthority{TeamID: r.TeamID, ActingIdentityID: r.ActorID}, leases, request.Now)
	published, found, err := d.ClaimServiceEndpointDNSWork(ctx, "public-worker", request.Now, time.Minute)
	if err != nil || !found || published.ServiceID != public.ServiceID || !published.Public || published.State != ServiceEndpointDNSPending {
		t.Fatal("public DNS was not claimable with a ready publisher", published, found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, published, request.Now); err != nil {
		t.Fatal(err)
	}
	published.State, published.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err = d.SaveServiceEndpointDNSWork(ctx, published, request.Now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "duplicate", request.Now, time.Minute); err != nil || found {
		t.Fatal("completed public DNS work remained queued", found, err)
	}

	stale := published
	request.Configuration.Public, request.Now = new(false), now.Add(3*time.Second)
	disabled, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || disabled.ServiceID != first.ServiceID || disabled.Metadata.Endpoint.Public {
		t.Fatal("disable changed local service identity", disabled, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, stale, request.Now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("old publication retained provider authority", err)
	}
	stale.State, stale.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, stale, request.Now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("old DNS worker completed the retired public revision", err)
	}
	current, found, err := d.ClaimServiceEndpointDNSWork(ctx, "current-worker", request.Now, time.Minute)
	if err != nil || !found || current.Public || current.State != ServiceEndpointDNSRemoving {
		t.Fatal("disable did not retire public DNS", current, found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, current, request.Now); err != nil {
		t.Fatal("disable invalidated current DNS removal work", err)
	}
	current.State, current.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, current, request.Now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "duplicate", request.Now, time.Minute); err != nil || found {
		t.Fatal("completed DNS removal remained queued", found, err)
	}
	if err := d.CloseServiceRun(ctx, public.ServiceID, run.RunID, run.Token, request.Now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.RealizeLocalProjectService(ctx, request); err != nil {
		t.Fatal(err)
	}
	// even another team manager cannot adopt this app owner's realization.
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	other := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "exposure-manager", TeamRoleAdmin)
	request.ActorID, request.Configuration.Public = other.IdentityID, new(true)
	if _, err := d.RealizeLocalProjectService(ctx, request); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("another identity changed the captured worktree's exposure", err)
	}
}
