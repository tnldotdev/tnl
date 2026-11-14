package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

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
			revisionIncrement := int64(1)
			if protocol == "http" {
				privatePort, publicPort, revisionIncrement = 443, 443, 0
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
			oldRun, err := d.PrepareServiceRun(ctx, private.ServiceID, access, "local-private", now, *private.Metadata)
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
			if err != nil || record.Endpoint == nil || !record.Endpoint.Public || record.Endpoint.Port != publicPort || record.Endpoint.Hostname != endpoint.Hostname || record.TrustRevision != private.Metadata.TrustRevision+revisionIncrement {
				t.Fatal("first public binding lost captured identity or fencing", record, err)
			}
			started, err := d.StartServiceRun(ctx, oldRun.ServiceID, oldRun.RunID, oldRun.RunNumber, access, now)
			if protocol == "http" && err != nil || protocol != "http" && !errors.Is(err, ErrServiceAccess) {
				t.Fatal("first exposure changed the wrong run authority", err)
			}
			if protocol == "http" {
				if err := d.CloseServiceRun(ctx, oldRun.ServiceID, oldRun.RunID, started.Token, now); err != nil {
					t.Fatal(err)
				}
			}
			next, err := d.PrepareServiceRun(ctx, private.ServiceID, access, "local-public", now, record.ServiceMetadata)
			if err != nil || next.ServicePort != record.Endpoint.Port {
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
			if err != nil || protocol == "http" && (len(projection.Services) != 1 || projection.Services[0].ServiceID != private.ServiceID || projection.Services[0].Port != 443 || projection.Services[0].PublicURLID != "") || protocol != "http" && len(projection.Services) != 0 {
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

func TestIntegrationLocalServiceExposureFencesDNSWork(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
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
	private, found, err := d.ClaimServiceEndpointDNSWork(ctx, "private-worker", now, time.Minute)
	if err != nil || !found || private.Public || private.ServiceID != first.ServiceID {
		t.Fatal("local private DNS was not queued", private, found, err)
	}
	request.Configuration.Public, request.Now = new(true), now.Add(time.Second)
	public, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || !public.Metadata.Endpoint.Public || public.Metadata.Endpoint.Port != 443 {
		t.Fatal("public startup did not use shared HTTPS", public, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, private, request.Now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatal("old loopback worker retained provider authority", err)
	}
	private.State = PublicURLDNSPublished
	if _, err := d.SaveServiceEndpointDNSWork(ctx, private, request.Now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatal("old DNS worker completed the new public revision", err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "public-worker", request.Now, time.Minute); err != nil || found {
		t.Fatal("public DNS published before a routable publisher", found, err)
	}
	request.Configuration.Public, request.Now = new(false), now.Add(2*time.Second)
	disabled, err := d.RealizeLocalProjectService(ctx, request)
	if err != nil || disabled.ServiceID != first.ServiceID || disabled.Metadata.Endpoint.Port != public.Metadata.Endpoint.Port || disabled.Metadata.Endpoint.Public {
		t.Fatal("disable released a local reservation", disabled, err)
	}
	current, found, err := d.ClaimServiceEndpointDNSWork(ctx, "current-worker", request.Now, time.Minute)
	if err != nil || !found || current.Public || current.Revision <= private.Revision {
		t.Fatal("disable did not replace public DNS with loopback", current, found, err)
	}
	if _, err := d.RealizeLocalProjectService(ctx, request); err != nil {
		t.Fatal(err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, current, request.Now); err != nil {
		t.Fatal("idempotent startup invalidated current DNS work", err)
	}
	current.State, current.AvailableAt = PublicURLDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, current, request.Now); err != nil {
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
