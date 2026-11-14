package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
)

func TestIntegrationPublisherAllocationIntentAndLease(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "allocation_intent")
	r := oidcRouteRequest(t, d, now)
	enrollment := publisherEnrollment(t, d, r, PublisherScope{TeamID: r.TeamID, Kind: "namespace", DomainID: r.DomainID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request := AllocateServiceRequest{Invocation: invocation, Configuration: ProjectServiceConfiguration{
		Target: "https://app.internal:3000", TargetTLS: &ProjectTargetTLS{Hostname: "app.internal"},
		RequirePostQuantum: new(true), HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}, Limits: &config.WorkLimits{Total: new(10)}},
	}}
	service, err := d.AllocatePublisherService(t.Context(), p, request, now)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := d.serviceConfiguration(t.Context(), controlstatedb.New(d.pool), service.ID)
	if err != nil || saved == nil || saved.Target != "app.internal:3000" || saved.TargetTLS == nil ||
		saved.TargetTLS.Hostname != "app.internal" || saved.HTTP.Access.IP[0] != "192.0.2.0/24" || !service.RequirePostQuantum || service.ExpiresAt != nil {
		t.Fatal("allocation lost protected normalized declaration or invented a hard lifetime", err)
	}
	retry := request
	retry.Configuration = *saved
	again, err := d.AllocatePublisherService(t.Context(), p, retry, now)
	if err != nil || !reflect.DeepEqual(service, again) {
		t.Fatal("normalized equivalent intent did not recover its original service", err)
	}
	for _, change := range []func(*ProjectServiceConfiguration){
		func(s *ProjectServiceConfiguration) { s.Target = "other.internal:3000" },
		func(s *ProjectServiceConfiguration) { s.TargetTLS = &ProjectTargetTLS{Hostname: "other.internal"} },
		func(s *ProjectServiceConfiguration) { s.RequirePostQuantum = new(false) },
		func(s *ProjectServiceConfiguration) {
			s.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
		},
		func(s *ProjectServiceConfiguration) {
			s.HTTP = &config.HTTPService{Access: &config.Access{IP: []string{"198.51.100.0/24"}}}
		},
		func(s *ProjectServiceConfiguration) {
			s.HTTP = &config.HTTPService{Limits: &config.WorkLimits{Total: new(20)}}
		},
		func(s *ProjectServiceConfiguration) { s.Traffic = &trafficlimits.Selection{Connections: new(10)} },
	} {
		changed := request
		change(&changed.Configuration)
		if _, err := d.AllocatePublisherService(t.Context(), p, changed, now); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("changed invocation intent did not conflict", err)
		}
	}
	_, _, _, _ = publishRunPrerequisitesInDatabase(t, d, now, nil)
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, p, "namespace-allocation", now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	if prepared.PublisherIdentityID != p.ID || prepared.PublisherGrantID != p.GrantID || prepared.PublisherKeyID != p.KeyID ||
		prepared.CertificatePlan.Scope != service.Endpoint.Hostname || !reflect.DeepEqual(prepared.CertificatePlan.Identifiers, []string{service.Endpoint.Hostname}) {
		t.Fatal("namespace service changed its root authority or borrowed a wildcard")
	}
	run, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, p, now)
	if err != nil {
		t.Fatal(err)
	}
	for elapsed := 30 * time.Second; elapsed <= 3*time.Minute; elapsed += 30 * time.Second {
		if _, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now.Add(elapsed), ServiceRunHealth{StreamCapacity: 64}); err != nil {
			t.Fatal("sliding run lease became a hard two-minute service lifetime", err)
		}
	}
	if _, err := d.AllocatePublisherService(t.Context(), p, request, now.Add(3*time.Minute)); err != nil {
		t.Fatal("active allocation recovery expired without a fixed deadline", err)
	}
}

func TestIntegrationDeploymentAllocationFixedExpiryAndCurrentApproval(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	_, _, access, _ := f.approve(t, map[string][]string{"publish": {"web"}}, "anonymous")
	request := f.allocation(t, access)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, access.GrantID, f.now.Add(10*time.Minute)); err != nil {
		t.Fatal(err)
	}
	deadline := f.now.Add(15*time.Minute + 137*time.Nanosecond)
	request.ExpiresAt = &deadline
	service, err := f.d.AllocateDeploymentPublication(t.Context(), request)
	if err != nil || service.ExpiresAt == nil || !service.ExpiresAt.Before(deadline) {
		t.Fatal("caller deadline was not clipped to the parent grant", err)
	}
	captured := *service.ExpiresAt
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET expires_at=$2 WHERE id=$1`, access.GrantID, deadline.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	again, err := f.d.AllocateDeploymentPublication(t.Context(), request)
	if err != nil || again.ExpiresAt == nil || !again.ExpiresAt.Equal(captured) {
		t.Fatal("retry extended a captured fixed deadline", err)
	}
	changed := request
	changed.ExpiresAt = nil
	if _, err := f.d.AllocateDeploymentPublication(t.Context(), changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("retry changed its requested fixed deadline", err)
	}
	anonymous := f.allocation(t, access)
	anonymous.Configuration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
	public, err := f.d.AllocateDeploymentPublication(t.Context(), anonymous)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.deployment_management_grants SET temporary_publication='restricted' WHERE grant_id=$1`, access.GrantID); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.GetServiceForPublisher(t.Context(), public.ID, access.PublisherIdentity, f.now); err == nil {
		t.Fatal("anonymous allocation survived restricted current approval")
	}
	if err := f.d.DeletePublisherService(t.Context(), access.PublisherIdentity, public.ID, f.now); err == nil {
		t.Fatal("publisher deleted without current required temporary approval")
	}
	if _, err := f.d.GetServiceForPublisher(t.Context(), service.ID, access.PublisherIdentity, f.now); err != nil {
		t.Fatal("restricted allocation depended on anonymous approval", err)
	}
	if _, err := f.d.GetDeploymentPublication(t.Context(), f.scope(access), "production", "web", f.now); err != nil {
		t.Fatal("temporary approval changed independent named approval", err)
	}
}
