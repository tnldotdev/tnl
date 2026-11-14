package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationPrivateServicePortCapacity(t *testing.T) {
	f := newPublishRunFixture(t)
	d, now, ctx := f.database, f.now, t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"api": {Protocol: "tcp", Target: "localhost:3000", Public: new(true)},
	}}
	r = selectedProjectRequest(r, "production")
	first, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || first.Services[0].Port != 25443 {
		t.Fatal("public service did not exhaust the fixture pool", first, err)
	}
	// publication and certificate preparation must work with no remaining port,
	// not only private declaration. this helper starts an enrolled local run.
	run := privateClaimRun(t, f)
	var captured int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_port_claims WHERE service_id=$1`, run.ServiceID).Scan(&captured); err != nil || captured != 0 {
		t.Fatal("private run captured an ingress reservation", captured, err)
	}
	r.ExpectedRevision = first.Revision
	api := r.Configuration.Services["api"]
	api.Public = new(false)
	r.Configuration.Services["api"] = api
	for name, protocol := range map[string]string{"web": "http", "orders": "postgres"} {
		r.Configuration.Services[name] = ProjectServiceConfiguration{Protocol: protocol, Target: "localhost:3000"}
		r.ServiceDeclarations[name] = protocol
	}
	private, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil || len(private.Services) != 3 {
		t.Fatal("private declarations depend on public capacity", private, err)
	}
	for _, service := range private.Services {
		want := 0
		if service.Service == "api" {
			want = 25443
		} else if service.Service == "web" {
			want = 443
		}
		if service.Public || service.Port != want || service.ServiceID == "" || service.Hostname == "" {
			t.Fatal("private identity or retained reservation changed", service)
		}
	}
	var claims int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_port_claims WHERE state='held'`).Scan(&claims); err != nil || claims != 1 {
		t.Fatal("private services consumed public capacity", claims, err)
	}
	// enabling public access is atomic; no partial configuration survives failure.
	r.ExpectedRevision = private.Revision
	orders := r.Configuration.Services["orders"]
	orders.Public = new(true)
	r.Configuration.Services["orders"] = orders
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("public enable ignored exhausted capacity", err)
	}
	current, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || current.Revision != private.Revision || current.Configuration.Services["orders"].Public != nil {
		t.Fatal("failed public enable partially committed", current, err)
	}
}

func TestIntegrationPrivateServiceFirstPublicBindingRetainsRun(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{
		"api": {Protocol: "tcp", Target: "localhost:3000"},
	}}
	r = selectedProjectRequest(r, "production")
	private, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	assignment := replica.assignments.Services[0]
	access := deploymentAssignmentAccess(t, d, replica, assignment, now)
	metadata := ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}
	old, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "private-binding", now, ServiceRunRequest{Metadata: metadata})
	if err != nil || old.Hostname == "" {
		t.Fatal("private preparation lost its managed TLS identity", err)
	}
	r.ExpectedRevision = private.Revision
	serviceConfiguration := r.Configuration.Services["api"]
	serviceConfiguration.Public = new(true)
	r.Configuration.Services["api"] = serviceConfiguration
	public, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	service := public.Services[0]
	if service.ServiceID != assignment.ServiceID || service.Port < 1024 || service.TrustRevision != metadata.TrustRevision {
		t.Fatal("first public binding changed service identity or connector trust", service)
	}
	started, err := d.StartServiceRun(ctx, old.ServiceID, old.RunID, old.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal("first public allocation closed a prepared connector run", err)
	}
	if err := d.CloseServiceRun(ctx, old.ServiceID, old.RunID, started.Token, now); err != nil {
		t.Fatal(err)
	}
	metadata.TrustRevision = service.TrustRevision
	next, err := d.PrepareServiceRun(ctx, service.ServiceID, access.PublisherIdentity, "public-binding", now, ServiceRunRequest{Metadata: metadata})
	if err != nil || next.Hostname != old.Hostname {
		t.Fatal("replacement did not retain its TLS identity", err)
	}
	// disable/re-enable retains the reservation and does not replace this run.
	revision := public.Revision
	for _, enabled := range []bool{false, true} {
		r.ExpectedRevision = revision
		serviceConfiguration.Public = new(enabled)
		r.Configuration.Services["api"] = serviceConfiguration
		changed, err := d.ApplyProjectConfiguration(ctx, r)
		if err != nil || changed.Services[0].Port != service.Port || changed.Services[0].TrustRevision != service.TrustRevision {
			t.Fatal("temporary disablement changed the binding", changed, err)
		}
		revision = changed.Revision
	}
	if _, err := d.StartServiceRun(ctx, next.ServiceID, next.RunID, next.RunNumber, access.PublisherIdentity, now); err != nil {
		t.Fatal("retained binding unnecessarily replaced its prepared run", err)
	}
}
