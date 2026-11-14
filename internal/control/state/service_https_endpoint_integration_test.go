package state

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationServiceHTTPSHasNoExclusiveReservation(t *testing.T) {
	d, now, r, applied, service := serviceReleaseProject(t, "http", false)
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, nil); err != nil {
		t.Fatal("shared HTTPS pinned the non-HTTP port inventory", err)
	}
	assertEndpoint := func(public bool) {
		t.Helper()
		current, err := d.GetService(ctx, service.ID, r.ActorID)
		if err != nil || current.Endpoint == nil || current.Endpoint.Port != 443 || current.Endpoint.Public != public ||
			current.Endpoint.Hostname != service.Endpoint.Hostname || current.TrustRevision != service.TrustRevision {
			t.Fatal("HTTPS exposure changed the service transport identity", current, err)
		}
		var claims int
		if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.service_port_claims WHERE service_id=$1`, service.ID).Scan(&claims); err != nil || claims != 0 {
			t.Fatal("HTTPS allocated exclusive capacity", claims, err)
		}
	}
	assertEndpoint(true)
	setReleaseProjectExposure(t, d, &r, &applied, false)
	assertEndpoint(false)
	publisher := serviceReleasePublisher(t, d, r, now)
	prepared, err := d.PrepareServiceRun(ctx, service.ID, publisher, "shared-https", now, service.ServiceMetadata)
	if err != nil || prepared.ServicePort != 443 {
		t.Fatal("connector-only HTTP lost its HTTPS transport identity", prepared, err)
	}
	for _, public := range []bool{true, false, true} {
		setReleaseProjectExposure(t, d, &r, &applied, public)
		assertEndpoint(public)
		if _, err := d.ReleaseServiceEndpoint(ctx, service.ID, r.ActorID, service.TrustRevision, 443, now); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("shared HTTPS was treated as an exclusive reservation", err)
		}
	}
	if _, err := d.StartServiceRun(ctx, service.ID, prepared.RunID, prepared.RunNumber, publisher, now); err != nil {
		t.Fatal("exposure or release attempt invalidated the prepared run", err)
	}
	// HTTPS also remains independent when the pool has held non-HTTP capacity.
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = applied.Revision
	r.Configuration.Services["db"] = ProjectServiceConfiguration{Protocol: "postgres", Target: "localhost:5432", Public: new(true)}
	r.ServiceDeclarations["db"] = "postgres"
	withDatabase, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, nil); !errors.Is(err, ErrServicePortsInUse) {
		t.Fatal("empty inventory discarded a held non-HTTP reservation", err)
	}
	r.ExpectedRevision = withDatabase.Revision
	r.Configuration.Services["other"] = r.Configuration.Services["app"]
	r.ServiceDeclarations["other"] = "http"
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal("exhausted non-HTTP capacity blocked another HTTPS service", err)
	}
	assertEndpoint(true)
}

func TestIntegrationServiceHTTPSRequiresIngressCapabilityForDNSAndVisitors(t *testing.T) {
	d, now, _, relays := newPublishRunPrerequisites(t)
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, nil); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.DNSAutomation = true
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"web": {Target: "localhost:3000", Public: new(true)},
	}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, enrollment, now)
	access := deploymentAssignmentAccess(t, d, replica, replica.assignments.Services[0], now)
	service, err := d.GetService(ctx, applied.Services[0].ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	run := readyAppliedServiceRun(t, d, access, replica.private, service, relays, now)
	registration := IngressRegistration{
		IngressID: "https-capability", IngressRunID: mustOpaqueID(t, opaqueid.IngressRunPrefix),
		ProtocolVersion: 1, ConnectionCapacity: 64, IngressPoolID: PrimaryIngressPoolID,
		ServicePorts: []int32{25443},
	}
	withoutHTTPS, err := d.RegisterIngress(ctx, registration, now, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	admit := func(lease IngressLease) error {
		_, err := d.AdmitPublicServiceVisitor(ctx, lease.IngressLeaseIdentity, PrimaryIngressPoolID,
			mustOpaqueID(t, opaqueid.VisitorConnectionPrefix), service.Endpoint.Hostname, 443, netip.MustParseAddr("192.0.2.10"), now)
		return err
	}
	if err := admit(withoutHTTPS); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("allocated-port inventory was mistaken for shared HTTPS support", err)
	}
	registration.HTTPS = true
	if _, err := d.RegisterIngress(ctx, registration, now, time.Minute); !errors.Is(err, ErrIngressAlreadyRunning) {
		t.Fatal("a live process changed its advertised capability", err)
	}
	claim := func(want bool) ServiceEndpointDNSWork {
		t.Helper()
		work, found, err := d.ClaimServiceEndpointDNSWork(ctx, "https-dns", now, time.Minute)
		if err != nil || found != want || found && (!work.Public || work.ServiceID != service.ID) {
			t.Fatal("DNS ignored shared HTTPS capability", work, found, err)
		}
		return work
	}
	claim(false)
	// the restarted process has shared HTTPS but no allocated-port listeners.
	now = now.Add(2 * time.Second)
	if _, err := d.HeartbeatServiceRun(ctx, service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	registration.IngressRunID = mustOpaqueID(t, opaqueid.IngressRunPrefix)
	registration.ServicePorts = nil
	withHTTPS, err := d.RegisterIngress(ctx, registration, now, time.Minute)
	if err != nil || withHTTPS.IngressLeaseRevision <= withoutHTTPS.IngressLeaseRevision {
		t.Fatal("restart did not fence the previous process", err)
	}
	if err := admit(withoutHTTPS); !errors.Is(err, ErrServiceAccess) && !errors.Is(err, ErrIngressLeaseStale) {
		t.Fatal("restarted ingress retained its old lease authority", err)
	}
	if err := admit(withHTTPS); err != nil {
		t.Fatal("shared HTTPS required an allocated port listener", err)
	}
	work := claim(true)
	if err := d.ValidateServiceEndpointDNSWork(ctx, work, now); err != nil {
		t.Fatal("ready shared HTTPS DNS was rejected", err)
	}
	// exposure revocation fences a worker that already captured the public name.
	r.ExpectedRevision = applied.Revision
	binding := r.Configuration.Services["web"]
	binding.Public = new(false)
	r.Configuration.Services["web"] = binding
	r.Now = now
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, work, now); !errors.Is(err, ErrDNSPublicURLWorkStale) {
		t.Fatal("revoked exposure left a public DNS worker authorized", err)
	}
	if err := admit(withHTTPS); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("stale public DNS authorized a connector-only service", err)
	}
}
