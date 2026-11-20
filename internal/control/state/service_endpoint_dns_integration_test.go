package state

import (
	"errors"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func readyEndpointDNSServiceRun(t *testing.T, d *Database, service ServiceRecord, leases map[string]RelayLease, publisher PublisherIdentity, key string, now time.Time) (ServiceRunPreparation, ServiceRunState) {
	t.Helper()
	prepared, err := d.PrepareServiceRun(t.Context(), service.ID, publisher, key, now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal("prepare endpoint DNS run:", err)
	}
	run, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal("start endpoint DNS run:", err)
	}
	installPrivateTestCertificate(t, d, prepared, run, now)
	for _, slot := range run.Connections {
		lease := leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, service.ID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, netip.MustParseAddr("127.0.0.1"), lease, now); err != nil {
			t.Fatal("claim endpoint DNS run connection:", err)
		}
		if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
			t.Fatal("ready endpoint DNS run connection:", err)
		}
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), service.ID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("endpoint DNS run was not ready", state, err)
	}
	return prepared, run
}

func TestIntegrationServiceEndpointDNSRevisions(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "service_endpoint_dns")
	ctx := t.Context()
	leases := map[string]RelayLease{}
	for slot := range 2 {
		registration := relayLifecycleRegistration(fmt.Sprintf("endpoint-dns-%d", slot))
		registration.ConnectionCapacity = 10
		lease, err := d.RegisterRelay(ctx, registration, now, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		leases[lease.RelayServiceID] = lease
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}

	r := appliedProjectRequest(t, d, now)
	r.DNSAutomation = true
	r.Configuration = ProjectConfiguration{Settings: &DeploymentSettings{}, Services: map[string]ProjectServiceConfiguration{"api": {Protocol: "tcp", Target: "localhost:3000"}}}
	r = selectedProjectRequest(r, "production")
	applied, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	claim := func(public bool, state ServiceEndpointDNSState) ServiceEndpointDNSWork {
		t.Helper()
		work, found, err := d.ClaimServiceEndpointDNSWork(ctx, "endpoint-worker", r.Now, time.Minute)
		if err != nil || !found || work.Hostname != applied.Services[0].Hostname || work.ServiceID != applied.Services[0].ServiceID || work.Public != public || work.State != state {
			t.Fatal("incorrect endpoint DNS work", work, found, err)
		}
		if err = d.ValidateServiceEndpointDNSWork(ctx, work, r.Now); err != nil {
			t.Fatal(err)
		}
		return work
	}
	// private automated endpoint: unmanaged, no DNS publication work before ready.
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "endpoint-worker", r.Now, time.Minute); err != nil || found {
		t.Fatal("private automated endpoint queued DNS publication work", found, err)
	}

	r.ExpectedRevision = applied.Revision
	r.Now = now.Add(time.Second)
	binding := r.Configuration.Services["api"]
	binding.Public = new(true)
	r.Configuration.Services["api"] = binding
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "duplicate", r.Now, time.Minute); err != nil || found {
		t.Fatal("public DNS became claimable without a ready publisher and exposed port", found, err)
	}

	service, err := d.GetService(ctx, applied.Services[0].ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.RegisterIngress(ctx, IngressRegistration{
		IngressID: "endpoint-dns-ingress", IngressRunID: "endpoint-dns-ingress-run", ProtocolVersion: 1,
		ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID, ServicePortRanges: []tcpport.Range{{First: service.Endpoint.Port, Last: service.Endpoint.Port}},
	}, r.Now, time.Hour); err != nil {
		t.Fatal(err)
	}
	deploymentEnrollment, err := testDeploymentPublisherEnrollment(d, ctx, r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, r.Now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, deploymentEnrollment, r.Now)
	assignment := replica.assignments.Services[0]
	access := deploymentAssignmentAccess(t, d, replica, assignment, r.Now)
	_, run := readyEndpointDNSServiceRun(t, d, service, leases, access.PublisherIdentity, "public", r.Now)

	// real canonical publication: public endpoint DNS is claimable and completable with a ready run+certificate.
	published := claim(true, ServiceEndpointDNSPending)
	published.State, published.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err = d.SaveServiceEndpointDNSWork(ctx, published, r.Now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "duplicate", r.Now, time.Minute); err != nil || found {
		t.Fatal("completed public DNS work remained queued", found, err)
	}

	// stale worker from the published revision cannot reclaim authority across exposure change.
	stale := published
	r.ExpectedRevision = applied.Revision
	r.Now = r.Now.Add(time.Second)
	binding.Public = new(false)
	r.Configuration.Services["api"] = binding
	applied, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.ValidateServiceEndpointDNSWork(ctx, stale, r.Now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("stale worker retained provider authority", err)
	}
	stale.State, stale.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err = d.SaveServiceEndpointDNSWork(ctx, stale, r.Now); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("old publication completed the retired public revision", err)
	}

	// public exposure removed: endpoint DNS removal is claimable and completed.
	removed := claim(false, ServiceEndpointDNSRemoving)
	removed.State, removed.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(ctx, removed, r.Now); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(ctx, "duplicate", r.Now, time.Minute); err != nil || found {
		t.Fatal("completed DNS removal remained queued", found, err)
	}

	// close the run and advance beyond true captured expiry/cert tails before reuse assertions.
	if err := d.CloseServiceRun(ctx, service.ID, run.RunID, run.Token, r.Now); err != nil {
		t.Fatal(err)
	}
	tail := r.Now.Add(8 * 24 * time.Hour)

	r.ExpectedRevision = applied.Revision
	r.Now = r.Now.Add(time.Second)
	delete(r.Configuration.Services, "api")
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	var endpointState string
	var retiredAt, reusableAfter time.Time
	if err = d.pool.QueryRow(ctx, `SELECT dns_state, retired_at, reusable_after FROM control.service_endpoints WHERE hostname=$1`, applied.Services[0].Hostname).Scan(&endpointState, &retiredAt, &reusableAfter); err != nil || endpointState != string(ServiceEndpointDNSRemoved) || retiredAt.IsZero() || !reusableAfter.After(r.Now) {
		t.Fatal("DNS removal released certificate authority early", endpointState, retiredAt, reusableAfter, err)
	}
	if count, err := d.ReleaseServicePorts(ctx, tail); err != nil || count != 1 {
		t.Fatal("completed retirement permanently held the service port", count, err)
	}
}
