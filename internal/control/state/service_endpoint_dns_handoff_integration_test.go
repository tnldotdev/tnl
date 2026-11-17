package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
)

// the external test composes state fixtures with the real DNS provider without
// making state depend on the provider that consumes it.
func ExerciseServiceEndpointDNSHandoff(t *testing.T, cleanupFirst bool, provider func(bool, string, ServiceEndpointDNSWork) error) {
	t.Helper()
	d, now, authority, leases := newPublishRunPrerequisites(t)
	project := appliedProjectRequest(t, d, now)
	authority.TeamID, authority.ActingIdentityID = project.TeamID, project.ActorID
	var domainID, domain string
	if err := d.pool.QueryRow(t.Context(), `SELECT id,canonical_domain FROM control.domains WHERE kind='managed'`).Scan(&domainID, &domain); err != nil {
		t.Fatal(err)
	}
	placement := ServicePlacement{DomainID: domainID, DNSAutomation: true}
	declaration := &ProjectServiceConfiguration{Protocol: "http", Target: "http://localhost:3000", Public: new(true)}
	first, err := d.CreateServiceAt(t.Context(), authority.TeamID, authority.ActingIdentityID, "dns-handoff", "first",
		placement, now, ServiceMetadata{Protocol: "http"}, declaration)
	if err != nil {
		t.Fatal("create predecessor", err)
	}
	start := func(service ServiceRecord, at time.Time) servicePublicationFixture {
		t.Helper()
		publisher, prepared := adminPreparedRun(t, d, service, authority.ActingIdentityID, at)
		run, err := d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, publisher, at)
		if err != nil {
			t.Fatal(err)
		}
		f := servicePublicationFixture{database: d, now: at, service: service, publisher: publisher, prepared: prepared, run: run, leases: leases}
		prepareServingPublisher(t, f)
		return f
	}
	at := now.Add(time.Second)
	firstRun := start(first, at)
	registerServingIngress(t, firstRun, "dns-handoff-ingress", at)
	publish, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "predecessor", at, time.Minute)
	if err != nil || !found || publish.ServiceID != first.ID || publish.OwnerID != first.ID {
		t.Fatal("claim predecessor publication", publish, found, err)
	}
	if err := provider(false, domain, publish); err != nil {
		t.Fatal("provider predecessor publication", err)
	}
	publish.State, publish.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(t.Context(), publish, at); err != nil {
		t.Fatal(err)
	}
	if err := d.DeleteService(t.Context(), first.ID, authority.ActingIdentityID, observedServiceDeletion(t, d, first.ID), at); err != nil {
		t.Fatal("delete predecessor", err)
	}
	at = at.Add(time.Second)
	removal, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "predecessor-removal", at, time.Minute)
	if err != nil || !found || removal.ServiceID != first.ID || removal.OwnerID != first.ID || removal.State != ServiceEndpointDNSRemoving {
		t.Fatal("claim predecessor removal", removal, found, err)
	}
	createReplacement := func() (ServiceRecord, error) {
		return d.CreateServiceAt(t.Context(), authority.TeamID, authority.ActingIdentityID, "dns-handoff", "replacement",
			placement, at, ServiceMetadata{Protocol: "http"}, declaration)
	}
	if !cleanupFirst {
		if _, err := createReplacement(); !errors.Is(err, ErrServiceConflict) {
			t.Fatal("replacement discarded the predecessor's pending DNS cleanup owner", err)
		}
		if err := d.ValidateServiceEndpointDNSWork(t.Context(), removal, at); err != nil {
			t.Fatal("rejected replacement fenced predecessor cleanup", err)
		}
		var count int
		if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.services WHERE team_id=$1 AND deleted_at IS NULL`,
			authority.TeamID).Scan(&count); err != nil || count != 0 {
			t.Fatal("rejected replacement leaked a saved service", count, err)
		}
	}
	if err := d.ValidateServiceEndpointDNSWork(t.Context(), removal, at); err != nil {
		t.Fatal(err)
	}
	if err := provider(true, domain, removal); err != nil {
		t.Fatal("provider predecessor removal", err)
	}
	removal.State, removal.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(t.Context(), removal, at); err != nil {
		t.Fatal(err)
	}
	// the same source can replace its deleted service immediately after cleanup;
	// the seven-day quarantine is for a different namespace owner.
	second, err := createReplacement()
	if err != nil || second.ID == first.ID || second.Endpoint.Hostname != first.Endpoint.Hostname {
		t.Fatal("same-source handoff remained blocked after DNS cleanup", second, err)
	}
	at = at.Add(time.Second)
	start(second, at)
	next, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "replacement", at, time.Minute)
	if err != nil || !found || next.ServiceID != second.ID || next.OwnerID != second.ID || next.State != ServiceEndpointDNSPending {
		t.Fatal("claim replacement publication", next, found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(t.Context(), removal, at); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("completed predecessor removal retained provider authority", err)
	}
	if _, err := d.SaveServiceEndpointDNSWork(t.Context(), removal, at); !errors.Is(err, ErrServiceEndpointDNSWorkStale) {
		t.Fatal("predecessor cleanup could overwrite replacement state", err)
	}
	if err := provider(false, domain, next); err != nil {
		t.Fatal("provider replacement publication", err)
	}
	next.State, next.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := d.SaveServiceEndpointDNSWork(t.Context(), next, at); err != nil {
		t.Fatal(err)
	}
	if _, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "after-handoff", at, time.Minute); err != nil || found {
		t.Fatal("successful handoff left orphaned DNS work", found, err)
	}
}

func TestIntegrationServiceEndpointDNSDeploymentHandoffWaitsForCleanup(t *testing.T) {
	e := newRestoredCertificateEnvironment(t, DomainKindManaged, naming.ManagedURLModeGenerated, false)
	applied, replica := e.deployment(t, "dns-deployment", true, map[string]ProjectServiceConfiguration{
		"api": {Protocol: "http", Target: "localhost:3000", Public: new(true)},
	})
	first := e.startAssigned(t, replica, "api")
	first.leases = make(map[string]RelayLease)
	for _, slot := range first.run.Connections {
		var lease RelayLease
		if err := e.database.pool.QueryRow(t.Context(), `SELECT relay_service_id,relay_id,relay_run_id,relay_lease_revision
			FROM control.relay_leases WHERE relay_service_id=$1`, slot.RelayServiceID).
			Scan(&lease.RelayServiceID, &lease.RelayID, &lease.RelayRunID, &lease.RelayLeaseRevision); err != nil {
			t.Fatal(err)
		}
		first.leases[slot.RelayServiceID] = lease
	}
	prepareServingPublisher(t, first)
	work, found, err := e.database.ClaimServiceEndpointDNSWork(t.Context(), "deployment-publish", e.now, time.Minute)
	if err != nil || !found || work.ServiceID != first.service.ID || work.OwnerID != applied.Deployments[0].ID {
		t.Fatal("deployment DNS did not capture its stable provider owner", work, found, err)
	}
	work.State, work.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err := e.database.SaveServiceEndpointDNSWork(t.Context(), work, e.now); err != nil {
		t.Fatal(err)
	}
	request := appliedCertificateRequest(e, "dns-deployment", applied, e.now.Add(time.Second))
	declaration := request.Configuration.Services["api"]
	delete(request.Configuration.Services, "api")
	removed, err := e.database.ApplyProjectConfiguration(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	removal, found, err := e.database.ClaimServiceEndpointDNSWork(t.Context(), "deployment-removal", request.Now, time.Minute)
	if err != nil || !found || removal.ServiceID != first.service.ID || removal.OwnerID != work.OwnerID || removal.State != ServiceEndpointDNSRemoving {
		t.Fatal("deployment removal lost the predecessor receipt", removal, found, err)
	}
	request.ExpectedRevision = removed.Revision
	request.Configuration.Services["api"] = declaration
	if _, err := e.database.ApplyProjectConfiguration(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("same-deployment replacement discarded pending cleanup", err)
	}
	if err := e.database.ValidateServiceEndpointDNSWork(t.Context(), removal, request.Now); err != nil {
		t.Fatal("rejected same-deployment handoff fenced cleanup", err)
	}
	removal.State, removal.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	if _, err := e.database.SaveServiceEndpointDNSWork(t.Context(), removal, request.Now); err != nil {
		t.Fatal(err)
	}
	replacement, err := e.database.ApplyProjectConfiguration(t.Context(), request)
	if err != nil || len(replacement.Services) != 1 || replacement.Services[0].ServiceID == first.service.ID ||
		replacement.Services[0].Hostname != first.service.Endpoint.Hostname || replacement.Deployments[0].ID != work.OwnerID {
		t.Fatal("same-deployment handoff remained blocked after cleanup", replacement, err)
	}
	if _, err := e.database.GetServiceForPublisher(t.Context(), replacement.Services[0].ServiceID, first.publisher, request.Now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replacement adopted the predecessor's exact publisher grant", err)
	}
	var captured bool
	if err := e.database.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL AND
		certificate_hostname=$2 AND certificate_scope=$3 AND certificate_identifiers=$4::text[]
		FROM control.service_runs WHERE id=$1`, first.run.RunID, first.service.Endpoint.Hostname,
		first.prepared.CertificatePlan.Scope, first.prepared.CertificatePlan.Identifiers).Scan(&captured); err != nil || !captured {
		t.Fatal("handoff rewrote the predecessor's captured certificate authority", captured, err)
	}
}
