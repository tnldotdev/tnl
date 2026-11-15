package state

import (
	"testing"
	"time"
)

func startAllocatedServiceRun(t *testing.T, f deploymentPublicationFixture, access PublisherAccess) deploymentServiceRunFixture {
	t.Helper()
	service, err := f.d.AllocateDeploymentPublication(t.Context(), f.allocation(t, access))
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := f.d.PrepareServiceRun(t.Context(), service.ID, access.PublisherIdentity, "retirement", f.now, ServiceRunRequest{Metadata: service.ServiceMetadata})
	if err != nil {
		t.Fatal(err)
	}
	run, err := f.d.StartServiceRun(t.Context(), service.ID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, f.now)
	if err != nil {
		t.Fatal(err)
	}
	return deploymentServiceRunFixture{service, prepared, run}
}

func completeAllocationRetirementDNS(t *testing.T, d *Database, now time.Time) {
	t.Helper()
	for {
		dns, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "allocation-retirement", now, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !found {
			return
		}
		if dns.State != ServiceEndpointDNSRemoving {
			t.Fatal("deleted allocation retained publication DNS work", dns.State)
		}
		dns.State, dns.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
		if _, err := d.SaveServiceEndpointDNSWork(t.Context(), dns, now); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIntegrationDeploymentAllocationNamespaceRetirement(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	_, _, _, _ = publishRunPrerequisitesInDatabase(t, f.d, f.now, nil)
	r, _, access, _ := f.approve(t, nil, "restricted")
	var namespace string
	if err := f.d.pool.QueryRow(t.Context(), `SELECT namespace FROM control.deployments WHERE id=$1`, f.production.ID).Scan(&namespace); err != nil {
		t.Fatal(err)
	}
	certified, pending := startAllocatedServiceRun(t, f, access), startAllocatedServiceRun(t, f, access)
	installPrivateTestCertificate(t, f.d, certified.prepared, certified.run, f.now, 10*24*time.Hour)
	work := createPlanIssuanceWork(t, f.d, f.now, PublishRunAuthentication{}, pending.prepared.CertificatePlan, false, nil, planIssuanceOptions{privateRun: &pending.run, lifetime: 24 * time.Hour})
	if certified.prepared.CertificatePlan.Scope == namespace {
		t.Fatal("fixture did not exercise exact-host certificate retirement")
	}
	if err := f.d.DeleteDeployment(t.Context(), r.DeploymentScope, f.production.ID, f.production.Revision, f.now); err != nil {
		t.Fatal(err)
	}
	reusable := func(at time.Time, want bool) {
		t.Helper()
		var got bool
		if err := f.d.pool.QueryRow(t.Context(), `SELECT control.service_namespace_reusable($1,$2)`, namespace, at).Scan(&got); err != nil || got != want {
			t.Fatal("allocation namespace retirement lost service/certificate/issuance/DNS authority", at, got, want, err)
		}
	}
	reusable(f.now.Add(11*24*time.Hour), false)
	// retirement workers report deletion of the actual allocation endpoints.
	completeAllocationRetirementDNS(t, f.d, f.now)
	reusable(f.now.Add(11*24*time.Hour), false)
	// model an uncertain order's terminal result separately from its late DNS
	// cleanup receipt. no certificate lifetime is changed by this fixture.
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.acme_orders SET state='canceled',work_owner=NULL,work_expires_at=NULL WHERE id=$1`, work.ID); err != nil {
		t.Fatal(err)
	}
	reusable(f.now.Add(11*24*time.Hour), false)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.acme_authorizations SET state='complete',cleanup_completed_at=$2,work_owner=NULL,work_expires_at=NULL WHERE order_id=$1`, work.ID, f.now); err != nil {
		t.Fatal(err)
	}
	reusable(f.now.Add(8*24*time.Hour), false)
	reusable(f.now.Add(11*24*time.Hour), true)
}

func TestIntegrationDeploymentAllocationCertificateSurvivesEndpointReassignment(t *testing.T) {
	f := newDeploymentPublicationFixture(t)
	_, _, _, _ = publishRunPrerequisitesInDatabase(t, f.d, f.now, nil)
	_, _, access, _ := f.approve(t, nil, "restricted")
	certified := startAllocatedServiceRun(t, f, access)
	installPrivateTestCertificate(t, f.d, certified.prepared, certified.run, f.now, 10*24*time.Hour)
	var namespace string
	if err := f.d.pool.QueryRow(t.Context(), `SELECT namespace FROM control.service_endpoints WHERE service_id=$1`, certified.service.ID).Scan(&namespace); err != nil {
		t.Fatal(err)
	}
	var capturedNamespace string
	if err := f.d.pool.QueryRow(t.Context(), `SELECT certificate_namespace FROM control.service_runs WHERE id=$1`, certified.run.RunID).Scan(&capturedNamespace); err != nil || capturedNamespace != namespace {
		t.Fatal("run did not capture the actual allocation endpoint namespace", err)
	}
	if err := f.d.DeletePublisherService(t.Context(), access.PublisherIdentity, certified.service.ID, f.now); err != nil {
		t.Fatal(err)
	}
	current, err := f.d.GetProjectConfiguration(t.Context(), f.project.TeamID, f.project.ProjectKey, f.project.ActorID, "production")
	if err != nil {
		t.Fatal(err)
	}
	r := f.project
	r.ExpectedRevision, r.Configuration, r.DNSAutomation = current.Revision, current.Configuration, true
	web := r.Configuration.Services["web"]
	web.Hostname = certified.service.Endpoint.Hostname
	r.Configuration.Services["web"] = web
	if _, err := f.d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal("same-deployment exact hostname could not replace its deleted service", err)
	}
	var endpointNamespace, endpointService string
	if err := f.d.pool.QueryRow(t.Context(), `SELECT namespace,service_id FROM control.service_endpoints WHERE hostname=$1`, web.Hostname).Scan(&endpointNamespace, &endpointService); err != nil || endpointNamespace == namespace || endpointService == certified.service.ID {
		t.Fatal("fixture did not reassign the endpoint's mutable provenance", err)
	}
	production, err := f.d.GetDeployment(t.Context(), DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, "production")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.DeleteDeployment(t.Context(), DeploymentScope{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID}, production.ID, production.Revision, f.now); err != nil {
		t.Fatal(err)
	}
	completeAllocationRetirementDNS(t, f.d, f.now)
	var reusable bool
	if err := f.d.pool.QueryRow(t.Context(), `SELECT control.service_namespace_reusable($1,$2)`, namespace, f.now.Add(8*24*time.Hour)).Scan(&reusable); err != nil || reusable {
		t.Fatal("endpoint reassignment lost the allocation's outstanding exact-host certificate authority", err)
	}
}
