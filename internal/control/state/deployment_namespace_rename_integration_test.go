package state

import (
	"errors"
	"net/netip"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestIntegrationPublisherNamespaceRenameAtomicAuthority(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	if _, err := d.RegisterIngress(t.Context(), IngressRegistration{
		IngressID: "rename-ingress", IngressRunID: "rename-ingress-run", ProtocolVersion: 1,
		ConnectionCapacity: 100, IngressPoolID: PrimaryIngressPoolID, HTTPS: true,
	}, now, time.Hour); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	r.DNSAutomation = true
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"api": {Target: "http://api.internal:3000", Public: new(true), Access: &ProjectServiceAccess{Team: true}},
	}}
	staging := projectServiceSelection(r, "staging")
	first, err := d.ApplyProjectConfiguration(t.Context(), staging)
	if err != nil {
		t.Fatal(err)
	}
	r = projectServiceSelection(r, "production", "api")
	r.ExpectedRevision = first.Revision
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	e, err := testDeploymentPublisherEnrollment(d, t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedDeployment(t, d, r, e, now)
	assignment := replica.assignments.Services[0]
	access := deploymentAssignmentAccess(t, d, replica, assignment, now)
	prep, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "old-run", now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	service, err := d.GetService(t.Context(), assignment.ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	installPrivateTestCertificate(t, d, prep, run, now)
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
		t.Fatal("rename publisher run was not ready", state, err)
	}
	published, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "rename-dns", now, time.Minute)
	if err != nil || !found || published.Hostname != applied.Services[0].Hostname || !published.Public || published.State != ServiceEndpointDNSPending {
		t.Fatal("old endpoint DNS was not claimable with a ready publisher", published, found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(t.Context(), published, now); err != nil {
		t.Fatal(err)
	}
	published.State, published.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	if _, err = d.SaveServiceEndpointDNSWork(t.Context(), published, now); err != nil {
		t.Fatal(err)
	}
	grants, _, err := d.ListServiceGrants(t.Context(), assignment.ServiceID, r.ActorID, "")
	if err != nil {
		t.Fatal(err)
	}

	request := RenameDeploymentNamespaceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Deployment: "production", NamespaceLabel: "staging", ExpectedRevision: applied.Revision, IdempotencyKey: "rename-one", DNSAutomation: true, Now: now.Add(time.Second)}
	if _, err := d.RenameDeploymentNamespace(t.Context(), request); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("namespace collision accepted", err)
	}
	current, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID, "production")
	if err != nil || !reflect.DeepEqual(current, applied) {
		// enrollment changes member status, not desired state.
		if err != nil || current.Revision != applied.Revision || !reflect.DeepEqual(current.Services, applied.Services) || !reflect.DeepEqual(current.Deployments, applied.Deployments) {
			t.Fatal("collision partially mutated state", err)
		}
	}
	request.NamespaceLabel = "live"
	request.Deployment = replica.member.DeploymentID
	renamed, err := d.RenameDeploymentNamespace(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Revision != applied.Revision+1 || renamed.Services[0].ServiceID != assignment.ServiceID || renamed.Services[0].Port != applied.Services[0].Port || renamed.Services[0].Hostname == applied.Services[0].Hostname || renamed.ConfigurationHash != applied.ConfigurationHash || !reflect.DeepEqual(renamed.Configuration, applied.Configuration) {
		t.Fatal("namespace rename changed service identity or configuration", renamed)
	}
	after, _, err := d.ListServiceGrants(t.Context(), assignment.ServiceID, r.ActorID, "")
	if err != nil || !reflect.DeepEqual(grants, after) {
		t.Fatal("visitor grants changed", err)
	}
	if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, request.Now, ServiceRunHealth{Healthy: true, StreamCapacity: 64, ActiveStreams: 0}); err == nil {
		t.Fatal("old run token survived namespace rename")
	}
	if _, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "stale-authority", request.Now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}}); err == nil {
		t.Fatal("old publication authority survived rename")
	}
	next, err := d.GetDeploymentPublisherAssignments(t.Context(), replica.lease.AccessToken, request.Now)
	if err != nil || next.Member != replica.member || next.Services[0].GrantID == assignment.GrantID {
		t.Fatal("deployment lease or replacement assignment lost", err)
	}
	replica.assignments = next
	newAccess := deploymentAssignmentAccess(t, d, replica, next.Services[0], request.Now)
	newPrep, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, newAccess.PublisherIdentity, "new-run", request.Now, ServiceRunRequest{Metadata: ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}})
	if err != nil || newPrep.CertificatePlan.Scope == prep.CertificatePlan.Scope || reflect.DeepEqual(newPrep.CertificatePlan.Identifiers, prep.CertificatePlan.Identifiers) {
		t.Fatal("old certificate scope reused", err)
	}

	// old published endpoint is retired for DNS removal; quarantine is held by DNS removal boundary.
	oldRemoval, found, err := d.ClaimServiceEndpointDNSWork(t.Context(), "rename-old-removal", request.Now, time.Minute)
	if err != nil || !found || oldRemoval.Hostname != applied.Services[0].Hostname || oldRemoval.ServiceID != assignment.ServiceID || oldRemoval.State != ServiceEndpointDNSRemoving {
		t.Fatal("old published endpoint DNS was not queued for removal", oldRemoval, found, err)
	}
	var newReady bool
	if err := d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=$1 AND retired_at IS NULL AND dns_state='pending' AND public)`, renamed.Services[0].Hostname).Scan(&newReady); err != nil || !newReady {
		t.Fatal("renamed endpoint did not become a pending public endpoint", err)
	}
	oldRemoval.State, oldRemoval.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	if _, err = d.SaveServiceEndpointDNSWork(t.Context(), oldRemoval, request.Now); err != nil {
		t.Fatal(err)
	}
	var oldRetired, newPending bool
	if err := d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=$1 AND retired_at IS NOT NULL AND dns_state='removed'),EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=$2 AND retired_at IS NULL AND dns_state='pending' AND public)`, applied.Services[0].Hostname, renamed.Services[0].Hostname).Scan(&oldRetired, &newPending); err != nil || !oldRetired || !newPending {
		t.Fatal("DNS transition not atomic", err)
	}
	var reusable bool
	if err := d.pool.QueryRow(t.Context(), `SELECT control.service_namespace_reusable($1,$2)`, prep.CertificatePlan.Scope, now.Add(time.Hour)).Scan(&reusable); err != nil || reusable {
		t.Fatal("DNS cleanup bypassed quarantine", err)
	}
	// close the old run via actual CloseServiceRun, then advance beyond true captured expiry/cert tails.
	if err := d.CloseServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, request.Now); err != nil && !errors.Is(err, ErrServiceAccess) {
		t.Fatal("old run close failed", err)
	}
	var certExpiresAt time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT COALESCE(certificate_expires_at, to_timestamp(0)) FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&certExpiresAt); err != nil {
		t.Fatal(err)
	}
	certTail := certExpiresAt
	if certTail.IsZero() || certTail.Before(now.Add(8*24*time.Hour)) {
		certTail = now.Add(8 * 24 * time.Hour)
	}
	tail := certTail.Add(time.Second)
	if err := d.pool.QueryRow(t.Context(), `SELECT control.service_namespace_reusable($1,$2)`, prep.CertificatePlan.Scope, tail).Scan(&reusable); err != nil || !reusable {
		t.Fatal("retired scope could not be reused after all boundaries cleared", err)
	}

	// concurrent exact retries all return the same historical response.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			retry, err := d.RenameDeploymentNamespace(t.Context(), request)
			if err != nil || !sameStoredResponse(t, retry, renamed) {
				t.Errorf("lost-reply retry changed result: %v", err)
			}
		})
	}
	wg.Wait()
	changed := request
	changed.NamespaceLabel = "other"
	if _, err := d.RenameDeploymentNamespace(t.Context(), changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("request key changed meaning", err)
	}
	changed.IdempotencyKey = "race-loser"
	if _, err := d.RenameDeploymentNamespace(t.Context(), changed); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("stale revision accepted", err)
	}
	changed.ExpectedRevision = renamed.Revision
	if _, err := d.RenameDeploymentNamespace(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	retry, err := d.RenameDeploymentNamespace(t.Context(), request)
	if err != nil || !sameStoredResponse(t, retry, renamed) {
		t.Fatal("retry returned later state instead of original response", err)
	}
	// two different mutations race from the same revision. only one may commit.
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, label := range []string{"race-one", "race-two"} {
		candidate := changed
		candidate.ExpectedRevision++
		candidate.NamespaceLabel, candidate.IdempotencyKey = label, label
		go func() { <-start; _, err := d.RenameDeploymentNamespace(t.Context(), candidate); results <- err }()
	}
	close(start)
	winners, stale := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if errors.Is(err, ErrProjectConfigurationStale) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || stale != 1 {
		t.Fatal("revision race did not have exactly one winner", winners, stale)
	}
}
