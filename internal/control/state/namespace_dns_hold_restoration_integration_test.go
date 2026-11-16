package state

import (
	"net/netip"
	"testing"
	"time"
)

func TestIntegrationNamespaceDNSRemovalHoldsRetiredScope(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	registerTestIngress(t, d, now)
	request := appliedProjectRequest(t, d, now)
	request.DNSAutomation = true
	request.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"api": {Target: "http://api.internal:3000", Public: new(true)},
	}}
	request = projectServiceSelection(request, "production", "api")
	applied, err := d.ApplyProjectConfiguration(ctx, request)
	if err != nil || len(applied.Services) != 1 {
		t.Fatal("apply one public service for namespace retirement", applied, err)
	}
	enrollment, err := testDeploymentPublisherEnrollment(d, ctx, request.TeamID, request.ProjectKey, "production", request.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	publisher := enrollAppliedDeployment(t, d, request, enrollment, now)
	if len(publisher.assignments.Services) != 1 {
		t.Fatal("namespace fixture did not select exactly one service")
	}
	assignment := publisher.assignments.Services[0]
	access := deploymentAssignmentAccess(t, d, publisher, assignment, now)
	service, err := d.GetService(ctx, assignment.ServiceID, request.ActorID)
	if err != nil || service.Endpoint == nil || !service.Endpoint.Public {
		t.Fatal("namespace fixture has no public service endpoint", err)
	}
	run := readyAppliedServiceRun(t, d, access, publisher.private, service, netip.MustParseAddr("127.0.0.1"), leases, now)
	var namespace string
	var identifiers []string
	var certificateExpiresAt, publisherExpiresAt time.Time
	if err := d.pool.QueryRow(ctx, `SELECT certificate_namespace,certificate_identifiers,
		certificate_expires_at,publisher_expires_at FROM control.service_runs
		WHERE id=$1 AND state='ready' AND certificate_issuance_id IS NOT NULL`,
		run.RunID).Scan(&namespace, &identifiers, &certificateExpiresAt, &publisherExpiresAt); err != nil {
		t.Fatal("capture the ready run's actual certificate and forwarding tails", err)
	}
	if namespace == "" || len(identifiers) != 1 || identifiers[0] == namespace || !certificateExpiresAt.After(now) {
		t.Fatal("namespace fixture lost its captured non-apex certificate plan", namespace, identifiers, certificateExpiresAt)
	}
	published, found, err := d.ClaimServiceEndpointDNSWork(ctx, "namespace-hold-publish", now, time.Minute)
	if err != nil || !found || published.ServiceID != service.ID || published.Hostname != service.Endpoint.Hostname ||
		!published.Public || published.State != ServiceEndpointDNSPending {
		t.Fatal("claim the ready service's public DNS work", published, found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, published, now); err != nil {
		t.Fatal(err)
	}
	published.State, published.AvailableAt = ServiceEndpointDNSPublished, time.Time{}
	published, err = d.SaveServiceEndpointDNSWork(ctx, published, now)
	if err != nil {
		t.Fatal("publish the old endpoint before renaming", err)
	}
	renamedAt := now.Add(time.Second)
	renamed, err := d.RenameDeploymentNamespace(ctx, RenameDeploymentNamespaceRequest{
		TeamID: request.TeamID, ProjectKey: request.ProjectKey, Deployment: publisher.member.DeploymentID,
		NamespaceLabel: "dns-hold-renamed", ActorID: request.ActorID, ExpectedRevision: applied.Revision,
		IdempotencyKey: "dns-hold-rename", DNSAutomation: true, Now: renamedAt,
	})
	if err != nil || len(renamed.Services) != 1 || renamed.Services[0].ServiceID != service.ID ||
		renamed.Services[0].Hostname == service.Endpoint.Hostname {
		t.Fatal("rename the namespace without replacing the saved service", renamed, err)
	}

	// all other vetoes must be cleared; an unfinished order must not mask dns.
	var orders, unfinishedOrders, authorizations, unfinishedAuthorizations int
	var issuanceExpiresAt time.Time
	if err := d.pool.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER(WHERE state<>'installed' OR not_after IS NULL),max(not_after)
		FROM control.acme_orders`).Scan(&orders, &unfinishedOrders, &issuanceExpiresAt); err != nil ||
		orders != 1 || unfinishedOrders != 0 || !issuanceExpiresAt.Equal(certificateExpiresAt) {
		t.Fatal("namespace fixture has another certificate or pending issuance", orders, unfinishedOrders, err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT count(*),
		count(*) FILTER(WHERE state<>'complete' OR presented_at IS NULL OR cleanup_completed_at IS NULL)
		FROM control.acme_authorizations`).Scan(&authorizations, &unfinishedAuthorizations); err != nil ||
		authorizations != len(identifiers) || unfinishedAuthorizations != 0 {
		t.Fatal("namespace fixture has unfinished challenge cleanup", authorizations, unfinishedAuthorizations, err)
	}
	var namespaceTail, endpointTail time.Time
	if err := d.pool.QueryRow(ctx, `SELECT claim.reusable_after,endpoint.reusable_after
		FROM control.service_namespace_claims claim
		JOIN control.service_endpoints endpoint ON endpoint.namespace=claim.namespace
		WHERE claim.namespace=$1 AND claim.retired_at IS NOT NULL
		AND endpoint.hostname=$2 AND endpoint.service_id=$3
		AND endpoint.retired_at IS NOT NULL AND endpoint.dns_state='removing'`,
		namespace, service.Endpoint.Hostname, service.ID).Scan(&namespaceTail, &endpointTail); err != nil {
		t.Fatal("old namespace and published endpoint were not retired for DNS removal", err)
	}
	var closed bool
	if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL
		AND NOT EXISTS(SELECT 1 FROM control.service_connection_slots WHERE service_run_id=$1 AND session_open)
		FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&closed); err != nil || !closed {
		t.Fatal("namespace rename retained old forwarding authority", err)
	}
	clearedAt := now.Add(8 * 24 * time.Hour)
	for _, tail := range []time.Time{namespaceTail, endpointTail, certificateExpiresAt, issuanceExpiresAt, publisherExpiresAt} {
		if tail.After(clearedAt) {
			clearedAt = tail
		}
	}
	clearedAt = clearedAt.Add(time.Second)
	checkReusable := func(want bool) {
		t.Helper()
		var reusable bool
		if err := d.pool.QueryRow(ctx, `SELECT control.service_namespace_reusable($1,$2)`, namespace, clearedAt).Scan(&reusable); err != nil {
			t.Fatal(err)
		}
		if reusable != want {
			t.Errorf("namespace reuse after every non-DNS tail: got %t, want %t", reusable, want)
		}
	}
	checkReusable(false)

	// claim at the observation time, not with a lease from eight days earlier.
	removal, found, err := d.ClaimServiceEndpointDNSWork(ctx, "namespace-hold-remove", clearedAt, time.Minute)
	if err != nil || !found || removal.Hostname != published.Hostname || removal.ServiceID != service.ID ||
		removal.State != ServiceEndpointDNSRemoving || removal.Revision <= published.Revision ||
		removal.Epoch <= published.Epoch || !removal.ExpiresAt.After(clearedAt) {
		t.Fatal("claim current fenced removal work for the exact old endpoint", removal, found, err)
	}
	if err := d.ValidateServiceEndpointDNSWork(ctx, removal, clearedAt); err != nil {
		t.Fatal(err)
	}
	checkReusable(false)
	removal.State, removal.AvailableAt = ServiceEndpointDNSRemoved, time.Time{}
	saved, err := d.SaveServiceEndpointDNSWork(ctx, removal, clearedAt)
	if err != nil || saved.State != ServiceEndpointDNSRemoved || saved.Revision != removal.Revision+1 {
		t.Fatal("complete the current removal claim", saved, err)
	}
	checkReusable(true)
}
