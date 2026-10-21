package controlstate

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestIntegrationPublisherNamespaceRenameAtomicAuthority(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := appliedProjectRequest(t, d, now)
	r.ProjectLabel = "storefront"
	r.DNSAutomation = true
	r.Configuration = ProjectConfiguration{Publishers: map[string]ProjectPublisherGroup{"production": {}, "staging": {}}, Services: map[string]ProjectServiceConfiguration{
		"api": {Publisher: "production", Target: "api.internal:3000", Access: &ProjectServiceAccess{Team: true}},
	}}
	applied, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	e, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, e, now)
	assignment := replica.assignments.Services[0]
	access := groupAssignmentAccess(t, d, replica, assignment, now)
	prep, err := d.PreparePrivateServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "old-run", now, PrivateServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartManagedServiceRun(t.Context(), assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	grants, err := d.ListPrivateServiceGrants(t.Context(), assignment.ServiceID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	request := RenamePublisherNamespaceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Group: "production", NamespaceLabel: "staging", ExpectedRevision: applied.Revision, IdempotencyKey: "rename-one", DNSAutomation: true, Now: now.Add(time.Second)}
	if _, err := d.RenamePublisherNamespace(t.Context(), request); !errors.Is(err, ErrPrivateServiceConflict) {
		t.Fatal("namespace collision accepted", err)
	}
	current, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || !reflect.DeepEqual(current, applied) {
		// enrollment changes member status, not desired state.
		if err != nil || current.Revision != applied.Revision || !reflect.DeepEqual(current.Services, applied.Services) || !reflect.DeepEqual(current.Groups, applied.Groups) {
			t.Fatal("collision partially mutated state", err)
		}
	}
	request.NamespaceLabel = "live"
	renamed, err := d.RenamePublisherNamespace(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if renamed.Revision != applied.Revision+1 || renamed.Services[0].ServiceID != assignment.ServiceID || renamed.Services[0].Port != applied.Services[0].Port || renamed.Services[0].Hostname == applied.Services[0].Hostname || renamed.ConfigurationHash != applied.ConfigurationHash || !reflect.DeepEqual(renamed.Configuration, applied.Configuration) {
		t.Fatal("namespace rename changed service identity or configuration", renamed)
	}
	after, err := d.ListPrivateServiceGrants(t.Context(), assignment.ServiceID, r.ActorID)
	if err != nil || !reflect.DeepEqual(grants, after) {
		t.Fatal("visitor grants changed", err)
	}
	if _, err := d.HeartbeatPrivateServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, request.Now); err == nil {
		t.Fatal("old run token survived namespace rename")
	}
	if _, err := d.PreparePrivateServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "stale-authority", request.Now, PrivateServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}); err == nil {
		t.Fatal("old publication authority survived rename")
	}
	next, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, request.Now)
	if err != nil || next.Member != replica.member || next.Services[0].GrantID == assignment.GrantID {
		t.Fatal("group lease or replacement assignment lost", err)
	}
	replica.assignments = next
	newAccess := groupAssignmentAccess(t, d, replica, next.Services[0], request.Now)
	newPrep, err := d.PreparePrivateServiceRun(t.Context(), assignment.ServiceID, newAccess.PublisherIdentity, "new-run", request.Now, PrivateServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision})
	if err != nil || newPrep.CertificatePlan.Scope == prep.CertificatePlan.Scope || reflect.DeepEqual(newPrep.CertificatePlan.Identifiers, prep.CertificatePlan.Identifiers) {
		t.Fatal("old certificate scope reused", err)
	}
	var oldRetired, newPending bool
	if err := d.pool.QueryRow(t.Context(), `SELECT EXISTS(SELECT 1 FROM control.managed_service_endpoints WHERE hostname=$1 AND retired_at IS NOT NULL AND dns_state='removing'),EXISTS(SELECT 1 FROM control.managed_service_endpoints WHERE hostname=$2 AND retired_at IS NULL AND dns_state='pending')`, applied.Services[0].Hostname, renamed.Services[0].Hostname).Scan(&oldRetired, &newPending); err != nil || !oldRetired || !newPending {
		t.Fatal("DNS transition not atomic", err)
	}
	var reusable bool
	if err := d.pool.QueryRow(t.Context(), `SELECT control.managed_namespace_reusable($1,$2)`, prep.CertificatePlan.Scope, now.Add(8*24*time.Hour)).Scan(&reusable); err != nil || reusable {
		t.Fatal("DNS cleanup did not hold old namespace", err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.managed_service_endpoints SET dns_state='removed',dns_available_at=NULL WHERE hostname=$1`, applied.Services[0].Hostname); err != nil {
		t.Fatal(err)
	}
	if err := d.pool.QueryRow(t.Context(), `SELECT control.managed_namespace_reusable($1,$2)`, prep.CertificatePlan.Scope, now.Add(time.Hour)).Scan(&reusable); err != nil || reusable {
		t.Fatal("DNS cleanup bypassed quarantine", err)
	}
	if err := d.pool.QueryRow(t.Context(), `SELECT control.managed_namespace_reusable($1,$2)`, prep.CertificatePlan.Scope, now.Add(8*24*time.Hour)).Scan(&reusable); err != nil || !reusable {
		t.Fatal("retired scope could not be reused after all boundaries cleared", err)
	}
	// concurrent exact retries all return the same historical response.
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			retry, err := d.RenamePublisherNamespace(t.Context(), request)
			if err != nil || !sameStoredResponse(t, retry, renamed) {
				t.Errorf("lost-reply retry changed result: %v", err)
			}
		})
	}
	wg.Wait()
	changed := request
	changed.NamespaceLabel = "other"
	if _, err := d.RenamePublisherNamespace(t.Context(), changed); !errors.Is(err, ErrPrivateServiceConflict) {
		t.Fatal("request key changed meaning", err)
	}
	changed.IdempotencyKey = "race-loser"
	if _, err := d.RenamePublisherNamespace(t.Context(), changed); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("stale revision accepted", err)
	}
	changed.ExpectedRevision = renamed.Revision
	if _, err := d.RenamePublisherNamespace(t.Context(), changed); err != nil {
		t.Fatal(err)
	}
	retry, err := d.RenamePublisherNamespace(t.Context(), request)
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
		go func() { <-start; _, err := d.RenamePublisherNamespace(t.Context(), candidate); results <- err }()
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
