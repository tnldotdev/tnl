package state

import (
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"
)

func TestIntegrationPublisherNamespaceRenameAtomicAuthority(t *testing.T) {
	d, now, _, _ := newPublishRunPrerequisites(t)
	r := retainedEnvironmentProject(t, d, now)
	ctx := t.Context()
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	creation := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: "production", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "api.internal:3000"}}, Public: true, DNSAutomation: true, IdempotencyKey: "original", Now: now}
	applied, err := d.CreateEnvironment(ctx, creation)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollTestEnvironment(t, d, r, applied)
	assignment := replica.assignments.Services[0]
	access := environmentAssignmentAccess(t, d, replica, assignment, now)
	prep, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "old-run", now, ServiceMetadata{Protocol: assignment.Configuration.Protocol, TrustRevision: assignment.TrustRevision}, &replica.assignments.Environment)
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(ctx, assignment.ServiceID, prep.RunID, prep.RunNumber, access.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := d.CreateServiceGrant(ctx, assignment.ServiceID, r.ActorID, "namespace-visitor", "identity", r.ActorID, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	before := privateOwnershipSnapshot(t, d)
	collision := creation
	collision.IdempotencyKey = "collision"
	collision.Targets = EnvironmentTargets{"api": {Address: "conflicting.internal:3000"}}
	if _, err := d.CreateEnvironment(ctx, collision); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("active selector collision accepted", err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("collision partially changed authority")
	}
	// namespace changes are an explicit lifecycle boundary: retire the old
	// environment and create another. no public rename can transfer saved IDs,
	// visitor grants, publisher leases, or certificate authority to the new one.
	if err := d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: applied.ID, ExpectedRevision: applied.MutationRevision, Now: now.Add(time.Second)}); err != nil {
		t.Fatal(err)
	}
	creation.Name, creation.IdempotencyKey = "live", "replacement"
	creation.Now = now.Add(time.Second)
	replacement, err := d.CreateEnvironment(ctx, creation)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ID == applied.ID || replacement.Services[0].ServiceID == assignment.ServiceID || replacement.Services[0].Hostname == applied.Services[0].Hostname {
		t.Fatal("replacement adopted old identity/namespace")
	}
	var revoked bool
	if err := d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.visitor_grants WHERE id=$1`, grant.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatal("retirement retained old visitor grant", err)
	}
	newGrants, _, err := d.ListServiceGrants(ctx, replacement.Services[0].ServiceID, r.ActorID, "")
	if err != nil || len(newGrants) != 0 {
		t.Fatal("replacement restored retired visitor authority", err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err == nil {
		t.Fatal("old run token survived retirement")
	}
	if _, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "stale-authority", now.Add(time.Second), ServiceMetadata{Protocol: "http", TrustRevision: assignment.TrustRevision}, &replica.assignments.Environment); err == nil {
		t.Fatal("old publication authority survived")
	}
	if _, err := d.GetEnvironmentPublisherAssignments(ctx, replica.lease.AccessToken, now.Add(time.Second)); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("retired lease survived", err)
	}
	next := enrollTestEnvironment(t, d, r, replacement)
	newAccess := environmentAssignmentAccess(t, d, next, next.assignments.Services[0], now.Add(time.Second))
	newPrep, err := d.PrepareServiceRun(ctx, replacement.Services[0].ServiceID, newAccess.PublisherIdentity, "new-run", now.Add(time.Second), ServiceMetadata{Protocol: "http", TrustRevision: next.assignments.Services[0].TrustRevision}, &next.assignments.Environment)
	if err != nil || newPrep.CertificatePlan.Scope == prep.CertificatePlan.Scope || reflect.DeepEqual(newPrep.CertificatePlan.Identifiers, prep.CertificatePlan.Identifiers) {
		t.Fatal("replacement reused old certificate scope", err)
	}
	var oldRetired, newPending bool
	if err := d.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=$1 AND retired_at IS NOT NULL AND dns_state='removing'),EXISTS(SELECT 1 FROM control.service_endpoints WHERE hostname=$2 AND retired_at IS NULL AND dns_state='pending')`, applied.Services[0].Hostname, replacement.Services[0].Hostname).Scan(&oldRetired, &newPending); err != nil || !oldRetired || !newPending {
		t.Fatal("DNS lifecycle transition incomplete", err)
	}
	var reusable bool
	if err := d.pool.QueryRow(ctx, `SELECT control.service_namespace_reusable($1,$2)`, prep.CertificatePlan.Scope, now.Add(8*24*time.Hour)).Scan(&reusable); err != nil || reusable {
		t.Fatal("DNS cleanup did not hold old namespace", err)
	}
	if _, err := d.pool.Exec(ctx, `UPDATE control.service_endpoints SET dns_state='removed',dns_available_at=NULL WHERE hostname=$1`, applied.Services[0].Hostname); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		at   time.Time
		want bool
	}{{now.Add(time.Hour), false}, {now.Add(8 * 24 * time.Hour), true}} {
		if err := d.pool.QueryRow(ctx, `SELECT control.service_namespace_reusable($1,$2)`, prep.CertificatePlan.Scope, test.at).Scan(&reusable); err != nil || reusable != test.want {
			t.Fatal("DNS cleanup/quarantine boundary", test.want, err)
		}
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Go(func() {
			retry, err := d.CreateEnvironment(ctx, creation)
			if err != nil || retry.ID != replacement.ID || retry.MutationRevision != replacement.MutationRevision {
				t.Errorf("concurrent creation retry changed result: %v", err)
			}
		})
	}
	wg.Wait()
	changed := creation
	changed.Name = "other"
	if _, err := d.CreateEnvironment(ctx, changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("creation key changed meaning", err)
	}
	// two explicit application mutations race at one revision. exactly one wins;
	// neither can rename the namespace or reauthorize a retired service ID.
	results := make(chan error, 2)
	start := make(chan struct{})
	for _, target := range []string{"race-one.internal:3000", "race-two.internal:3000"} {
		wg.Go(func() {
			<-start
			_, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: replacement.ID, ExpectedRevision: replacement.MutationRevision, DefinitionRevision: replacement.AppliedDefinitionRevision, Targets: EnvironmentTargets{"api": {Address: target}}}, Now: now.Add(2 * time.Second)})
			results <- err
		})
	}
	close(start)
	wg.Wait()
	winners, stale := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			winners++
		} else if errors.Is(err, ErrEnvironmentStale) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || stale != 1 {
		t.Fatal("revision race did not have one winner", winners, stale)
	}
	current, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, replacement.ID, r.ActorID)
	if err != nil || current.Services[0].ServiceID != replacement.Services[0].ServiceID || current.Services[0].Hostname != replacement.Services[0].Hostname {
		t.Fatal("application changed endpoint authority", err)
	}
	before = privateOwnershipSnapshot(t, d)
	retry, err := d.CreateEnvironment(ctx, creation)
	if err != nil || retry.ID != current.ID || retry.MutationRevision != current.MutationRevision || !reflect.DeepEqual(retry.Targets, current.Targets) || !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("creation retry rewound later state or restored authority", err)
	}
}
