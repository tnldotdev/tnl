package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func TestIntegrationPublisherGroupBindings(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_bindings")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}}, Services: map[string]ProjectServiceConfiguration{
		"api":   {PublisherGroup: "customer", Protocol: "http", TargetBinding: "group"},
		"fixed": {PublisherGroup: "customer", Protocol: "tcp", Target: "localhost:22"},
	}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	create := func(key, target string, revision int64) CreateBoundPublisherGroupRequest {
		return CreateBoundPublisherGroupRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ExpectedRevision: revision, Now: now, Creation: PublisherGroupCreation{Template: "customer", IdempotencyKey: key, Bindings: PublisherGroupBindings{"api": {Target: target}}}}
	}
	bad := create("missing", "localhost:3000", current.Revision)
	bad.Creation.Bindings = nil
	if _, err = d.CreateBoundPublisherGroup(ctx, bad); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("missing binding", err)
	}
	firstRequest := create("external/customer/42", "http://192.0.2.42:3000/", current.Revision)
	beforeRequest, _ := json.Marshal(firstRequest)
	first, err := d.CreateBoundPublisherGroup(ctx, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	afterRequest, _ := json.Marshal(firstRequest)
	if !bytes.Equal(beforeRequest, afterRequest) {
		t.Fatal("creation mutated its caller's generated-name or binding inputs")
	}
	if first.ID == "" || !naming.ValidServiceName(first.Name) || first.Name == firstRequest.Creation.IdempotencyKey || first.From != "customer" || len(first.Services) != 2 {
		t.Fatal("invalid generated identity", first)
	}
	second, err := d.CreateBoundPublisherGroup(ctx, create("external/customer/43", "192.0.2.43:3000", first.Revision))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.Services[0].ServiceID == second.Services[0].ServiceID {
		t.Fatal("shared customer identities")
	}
	firstRequest.Creation.Bindings["api"] = PublisherGroupTargetBinding{Target: "192.0.2.42:3000"}
	replayed, err := d.CreateBoundPublisherGroup(ctx, firstRequest)
	if err != nil || replayed.ID != first.ID || replayed.Revision != second.Revision {
		t.Fatal("semantic replay", replayed, err)
	}
	changed := firstRequest
	changed.Creation.Bindings = PublisherGroupBindings{"api": {Target: "192.0.2.99:3000"}}
	if _, err = d.CreateBoundPublisherGroup(ctx, changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("key admitted a changed request", err)
	}
	unauthorized := firstRequest
	unauthorized.ActorID = "missing"
	if _, err = d.CreateBoundPublisherGroup(ctx, unauthorized); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replay bypassed authorization", err)
	}

	e1, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, first.ID, r.ActorID, 2, 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	if e1.Publisher.Project != r.ProjectKey || e1.Publisher.Group != first.Name {
		t.Fatal("missing installation context")
	}
	m1 := enrollAppliedGroup(t, d, r, e1, now)
	e2, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, second.ID, r.ActorID, 1, 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	m2 := enrollAppliedGroup(t, d, r, e2, now)
	assertTarget := func(member enrolledGroupReplica, target string) PublisherGroupServiceAssignment {
		t.Helper()
		assignments, err := d.GetPublisherGroupAssignments(ctx, member.lease.AccessToken, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, assignment := range assignments.Services {
			if assignment.Service == "api" {
				if assignment.Configuration.Target != target || assignment.Configuration.TargetBinding != "" {
					t.Fatal("wrong exact assigned target", assignment)
				}
				return assignment
			}
		}
		t.Fatal("missing api assignment")
		return PublisherGroupServiceAssignment{}
	}
	oldAssignment := assertTarget(m1, "192.0.2.42:3000")
	_ = assertTarget(m2, "192.0.2.43:3000")
	snapshot, err := targettrust.NewCache(nil).Capture(ctx, "", "192.0.2.42:8443", config.TrustSource{Hostname: new("api.customer.internal"), CA: "system"})
	if err != nil {
		t.Fatal(err)
	}
	trust, err := snapshot.Declaration()
	if err != nil {
		t.Fatal(err)
	}
	updated, err := d.UpdatePublisherGroupBindings(ctx, r.TeamID, r.ProjectKey, first.ID, r.ActorID, second.Revision, PublisherGroupBindings{"api": {Target: "192.0.2.42:8443", TargetTLS: &ProjectTargetTLS{Hostname: trust.Hostname, Digest: trust.Digest}}}, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != first.ID || updated.Services[0].ServiceID != first.Services[0].ServiceID || updated.Services[0].Hostname != first.Services[0].Hostname || updated.Services[0].Port != first.Services[0].Port {
		t.Fatal("binding update replaced endpoint", updated)
	}
	newAssignment := assertTarget(m1, "192.0.2.42:8443")
	if newAssignment.GrantID == oldAssignment.GrantID || newAssignment.TrustRevision <= oldAssignment.TrustRevision || newAssignment.Configuration.TargetTLS.Digest != trust.Digest {
		t.Fatal("binding update retained old trust/grant", oldAssignment, newAssignment)
	}
	_ = assertTarget(m2, "192.0.2.43:3000")
	if _, err := d.UpdatePublisherGroupBindings(ctx, r.TeamID, r.ProjectKey, first.ID, r.ActorID, second.Revision, updated.Bindings, false, now); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("stale no-op binding update", err)
	}
	current, err = d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	if current.Configuration.Services["api"].Target != "" || current.Configuration.Services["api"].TargetBinding != "group" {
		t.Fatal("instance settings entered desired config")
	}
	var ciphertext []byte
	if err := d.pool.QueryRow(ctx, `SELECT bindings_ciphertext FROM control.publisher_group_bindings WHERE group_id=$1`, first.ID).Scan(&ciphertext); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(ciphertext, []byte("192.0.2.42")) || bytes.Contains(ciphertext, []byte(trust.Hostname)) {
		t.Fatal("plaintext instance settings")
	}
	r.ExpectedRevision = current.Revision
	r.Configuration = current.Configuration
	g := r.Configuration.PublisherGroups["customer"]
	g.Description = "updated template"
	r.Configuration.PublisherGroups["customer"] = g
	current, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	_ = assertTarget(m1, "192.0.2.42:8443")
	_ = assertTarget(m2, "192.0.2.43:3000")
	if err := d.RevokePublisherGroupMember(ctx, r.TeamID, r.ProjectKey, first.ID, m2.member.PublisherIdentityID, r.ActorID, now); err == nil {
		t.Fatal("cross-customer revocation")
	}
	if err := d.RevokePublisherGroupMember(ctx, r.TeamID, r.ProjectKey, first.ID, m1.member.PublisherIdentityID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetPublisherGroupAssignments(ctx, m1.lease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("revoked exact member retains access", err)
	}
	current, err = d.RemovePublisherGroup(ctx, r.TeamID, r.ProjectKey, first.ID, r.ActorID, current.Revision, false, now)
	if err != nil {
		t.Fatal(err)
	}
	retired, err := d.CreateBoundPublisherGroup(ctx, firstRequest)
	if !errors.Is(err, ErrPublisherGroupRetired) || retired.ID != "" {
		t.Fatal("retired key returned a usable create identity", retired, err)
	}
	read, err := d.GetManagedPublisherGroup(ctx, r.TeamID, r.ProjectKey, first.ID, r.ActorID)
	if err != nil || !read.Retired || read.ID != first.ID {
		t.Fatal("retired get", read, err)
	}
	if len(current.Groups) != 1 || current.Groups[0].ID != second.ID {
		t.Fatal("retirement changed other group")
	}
	_ = assertTarget(m2, "192.0.2.43:3000")
	current, err = d.RemovePublisherGroup(ctx, r.TeamID, r.ProjectKey, second.ID, r.ActorID, current.Revision, false, now)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = current.Revision
	r.Configuration = ProjectConfiguration{}
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CreateBoundPublisherGroup(ctx, firstRequest); !errors.Is(err, ErrPublisherGroupRetired) {
		t.Fatal("removed template changed retired key behavior", err)
	}
}

func TestIntegrationPublisherGroupBoundDiscoveryAndReplayNormalization(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "bound_discovery")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}}, Services: map[string]ProjectServiceConfiguration{
		"api":     {PublisherGroup: "customer", TargetBinding: "group"},
		"cluster": {PublisherGroup: "customer", Protocol: "kubernetes", TargetBinding: "group"},
		"db":      {PublisherGroup: "customer", Protocol: "postgres", TargetBinding: "group"},
	}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	request := CreateBoundPublisherGroupRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ExpectedRevision: current.Revision, Now: now, Creation: PublisherGroupCreation{Template: "customer", IdempotencyKey: "same-key", Bindings: PublisherGroupBindings{
		"api":     {Target: "http://192.0.2.1:3000/"},
		"cluster": {TargetDiscovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: new("customer-one")}},
		"db":      {TargetDiscovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Cluster: new("customer-db")}},
	}}}
	first, err := d.CreateBoundPublisherGroup(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	// provider defaults and address shorthand are part of semantic equality.
	canonical := request
	canonical.Creation.Bindings = PublisherGroupBindings{
		"db":      {TargetDiscovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Cluster: new("customer-db"), Endpoint: new("writer")}},
		"cluster": {TargetDiscovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: new("customer-one")}},
		"api":     {Target: "192.0.2.1:3000"},
	}
	replayed, err := d.CreateBoundPublisherGroup(ctx, canonical)
	if err != nil || replayed.ID != first.ID {
		t.Fatal("provider-default replay", replayed, err)
	}
	var clusterService string
	for _, service := range first.Services {
		if service.Service == "cluster" {
			clusterService = service.ServiceID
		}
	}
	auth, err := d.visitorKubernetesAuth(ctx, controlstatedb.New(d.pool), clusterService)
	if err != nil || auth == nil || auth.Cluster != "customer-one" || auth.Region != "us-east-1" {
		t.Fatal("visitor projection lost exact bound EKS selector", auth, err)
	}
	// the template's current protocol is not the normalization authority for an
	// older create request. the immutable create record retains that context.
	r.ExpectedRevision = first.Revision
	api := r.Configuration.Services["api"]
	api.Protocol = "postgres"
	r.Configuration.Services["api"] = api
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("protocol changed without explicit approval", err)
	}
	r.GroupBindings = map[string]PublisherGroupBindings{first.ID: canonical.Creation.Bindings}
	current, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	replayed, err = d.CreateBoundPublisherGroup(ctx, request)
	if err != nil || replayed.ID != first.ID || replayed.Revision != current.Revision {
		t.Fatal("template change broke immutable replay", replayed, err)
	}
	// keys are project-scoped rather than global customer identifiers.
	r.ProjectKey = "other"
	r.ExpectedRevision = 0
	r.GroupBindings = nil
	current, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	canonical.ProjectKey = r.ProjectKey
	canonical.ExpectedRevision = current.Revision
	second, err := d.CreateBoundPublisherGroup(ctx, canonical)
	if err != nil || second.ID == first.ID {
		t.Fatal("key was not project-scoped", second, err)
	}
}

func TestIntegrationPublisherGroupBindingsAtomicApply(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_bindings_atomic")
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "customer", TargetBinding: "group"}}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	groups := []PublisherGroupResource{}
	for i := 0; i < 2; i++ {
		group, err := d.CreateBoundPublisherGroup(ctx, CreateBoundPublisherGroupRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ExpectedRevision: current.Revision, Now: now, Creation: PublisherGroupCreation{Name: fmt.Sprintf("customer-%d", i), Template: "customer", Bindings: PublisherGroupBindings{"api": {Target: fmt.Sprintf("192.0.2.%d:3000", i+1)}}}})
		if err != nil {
			t.Fatal(err)
		}
		current.Revision = group.Revision
		groups = append(groups, group)
	}
	r.ExpectedRevision = current.Revision
	r.Configuration.Services["db"] = ProjectServiceConfiguration{PublisherGroup: "customer", Protocol: "postgres", TargetBinding: "group"}
	r.GroupBindings = map[string]PublisherGroupBindings{groups[0].ID: {"api": {Target: "192.0.2.1:3001"}, "db": {Target: "192.0.2.1:5432"}}}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("missing customer binding accepted", err)
	}
	r.GroupBindings[groups[1].ID] = PublisherGroupBindings{"api": {Target: "192.0.2.2:3001"}, "db": {Target: "192.0.2.2:5432"}}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("capacity failure accepted", err)
	}
	after, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || after.Revision != current.Revision || len(after.Services) != 2 || after.Groups[0].Bindings["api"].Target != "192.0.2.1:3000" {
		t.Fatal("failed apply partially saved", after, err)
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25446}}); err != nil {
		t.Fatal(err)
	}
	after, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil || len(after.Services) != 4 {
		t.Fatal("atomic apply failed", after, err)
	}
	for _, before := range groups {
		for _, group := range after.Groups {
			if group.ID == before.ID && group.Bindings["api"].Target == before.Bindings["api"].Target {
				t.Fatal("binding batch not applied")
			}
		}
	}
}

func TestIntegrationPublisherGroupCreateIdempotencyConcurrency(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_creation_race")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "customer", TargetBinding: "group"}}}
	current, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	request := CreateBoundPublisherGroupRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ExpectedRevision: current.Revision, Now: now, Creation: PublisherGroupCreation{Template: "customer", IdempotencyKey: "customer/id", Bindings: PublisherGroupBindings{"api": {Target: "192.0.2.1:3000"}}}}
	const workers = 8
	var wg sync.WaitGroup
	results := make(chan PublisherGroupResource, workers)
	failures := make(chan error, workers)
	start := make(chan struct{})
	for range workers {
		wg.Go(func() {
			<-start
			result, err := d.CreateBoundPublisherGroup(t.Context(), request)
			results <- result
			failures <- err
		})
	}
	close(start)
	wg.Wait()
	close(results)
	close(failures)
	for err := range failures {
		if err != nil {
			t.Fatal(err)
		}
	}
	id := ""
	for result := range results {
		if id == "" {
			id = result.ID
		}
		if result.ID != id {
			t.Fatal("duplicate allocation", id, result.ID)
		}
	}
	after, err := d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || len(after.Groups) != 1 || len(after.Services) != 1 || after.Revision != current.Revision+1 {
		t.Fatal("race allocated more than once", after, err)
	}
}
