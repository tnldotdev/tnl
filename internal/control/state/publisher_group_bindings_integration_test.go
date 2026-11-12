package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationPublisherGroupBindings(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_bindings")
	ctx := t.Context()
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "fixed": {Protocol: "tcp"}})
	create := func(key, target string) CreateEnvironmentRequest {
		return CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: key, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: target}, "fixed": {Address: "localhost:22"}}, IdempotencyKey: key, Now: now}
	}
	bad := create("missing", "localhost:3000")
	bad.Targets = nil
	if _, err := d.CreateEnvironment(ctx, bad); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("missing target", err)
	}
	firstRequest := create("external/customer/42", "http://192.0.2.42:3000/")
	beforeRequest, _ := json.Marshal(firstRequest)
	first, err := d.CreateEnvironment(ctx, firstRequest)
	if err != nil {
		t.Fatal(err)
	}
	afterRequest, _ := json.Marshal(firstRequest)
	if !bytes.Equal(beforeRequest, afterRequest) {
		t.Fatal("creation mutated its caller")
	}
	if !opaqueid.Valid(first.ID, opaqueid.EnvironmentPrefix) || first.Name != firstRequest.Name || first.AppliedDefinitionRevision != definition.Revision || len(first.Services) != 2 {
		t.Fatal("invalid exact environment", first)
	}
	second, err := d.CreateEnvironment(ctx, create("external/customer/43", "192.0.2.43:3000"))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID == second.ID || first.Services[0].ServiceID == second.Services[0].ServiceID {
		t.Fatal("shared customer identities")
	}
	firstRequest.Targets["api"] = EnvironmentTarget{Address: "192.0.2.42:3000"}
	replayed, err := d.CreateEnvironment(ctx, firstRequest)
	if err != nil || !reflect.DeepEqual(replayed, first) {
		t.Fatal("semantic replay", err)
	}
	changed := firstRequest
	changed.Targets = EnvironmentTargets{"api": {Address: "192.0.2.99:3000"}, "fixed": {Address: "localhost:22"}}
	if _, err := d.CreateEnvironment(ctx, changed); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("key admitted changed intent", err)
	}
	unauthorized := firstRequest
	unauthorized.ActorID = "missing"
	if _, err := d.CreateEnvironment(ctx, unauthorized); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("replay bypassed authorization", err)
	}
	e1 := retainedPublisherEnrollment(t, d, r, first, 2)
	if e1.ProjectKey != r.ProjectKey || e1.EnvironmentID != first.ID || e1.TeamID != r.TeamID {
		t.Fatal("missing exact installation context")
	}
	m1 := retainedPublisherReplica(t, d, e1, now)
	m2 := enrollTestEnvironment(t, d, r, second)
	assertTarget := func(member environmentPublisherReplica, target string) EnvironmentPublisherAssignment {
		t.Helper()
		assignments, err := d.GetEnvironmentPublisherAssignments(ctx, member.lease.AccessToken, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, assignment := range assignments.Services {
			if assignment.Service == "api" {
				if assignment.Configuration.Target != target {
					t.Fatal("wrong exact target", assignment)
				}
				return assignment
			}
		}
		t.Fatal("missing api assignment")
		return EnvironmentPublisherAssignment{}
	}
	oldAssignment := assertTarget(m1, "192.0.2.42:3000")
	_ = assertTarget(m2, "192.0.2.43:3000")
	trust := appliedTargetTrust(t, "api.customer.internal")
	targets := EnvironmentTargets{"api": {Address: "192.0.2.42:8443", TLS: trust}, "fixed": {Address: "localhost:22"}}
	updated, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: first.ID, ExpectedRevision: first.MutationRevision, DefinitionRevision: first.AppliedDefinitionRevision, Targets: targets}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != first.ID || updated.Services[0].ServiceID != first.Services[0].ServiceID || updated.Services[0].Hostname != first.Services[0].Hostname || updated.Services[0].Port != first.Services[0].Port {
		t.Fatal("target update replaced endpoint")
	}
	newAssignment := assertTarget(m1, "192.0.2.42:8443")
	if newAssignment.GrantID != oldAssignment.GrantID || newAssignment.TrustRevision <= oldAssignment.TrustRevision || newAssignment.Configuration.TargetTLS.Digest != trust.Digest {
		t.Fatal("apply conflated trust and grant authority")
	}
	mutation := retainedPublisherGrantMutation(t, d, r, updated, m1.member.PublisherIdentityID, newAssignment.ServiceID)
	if err := d.RevokeEnvironmentPublisherGrant(ctx, RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: mutation, GrantID: oldAssignment.GrantID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthorizeEnvironmentPublisherService(ctx, AuthorizeEnvironmentPublisherServiceRequest{EnvironmentPublisherGrantMutation: mutation, ExpectedPreviousGrantID: environmentPublisherGrantExpected(t, oldAssignment.GrantID), IdempotencyKey: "target-rotation"}); err != nil {
		t.Fatal(err)
	}
	if assertTarget(m1, "192.0.2.42:8443").GrantID == oldAssignment.GrantID {
		t.Fatal("explicit rotation retained old grant")
	}
	_ = assertTarget(m2, "192.0.2.43:3000")
	if _, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: first.ID, ExpectedRevision: first.MutationRevision, DefinitionRevision: first.AppliedDefinitionRevision, Targets: targets}, Now: now}); !errors.Is(err, ErrEnvironmentStale) {
		t.Fatal("stale no-op target update", err)
	}
	stored, err := d.CreateServiceDefinition(ctx, CreateServiceDefinitionRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Definition: definition.Definition, Now: now})
	if err != nil || stored.Revision != definition.Revision || !reflect.DeepEqual(stored.Definition, definition.Definition) {
		t.Fatal("instance targets entered shared definition", err)
	}
	var ciphertext []byte
	if err := d.pool.QueryRow(ctx, `SELECT bindings_ciphertext FROM control.publisher_group_bindings WHERE group_id=(SELECT group_id FROM control.environments WHERE id=$1)`, first.ID).Scan(&ciphertext); err != nil || bytes.Contains(ciphertext, []byte("192.0.2.42")) || bytes.Contains(ciphertext, []byte(trust.Hostname)) {
		t.Fatal("plaintext instance settings", err)
	}
	// authoring a newer shared shape does not mutate existing environments.
	environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "postgres"}, "fixed": {Protocol: "tcp"}})
	_ = assertTarget(m1, "192.0.2.42:8443")
	_ = assertTarget(m2, "192.0.2.43:3000")
	if err := d.RevokeEnvironmentPublisher(ctx, environmentPublisherSelection(t, d, r, updated), m2.member.PublisherIdentityID, now); err == nil {
		t.Fatal("cross-customer revocation")
	}
	if err := d.RevokeEnvironmentPublisher(ctx, environmentPublisherSelection(t, d, r, updated), m1.member.PublisherIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetEnvironmentPublisherAssignments(ctx, m1.lease.AccessToken, now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("revoked member retains access", err)
	}
	if err := d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: first.ID, ExpectedRevision: updated.MutationRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
	retired, err := d.CreateEnvironment(ctx, firstRequest)
	if !errors.Is(err, ErrEnvironmentRetired) || retired.ID != "" {
		t.Fatal("retired create returned usable identity", err)
	}
	read, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, first.ID, r.ActorID)
	if err != nil || !read.Retired || read.ID != first.ID {
		t.Fatal("retired get", err)
	}
	other, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, second.ID, r.ActorID)
	if err != nil || other.Retired {
		t.Fatal("retirement changed sibling", err)
	}
	_ = assertTarget(m2, "192.0.2.43:3000")
	if err := d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: second.ID, ExpectedRevision: second.MutationRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
	environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"unrelated": {Protocol: "tcp"}})
	if _, err := d.CreateEnvironment(ctx, firstRequest); !errors.Is(err, ErrEnvironmentRetired) {
		t.Fatal("new definition changed retired key behavior", err)
	}
}

func TestIntegrationPublisherGroupBoundDiscoveryAndReplayNormalization(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "bound_discovery")
	ctx := t.Context()
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "cluster": {Protocol: "kubernetes"}, "db": {Protocol: "postgres"}})
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: "customer", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "http://192.0.2.1:3000/"}, "cluster": {Discovery: &ProjectTargetDiscovery{Type: "eks", Region: "us-east-1", Cluster: new("customer-one")}}, "db": {Discovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Cluster: new("customer-db")}}}, IdempotencyKey: "same-key", Now: now}
	first, err := d.CreateEnvironment(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	canonical := request
	canonical.Targets = EnvironmentTargets{"api": {Address: "192.0.2.1:3000"}, "cluster": request.Targets["cluster"], "db": {Discovery: &ProjectTargetDiscovery{Type: "rds", Region: "us-east-1", Cluster: new("customer-db"), Endpoint: new("writer")}}}
	replayed, err := d.CreateEnvironment(ctx, canonical)
	if err != nil || replayed.ID != first.ID {
		t.Fatal("provider-default replay", err)
	}
	var clusterService string
	for _, service := range first.Services {
		if service.Service == "cluster" {
			clusterService = service.ServiceID
		}
	}
	auth, err := d.visitorKubernetesAuth(ctx, controlstatedb.New(d.pool), clusterService)
	if err != nil || auth == nil || auth.Cluster != "customer-one" || auth.Region != "us-east-1" {
		t.Fatal("visitor lost exact EKS selector", err)
	}
	changed := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "postgres"}, "cluster": {Protocol: "kubernetes"}, "db": {Protocol: "postgres"}})
	if _, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: first.ID, ExpectedRevision: first.MutationRevision, DefinitionRevision: changed.Revision}, Now: now}); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("protocol changed without target approval", err)
	}
	updated, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: first.ID, ExpectedRevision: first.MutationRevision, DefinitionRevision: changed.Revision, Targets: canonical.Targets}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	replayed, err = d.CreateEnvironment(ctx, request)
	if err != nil || replayed.ID != first.ID || replayed.MutationRevision != updated.MutationRevision {
		t.Fatal("new definition broke immutable replay", err)
	}
	other := r
	other.ProjectKey = "other"
	otherDefinition := environmentDefinition(t, d, other, definition.Definition.Services)
	canonical.ProjectKey = other.ProjectKey
	canonical.DefinitionRevision = otherDefinition.Revision
	second, err := d.CreateEnvironment(ctx, canonical)
	if err != nil || second.ID == first.ID {
		t.Fatal("key was not project scoped", err)
	}
}

func TestIntegrationPublisherGroupBindingsAtomicApply(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_bindings_atomic")
	ctx := t.Context()
	r := retainedEnvironmentProject(t, d, now)
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	var environments []Environment
	for i := range 2 {
		e, _ := createTestEnvironment(t, d, r, fmt.Sprintf("customer-%d", i), definition.Revision, EnvironmentTargets{"api": {Address: fmt.Sprintf("192.0.2.%d:3000", i+1)}})
		environments = append(environments, e)
	}
	grown := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "db": {Protocol: "postgres"}})
	request := ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now}
	for i, e := range environments {
		request.Items = append(request.Items, EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: grown.Revision, Targets: EnvironmentTargets{"api": {Address: fmt.Sprintf("192.0.2.%d:3001", i+1)}, "db": {Address: fmt.Sprintf("192.0.2.%d:5432", i+1)}}})
	}
	before := privateOwnershipSnapshot(t, d)
	bad := request
	bad.Items = append([]EnvironmentApplication(nil), request.Items...)
	bad.Items[1].Targets = nil
	if _, err := d.ApplyEnvironments(ctx, bad); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("missing environment approval accepted", err)
	}
	if _, err := d.ApplyEnvironments(ctx, request); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("capacity failure accepted", err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("failed batch partially committed")
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25446}}); err != nil {
		t.Fatal(err)
	}
	after, err := d.ApplyEnvironments(ctx, request)
	if err != nil || len(after) != 2 {
		t.Fatal("atomic batch failed", err)
	}
	for _, e := range after {
		if len(e.Services) != 2 || e.Targets["api"].Address == environments[0].Targets["api"].Address || e.MutationRevision != 2 {
			t.Fatal("batch target/revision not applied")
		}
	}
}

func TestIntegrationPublisherGroupCreateIdempotencyConcurrency(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "group_creation_race")
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: "customer", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "192.0.2.1:3000"}}, IdempotencyKey: "customer/id", Now: now}
	const workers = 8
	var wg sync.WaitGroup
	results := make(chan Environment, workers)
	failures := make(chan error, workers)
	start := make(chan struct{})
	for range workers {
		wg.Go(func() {
			<-start
			result, err := d.CreateEnvironment(t.Context(), request)
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
	after, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, id, r.ActorID)
	if err != nil || len(after.Services) != 1 || after.MutationRevision != 1 {
		t.Fatal("race allocated more than once", err)
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.environments WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&count); err != nil || count != 1 {
		t.Fatal("race created extra environments", err)
	}
}
