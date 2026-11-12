package state

import (
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationPublisherGroupTemplates(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_templates")
	r := retainedEnvironmentProject(t, d, now)
	ctx := t.Context()
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"diagnostics": {Protocol: "http"}, "shell": {Protocol: "tcp"}})
	collection, _ := createTestCollection(t, d, r, "tractor", definition.Revision)
	var count int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1`, r.TeamID).Scan(&count); err != nil || count != 0 {
		t.Fatal("definition or collection allocated endpoints", err)
	}
	selection := EnvironmentPublisherSelection{TeamID: r.TeamID, ProjectKey: r.ProjectKey, EnvironmentID: collection.ID}
	if _, err := d.IssueEnvironmentPublisherEnrollment(ctx, IssueEnvironmentPublisherEnrollmentRequest{EnvironmentPublisherSelection: selection, ExpectedRevision: 1, ExpectedConfigurationHash: definition.ConfigurationHash, Services: []string{"diagnostics"}, MaxMembers: 1, Lifetime: 10 * time.Minute, Now: now}); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("collection ID accepted as environment enrollment", err)
	}
	var environments []Environment
	var requests []CreateEnvironmentRequest
	for _, name := range []string{"tractor-042", "tractor-043"} {
		request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: name, CollectionID: collection.ID, ExpectedCollectionRevision: collection.MutationRevision, Targets: EnvironmentTargets{"diagnostics": {Address: "localhost:9080"}, "shell": {Address: "localhost:22"}}, IdempotencyKey: name, Now: now}
		e, err := d.CreateEnvironment(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		environments = append(environments, e)
		requests = append(requests, request)
	}
	if environments[0].Services[0].ServiceID == environments[1].Services[0].ServiceID || len(environments[0].Services) != 2 || len(environments[1].Services) != 2 {
		t.Fatal("environments shared resources")
	}
	replayed, err := d.CreateEnvironment(ctx, requests[0])
	if err != nil || !reflect.DeepEqual(replayed, environments[0]) {
		t.Fatal("create not idempotent", err)
	}
	// human selectors cannot become service or namespace authority.
	for _, name := range []string{environments[0].Name, "renamed"} {
		if _, err := d.GetService(ctx, name, r.ActorID); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("friendly selector became a service identity", err)
		}
	}
	member := enrollTestEnvironment(t, d, r, environments[0])
	if len(member.assignments.Services) != 2 {
		t.Fatal("wrong assignments")
	}
	for _, s := range member.assignments.Services {
		if s.Service != "diagnostics" && s.Service != "shell" {
			t.Fatal("internal binding leaked", s)
		}
	}
	for _, e := range environments {
		service, err := d.GetService(ctx, e.Services[0].ServiceID, r.ActorID)
		if err != nil || service.ID != e.Services[0].ServiceID {
			t.Fatal("exact saved service lookup", err)
		}
	}
	batch := ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now}
	for _, e := range environments {
		batch.Items = append(batch.Items, EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: e.AppliedDefinitionRevision, Targets: EnvironmentTargets{"diagnostics": {Address: "localhost:9090"}, "shell": {Address: "localhost:22"}}})
	}
	updated, err := d.ApplyEnvironments(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range updated {
		for _, old := range environments {
			if old.ID == e.ID && e.Services[0].ServiceID != old.Services[0].ServiceID {
				t.Fatal("batch replaced retained service")
			}
		}
	}
	assignments, err := d.GetEnvironmentPublisherAssignments(ctx, member.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range assignments.Services {
		if s.Service == "diagnostics" && s.Configuration.Target != "localhost:9090" {
			t.Fatal("publisher missed explicit rollout")
		}
	}
	// publishing another definition does not edit or retire collection members.
	environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"unrelated": {Protocol: "tcp"}})
	for _, e := range updated {
		current, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, e.ID, r.ActorID)
		if err != nil || !reflect.DeepEqual(current.Services, e.Services) {
			t.Fatal("new shape changed existing member", err)
		}
	}
	if _, err := d.pool.Exec(ctx, `DELETE FROM control.service_definitions WHERE team_id=$1 AND project_key=$2 AND revision=$3`, r.TeamID, r.ProjectKey, definition.Revision); err == nil {
		t.Fatal("in-use immutable definition was removed")
	}
	if err := d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: updated[0].ID, ExpectedRevision: updated[0].MutationRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetEnvironmentPublisherAssignments(ctx, member.lease.AccessToken, now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("retired environment kept publisher authority", err)
	}
	if _, err := d.CreateEnvironment(ctx, requests[0]); !errors.Is(err, ErrEnvironmentRetired) {
		t.Fatal("retired creation key was reused", err)
	}
	other, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, updated[1].ID, r.ActorID)
	if err != nil || other.Retired || len(other.Services) != 2 {
		t.Fatal("retirement changed sibling", err)
	}
	if err := d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: other.ID, ExpectedRevision: other.MutationRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationPublisherGroupTemplateAtomicAllocation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "template_ports")
	ctx := t.Context()
	r := retainedEnvironmentProject(t, d, now)
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
	var environments []Environment
	for _, name := range []string{"tractor-a", "tractor-b"} {
		e, _ := createTestEnvironment(t, d, r, name, definition.Revision, EnvironmentTargets{"api": {Address: "localhost:9080"}})
		environments = append(environments, e)
	}
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, SourceFingerprint: r.SourceFingerprint, Name: "tractor-c", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "localhost:9080"}}, IdempotencyKey: "tractor-c", Now: now}
	if _, err := d.CreateEnvironment(ctx, request); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("creation accepted exhaustion", err)
	}
	grown := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}, "shell": {Protocol: "tcp"}})
	batch := ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now}
	for _, e := range environments {
		batch.Items = append(batch.Items, EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: grown.Revision, Targets: EnvironmentTargets{"api": {Address: "localhost:9080"}, "shell": {Address: "localhost:22"}}})
	}
	before := privateOwnershipSnapshot(t, d)
	if _, err := d.ApplyEnvironments(ctx, batch); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("batch accepted exhaustion", err)
	}
	if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
		t.Fatal("exhaustion partially committed")
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25446}}); err != nil {
		t.Fatal(err)
	}
	after, err := d.ApplyEnvironments(ctx, batch)
	if err != nil || len(after) != 2 || len(after[0].Services) != 2 || len(after[1].Services) != 2 {
		t.Fatal("batch addition incomplete", err)
	}
	batch.Items = nil
	for _, e := range after {
		batch.Items = append(batch.Items, EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"api": {Address: "localhost:9080"}}})
	}
	after, err = d.ApplyEnvironments(ctx, batch)
	if err != nil || len(after) != 2 || len(after[0].Services) != 1 || len(after[1].Services) != 1 {
		t.Fatal("batch removal incomplete", err)
	}
}

func TestIntegrationPublisherGroupConnectionDirectDeclaration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "direct_group_scope")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	request, key := retainedVisitorPreparation(t, f, now)
	request.Services = map[string]string{"api": "http"}
	signRetainedVisitorPreparation(&request, key)
	prepared, err := d.PrepareEnvironmentVisitor(t.Context(), request, now)
	if err != nil || len(prepared.Session.ServiceIDs) != 1 || prepared.Services["api"].ID != prepared.Session.ServiceIDs[0] {
		t.Fatal("exact environment did not resolve", err)
	}
	unknown, err := opaqueid.New(opaqueid.EnvironmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request.EnvironmentID = unknown
	signRetainedVisitorPreparation(&request, key)
	if _, err := d.PrepareEnvironmentVisitor(t.Context(), request, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("unknown environment fell back to unscoped service", err)
	}
	if err := d.DeleteService(t.Context(), prepared.Services["api"].ID, f.project.ActorID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("generic service deletion bypassed environment lifecycle", err)
	}
}

func TestIntegrationPublisherGroupTemplateWorkloadIsolation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "template_workloads")
	f := newRetainedVisitorFixture(t, d, now, retainedGitHubTrust(), 3600, false)
	ctx := t.Context()
	r := f.project
	second, _ := createTestEnvironment(t, d, r, "tractor-b", f.environment.AppliedDefinitionRevision, f.environment.Targets)
	permission, err := d.CreateEnvironmentVisitorPermission(ctx, EnvironmentVisitorPermission{MachineID: f.machine.ID, TeamID: r.TeamID, ProjectKey: r.ProjectKey, Scope: EnvironmentPermissionScope{EnvironmentIDs: []string{f.environment.ID, second.ID}}, Services: []string{"api", "db"}, MaxDurationSeconds: 3600, ExpiresAt: now.Add(time.Hour)}, r.ActorID, now)
	if err != nil {
		t.Fatal(err)
	}
	f.permission = permission
	request, key := retainedVisitorPreparation(t, f, now)
	request.Services = map[string]string{"api": "http"}
	signRetainedVisitorPreparation(&request, key)
	unscoped := request
	unscoped.EnvironmentID = ""
	signRetainedVisitorPreparation(&unscoped, key)
	if _, err := d.PrepareEnvironmentVisitor(ctx, unscoped, now); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("unscoped policy guessed an environment", err)
	}
	prepared, err := d.PrepareEnvironmentVisitor(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	first := prepared.Session
	if len(first.ServiceIDs) != 1 || first.ServiceIDs[0] != prepared.Services["api"].ID {
		t.Fatal("wrong service snapshot")
	}
	inventory, err := d.ListWorkloadServices(ctx, first.Credential, now)
	if err != nil || len(inventory) != 1 || inventory[0].Service != "api" {
		t.Fatal("internal service key leaked", err)
	}
	var otherID string
	for _, s := range second.Services {
		if s.Service == "api" {
			otherID = s.ServiceID
		}
	}
	if _, err := d.CheckWorkloadService(ctx, first.Credential, otherID, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("environment A visited B", err)
	}
	request.EnvironmentID = second.ID
	if _, err := d.PrepareEnvironmentVisitor(ctx, request, now); !errors.Is(err, ErrMachineDenied) {
		t.Fatal("unsigned scope change accepted", err)
	}
	signRetainedVisitorPreparation(&request, key)
	if _, err := d.PrepareEnvironmentVisitor(ctx, request, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatal("existing nonce widened environment scope", err)
	}
	createTestEnvironment(t, d, r, "tractor-c", f.environment.AppliedDefinitionRevision, f.environment.Targets)
	after, err := d.RenewEnvironmentVisitorSession(ctx, first.ID, first.Credential, signWorkloadRenewal(first, key), now.Add(31*time.Second))
	if err != nil || len(after.ServiceIDs) != 1 || after.ServiceIDs[0] != first.ServiceIDs[0] {
		t.Fatal("new environment widened existing rights", err)
	}
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"db": {Protocol: "postgres"}})
	if _, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: f.environment.ID, ExpectedRevision: f.environment.MutationRevision, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"db": {Address: "db.internal:5432"}}}, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CheckWorkloadService(ctx, first.Credential, first.ServiceIDs[0], now.Add(32*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("removed accepted service retained access", err)
	}
}
