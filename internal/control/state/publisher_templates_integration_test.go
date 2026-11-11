package state

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationPublisherGroupTemplates(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "publisher_templates")
	r := appliedProjectRequest(t, d, now)
	r.Configuration.PublisherGroups = map[string]ProjectPublisherGroup{"tractor": {Template: true}}
	r.Configuration.Services = map[string]ProjectServiceConfiguration{
		"diagnostics": {PublisherGroup: "tractor", Target: "http://localhost:9080", Access: &ProjectServiceAccess{Team: true}},
		"shell":       {PublisherGroup: "tractor", Protocol: "tcp", Target: "localhost:22"},
	}
	ctx := t.Context()
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Groups) != 0 || len(current.Services) != 0 {
		t.Fatalf("template allocated endpoints: %+v", current)
	}
	if _, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "tractor", r.ActorID, 1, 10*time.Minute, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatalf("template accepted enrollment: %v", err)
	}
	ids := map[string]string{}
	for _, name := range []string{"tractor-042", "tractor-043"} {
		current, err = d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, name, "tractor", r.ActorID, current.Revision, false, now)
		if err != nil {
			t.Fatal(err)
		}
		for _, service := range current.Services {
			if service.PublisherGroup == name && service.Service == "diagnostics" {
				ids[name] = service.ServiceID
			}
		}
	}
	if len(ids) != 2 || ids["tractor-042"] == ids["tractor-043"] || len(current.Services) != 4 {
		t.Fatalf("groups shared resources: %+v", current)
	}
	revision := current.Revision
	current, err = d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-042", "tractor", r.ActorID, revision, false, now)
	if err != nil || current.Revision != revision {
		t.Fatalf("create was not idempotent: %d %v", current.Revision, err)
	}
	if _, err := d.RenamePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-042", "renamed", r.ActorID, current.Revision, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatalf("derived selector rename was accepted: %v", err)
	}
	if _, err := d.RenamePublisherNamespace(ctx, RenamePublisherNamespaceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, Group: "tractor-042", NamespaceLabel: "renamed", ActorID: r.ActorID, ExpectedRevision: current.Revision, IdempotencyKey: "rename", Now: now}); !errors.Is(err, ErrProjectManaged) {
		t.Fatalf("derived namespace rename was accepted: %v", err)
	}
	enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, "tractor-042", r.ActorID, 1, 10*time.Minute, now)
	if err != nil {
		t.Fatal(err)
	}
	member := enrollAppliedGroup(t, d, r, enrollment, now)
	if len(member.assignments.Services) != 2 {
		t.Fatalf("wrong assignments: %+v", member.assignments)
	}
	for _, service := range member.assignments.Services {
		if service.Service != "diagnostics" && service.Service != "shell" || service.Configuration.PublisherGroup != "tractor-042" {
			t.Fatalf("internal binding leaked: %+v", service)
		}
	}
	for name, id := range ids {
		service, err := d.GetProjectService(ctx, GetProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, PublisherGroup: name, Service: "diagnostics", IdentityID: r.ActorID, Now: now})
		if err != nil || service.ID != id {
			t.Fatalf("group lookup %s: %+v %v", name, service, err)
		}
	}
	if _, err := d.GetProjectService(ctx, GetProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "diagnostics", IdentityID: r.ActorID, Now: now}); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("unscoped lookup guessed a tractor: %v", err)
	}
	// one apply changes every group without replacing their retained services.
	r.ExpectedRevision = current.Revision
	s := r.Configuration.Services["diagnostics"]
	s.Target = "http://localhost:9090"
	r.Configuration.Services["diagnostics"] = s
	current, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range current.Services {
		if service.Service == "diagnostics" && service.ServiceID != ids[service.PublisherGroup] {
			t.Fatal("apply replaced a retained service", service)
		}
	}
	assignments, err := d.GetPublisherGroupAssignments(ctx, member.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range assignments.Services {
		if service.Service == "diagnostics" && service.Configuration.Target != "localhost:9090" {
			t.Fatalf("publisher did not receive rollout: %+v", service)
		}
	}
	// omitting the concrete groups from Git never removes them. removing their
	// source definition is blocked before any resources can be retired.
	r.ExpectedRevision = current.Revision
	r.Configuration = ProjectConfiguration{}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrPublisherTemplateInUse) {
		t.Fatalf("removed an in-use template: %v", err)
	}
	current, err = d.RemovePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-042", r.ActorID, current.Revision, false, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Groups) != 1 || len(current.Services) != 2 {
		t.Fatalf("remove changed another tractor: %+v", current)
	}
	if _, err := d.GetPublisherGroupAssignments(ctx, member.lease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatalf("removed equipment kept publisher authority: %v", err)
	}
	if _, err := d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-042", "tractor", r.ActorID, current.Revision, false, now); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("retired name was reused: %v", err)
	}
	current, err = d.RemovePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-043", r.ActorID, current.Revision, false, now)
	if err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = current.Revision
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal("could not remove unused template", err)
	}
}

func TestIntegrationPublisherGroupTemplateAtomicAllocation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "template_ports")
	ctx := t.Context()
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25444}}); err != nil {
		t.Fatal(err)
	}
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"tractor": {Template: true}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "tractor", Target: "localhost:9080"}}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tractor-a", "tractor-b"} {
		current, err = d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, name, "tractor", r.ActorID, current.Revision, false, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-c", "tractor", r.ActorID, current.Revision, false, now); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("creation did not reject exhaustion", err)
	}
	r.ExpectedRevision = current.Revision
	r.Configuration.Services["shell"] = ProjectServiceConfiguration{PublisherGroup: "tractor", Protocol: "tcp", Target: "localhost:22"}
	if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("fleet update did not reject exhaustion", err)
	}
	after, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || after.Revision != current.Revision || len(after.Groups) != 2 || len(after.Services) != 2 {
		t.Fatal("exhaustion partially committed", after, err)
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25446}}); err != nil {
		t.Fatal(err)
	}
	after, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil || len(after.Services) != 4 {
		t.Fatal("fleet addition did not reconcile all groups", after, err)
	}
	r.ExpectedRevision = after.Revision
	delete(r.Configuration.Services, "shell")
	after, err = d.ApplyProjectConfiguration(ctx, r)
	if err != nil || len(after.Services) != 2 {
		t.Fatal("fleet removal did not reconcile all groups", after, err)
	}
}

func TestIntegrationPublisherGroupConnectionDirectDeclaration(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "direct_group_scope")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	current, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	group := current.Groups[0].ID
	request, key := workloadExchange(t, r, now)
	request.Services = []string{publisherGroupServiceKey(group, "api")}
	signWorkloadRequest(&request, key)
	session, err := d.ExchangeWorkload(t.Context(), request, now)
	if err != nil || len(session.ServiceIDs) != 1 || session.ServiceIDs[0] != current.Services[0].ServiceID {
		t.Fatal("declared group scope did not resolve exactly", session, err)
	}
	request.Services = []string{publisherGroupServiceKey("pgrp_aaaaaaaaaaaaaaaaaaaaaa", "api")}
	signWorkloadRequest(&request, key)
	if _, err := d.ExchangeWorkload(t.Context(), request, now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatal("unknown group fell back to an unscoped service", err)
	}
	if _, err := d.RemovePublisherGroup(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, current.Revision, false, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("imperative removal retired a Git-owned group", err)
	}
}

func TestIntegrationPublisherGroupTemplateWorkloadIsolation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "template_workloads")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = workloadConfiguration()
	r.Configuration.PublisherGroups["production"] = ProjectPublisherGroup{Template: true}
	ctx := t.Context()
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tractor-a", "tractor-b"} {
		current, err = d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, name, "production", r.ActorID, current.Revision, false, now)
		if err != nil {
			t.Fatal(err)
		}
	}
	groups := map[string]string{}
	services := map[string]string{}
	for _, group := range current.Groups {
		groups[group.Name] = group.ID
	}
	for _, service := range current.Services {
		if service.Service == "api" {
			services[service.PublisherGroup] = service.ServiceID
		}
	}
	request, key := workloadExchange(t, r, now)
	if _, err := d.ExchangeWorkload(ctx, request, now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatalf("unscoped policy selected a tractor: %v", err)
	}
	request.Services = []string{publisherGroupServiceKey(groups["tractor-a"], "api")}
	signWorkloadRequest(&request, key)
	first, err := d.ExchangeWorkload(ctx, request, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.ServiceIDs) != 1 || first.ServiceIDs[0] != services["tractor-a"] {
		t.Fatalf("wrong service snapshot: %+v", first)
	}
	inventory, err := d.ListWorkloadServices(ctx, first.Credential, now)
	if err != nil || len(inventory) != 1 || inventory[0].Service != "api" {
		t.Fatalf("internal service binding leaked to the SDK: %+v %v", inventory, err)
	}
	if _, err := d.CheckWorkloadService(ctx, first.Credential, services["tractor-b"], now); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("tractor A could visit B: %v", err)
	}
	// the signed service scope cannot be edited to take over another tractor.
	request.Services = []string{publisherGroupServiceKey(groups["tractor-b"], "api")}
	if _, err := d.ExchangeWorkload(ctx, request, now); !errors.Is(err, ErrWorkloadDenied) {
		t.Fatalf("unsigned scope change accepted: %v", err)
	}
	signWorkloadRequest(&request, key)
	if _, err := d.ExchangeWorkload(ctx, request, now); !errors.Is(err, ErrWorkloadConflict) {
		t.Fatalf("existing execution widened its scope: %v", err)
	}
	current, err = d.CreatePublisherGroup(ctx, r.TeamID, r.ProjectKey, "tractor-c", "production", r.ActorID, current.Revision, false, now)
	if err != nil {
		t.Fatal(err)
	}
	after, err := d.RenewWorkloadSession(ctx, first.ID, first.Credential, signWorkloadRenewal(first, key), now.Add(31*time.Second))
	if err != nil || len(after.ServiceIDs) != 1 || after.ServiceIDs[0] != first.ServiceIDs[0] {
		t.Fatalf("new group widened existing authority: %+v %v", after, err)
	}
	r.ExpectedRevision = current.Revision
	policy := r.Configuration.Workloads["test"]
	policy.Services = []string{"db"}
	r.Configuration.Workloads["test"] = policy
	if _, err := d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := d.CheckWorkloadService(ctx, first.Credential, services["tractor-a"], now.Add(32*time.Second)); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("narrowed template policy retained access: %v", err)
	}
}
