package state

import (
	"errors"
	"testing"
	"time"
)

func TestIntegrationPublisherGroupProtocolChangesRequireExplicitBindings(t *testing.T) {
	for _, protocol := range []string{"tcp", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "bound_protocol_"+protocol)
			ctx := t.Context()
			r := appliedProjectRequest(t, d, now)
			r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}, "other": {Template: true}}, Services: map[string]ProjectServiceConfiguration{
				"api":       {PublisherGroup: "customer", Protocol: "http", TargetBinding: "group"},
				"other-api": {PublisherGroup: "other", Protocol: "http", TargetBinding: "group"},
			}}
			current, err := d.ApplyProjectConfiguration(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			groups := []PublisherGroupResource{}
			members := []enrolledGroupReplica{}
			for _, name := range []string{"customer-a", "customer-b", "other-c"} {
				template, service := "customer", "api"
				if name == "other-c" {
					template, service = "other", "other-api"
				}
				group, err := d.CreateBoundPublisherGroup(ctx, CreateBoundPublisherGroupRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ExpectedRevision: current.Revision, Now: now, Creation: PublisherGroupCreation{Name: name, Template: template, Bindings: PublisherGroupBindings{service: {Target: "equipment.internal:5432"}}}})
				if err != nil {
					t.Fatal(err)
				}
				current.Revision = group.Revision
				groups = append(groups, group)
				enrollment, err := d.IssuePublisherGroupEnrollment(ctx, r.TeamID, r.ProjectKey, group.ID, r.ActorID, 1, time.Hour, now)
				if err != nil {
					t.Fatal(err)
				}
				members = append(members, enrollAppliedGroup(t, d, r, enrollment, now))
			}
			r.ExpectedRevision = current.Revision
			api := r.Configuration.Services["api"]
			api.Protocol = protocol
			r.Configuration.Services["api"] = api
			if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("template silently reinterpreted retained bindings", err)
			}
			r.GroupBindings = map[string]PublisherGroupBindings{groups[0].ID: {"api": {Target: "equipment.internal:5432"}}}
			if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectConfigurationInvalid) {
				t.Fatal("partial customer approval was accepted", err)
			}
			after, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
			if err != nil || after.Revision != current.Revision || after.Configuration.Services["api"].Protocol != "http" {
				t.Fatal("rejected approval partially saved", after, err)
			}
			r.GroupBindings[groups[1].ID] = PublisherGroupBindings{"api": {Target: "equipment.internal:5432"}}
			r.ExpectedRevision = current.Revision - 1
			if _, err := d.ApplyProjectConfiguration(ctx, r); !errors.Is(err, ErrProjectConfigurationStale) {
				t.Fatal("stale protocol approval committed", err)
			}
			r.ExpectedRevision = current.Revision
			after, err = d.ApplyProjectConfiguration(ctx, r)
			if err != nil {
				t.Fatal(err)
			}
			for i, before := range groups {
				resource, err := publisherGroupResource(after, before.ID)
				if err != nil || resource.ID != before.ID || resource.Services[0].ServiceID != before.Services[0].ServiceID || resource.Services[0].Hostname != before.Services[0].Hostname || resource.Services[0].Port != before.Services[0].Port {
					t.Fatal("protocol approval changed endpoint identity", resource, err)
				}
				wantProtocol, service := protocol, "api"
				if i == 2 {
					wantProtocol, service = "http", "other-api"
				}
				if resource.Bindings[service].protocol != wantProtocol {
					t.Fatal("wrong saved protocol pin", resource.Bindings)
				}
				assignments, err := d.GetPublisherGroupAssignments(ctx, members[i].lease.AccessToken, now)
				if err != nil || len(assignments.Services) != 1 || assignments.Services[0].Configuration.Protocol != wantProtocol || assignments.Services[0].Configuration.Target != "equipment.internal:5432" {
					t.Fatal("approval crossed exact group scope", assignments, err)
				}
				if i < 2 && assignments.Services[0].GrantID == members[i].assignments.Services[0].GrantID {
					t.Fatal("protocol approval retained old publisher authority")
				}
			}
		})
	}
}
