package state

import (
	"errors"
	"reflect"
	"testing"
)

func TestIntegrationPublisherGroupProtocolChangesRequireExplicitBindings(t *testing.T) {
	for _, protocol := range []string{"tcp", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "bound_protocol_"+protocol)
			ctx := t.Context()
			r := retainedEnvironmentProject(t, d, now)
			definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: "http"}})
			var environments []Environment
			var members []environmentPublisherReplica
			for _, name := range []string{"customer-a", "customer-b", "other-c"} {
				e, _ := createTestEnvironment(t, d, r, name, definition.Revision, EnvironmentTargets{"api": {Address: "equipment.internal:5432"}})
				environments = append(environments, e)
				members = append(members, enrollTestEnvironment(t, d, r, e))
			}
			next := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"api": {Protocol: protocol}})
			request := ApplyEnvironmentsRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, Now: now}
			for _, e := range environments[:2] {
				request.Items = append(request.Items, EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: next.Revision})
			}
			before := privateOwnershipSnapshot(t, d)
			if _, err := d.ApplyEnvironments(ctx, request); !errors.Is(err, ErrEnvironmentInvalid) {
				t.Fatal("definition silently reinterpreted retained targets", err)
			}
			request.Items[0].Targets = EnvironmentTargets{"api": {Address: "equipment.internal:5432"}}
			if _, err := d.ApplyEnvironments(ctx, request); !errors.Is(err, ErrEnvironmentInvalid) {
				t.Fatal("partial target approval accepted", err)
			}
			if !reflect.DeepEqual(before, privateOwnershipSnapshot(t, d)) {
				t.Fatal("rejected approval partially committed")
			}
			request.Items[1].Targets = EnvironmentTargets{"api": {Address: "equipment.internal:5432"}}
			request.Items[1].ExpectedRevision = environments[1].MutationRevision + 1
			if _, err := d.ApplyEnvironments(ctx, request); !errors.Is(err, ErrEnvironmentStale) {
				t.Fatal("stale protocol approval committed", err)
			}
			request.Items[1].ExpectedRevision = environments[1].MutationRevision
			if _, err := d.ApplyEnvironments(ctx, request); err != nil {
				t.Fatal(err)
			}
			for i, old := range environments {
				current, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, old.ID, r.ActorID)
				if err != nil || current.ID != old.ID || current.Services[0].ServiceID != old.Services[0].ServiceID || current.Services[0].Hostname != old.Services[0].Hostname || current.Services[0].Port != old.Services[0].Port {
					t.Fatal("protocol approval replaced endpoint", err)
				}
				want := "http"
				if i < 2 {
					want = protocol
				}
				if current.Services[0].Protocol != want {
					t.Fatal("wrong saved protocol pin")
				}
				assignments, err := d.GetEnvironmentPublisherAssignments(ctx, members[i].lease.AccessToken, now)
				if err != nil || len(assignments.Services) != 1 || assignments.Services[0].Configuration.Protocol != want || assignments.Services[0].Configuration.Target != "equipment.internal:5432" {
					t.Fatal("approval crossed exact environment", err)
				}
				if assignments.Services[0].GrantID != members[i].assignments.Services[0].GrantID {
					t.Fatal("apply unexpectedly changed grant authority")
				}
				if i < 2 {
					a := assignments.Services[0]
					mutation := retainedPublisherGrantMutation(t, d, r, current, members[i].member.PublisherIdentityID, a.ServiceID)
					if err := d.RevokeEnvironmentPublisherGrant(ctx, RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: mutation, GrantID: a.GrantID}); err != nil {
						t.Fatal(err)
					}
					if _, err := d.AuthorizeEnvironmentPublisherService(ctx, AuthorizeEnvironmentPublisherServiceRequest{EnvironmentPublisherGrantMutation: mutation, ExpectedPreviousGrantID: environmentPublisherGrantExpected(t, a.GrantID), IdempotencyKey: "protocol-replacement"}); err != nil {
						t.Fatal(err)
					}
					rotated, err := d.GetEnvironmentPublisherAssignments(ctx, members[i].lease.AccessToken, now)
					if err != nil || rotated.Services[0].GrantID == a.GrantID {
						t.Fatal("explicit rotation retained old authority", err)
					}
				}
			}
		})
	}
}
