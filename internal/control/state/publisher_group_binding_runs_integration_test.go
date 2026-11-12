package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationPublisherGroupBindingChangesInvalidateRuns(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"db": {Protocol: "postgres"}})
	groups := []Environment{}
	members := []environmentPublisherReplica{}
	for _, name := range []string{"customer-a", "customer-b"} {
		group, _ := createTestEnvironment(t, d, r, name, definition.Revision, EnvironmentTargets{"db": {Address: name + ".internal:5432"}})
		groups = append(groups, group)
		members = append(members, enrollTestEnvironment(t, d, r, group))
	}
	type publication struct {
		assignment EnvironmentPublisherAssignment
		access     PublisherAccess
		run        ServiceRunState
	}
	start := func(t *testing.T, member environmentPublisherReplica) publication {
		t.Helper()
		assignments, err := d.GetEnvironmentPublisherAssignments(ctx, member.lease.AccessToken, now)
		if err != nil || len(assignments.Services) != 1 {
			t.Fatal("get assigned publication", assignments, err)
		}
		assignment := assignments.Services[0]
		access := environmentAssignmentAccess(t, d, member, assignment, now)
		trust, err := appliedServiceTargetTrust(assignment.Configuration.TargetTLS)
		if err != nil {
			t.Fatal(err)
		}
		metadata := ServiceMetadata{Protocol: assignment.Configuration.Protocol, TLS: trust, PublisherPool: true, TrustRevision: assignment.TrustRevision}
		prepared, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "binding-regression/"+assignment.GrantID, now, metadata, &assignments.Environment)
		if err != nil {
			t.Fatal(err)
		}
		run, err := d.StartServiceRun(ctx, assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
		if err != nil {
			t.Fatal(err)
		}
		installPrivateTestCertificate(t, d, prepared, run, now)
		for _, slot := range run.Connections {
			lease := leases[slot.RelayServiceID].RelayLeaseIdentity
			if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, assignment.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
				t.Fatal(err)
			}
			if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
				t.Fatal(err)
			}
		}
		if state, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
			t.Fatal("publication not ready", state, err)
		}
		return publication{assignment: assignment, access: access, run: run}
	}
	first, other := start(t, members[0]), start(t, members[1])
	for _, change := range []string{"target", "target TLS"} {
		t.Run(change, func(t *testing.T) {
			previousMutation := retainedPublisherGrantMutation(t, d, r, groups[0], members[0].member.PublisherIdentityID, first.assignment.ServiceID)
			previousGrant, err := d.GetEnvironmentPublisherGrant(ctx, previousMutation.InspectEnvironmentPublisherGrantRequest)
			if err != nil || previousGrant.Grant == nil || previousGrant.Grant.ID != first.assignment.GrantID || previousGrant.Grant.RevokedAt != nil {
				t.Fatal("missing current exact grant before apply", err)
			}
			bindings := EnvironmentTargets{"db": {Address: "replacement.internal:5432"}}
			if change == "target TLS" {
				digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00replacement.internal\x00"))
				binding := bindings["db"]
				binding.TLS = &ProjectTargetTLS{Hostname: "replacement.internal", Digest: hex.EncodeToString(digest[:])}
				bindings["db"] = binding
			}
			updated, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: groups[0].ID, ExpectedRevision: groups[0].MutationRevision, DefinitionRevision: definition.Revision, Targets: bindings}, Now: now})
			if err != nil {
				t.Fatal(err)
			}
			if updated.Services[0].ServiceID != groups[0].Services[0].ServiceID || updated.Services[0].Hostname != groups[0].Services[0].Hostname || updated.Services[0].Port != groups[0].Services[0].Port {
				t.Fatal("mutation replaced reserved endpoint", updated)
			}
			groups[0] = updated
			// apply must close the changed publication before any grant mutation
			// can mask missing cleanup, while preserving its existing authority.
			var closedByApply bool
			if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, first.run.RunID).Scan(&closedByApply); err != nil || !closedByApply {
				t.Fatal("apply did not durably close the changed run", closedByApply, err)
			}
			if _, err := d.HeartbeatServiceRun(ctx, first.run.ServiceID, first.run.RunID, first.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("old run survived apply before grant revocation", err)
			}
			if state, err := d.HeartbeatServiceRun(ctx, other.run.ServiceID, other.run.RunID, other.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
				t.Fatal("apply disturbed the other customer before grant revocation", state, err)
			}
			preservedGrant, err := d.GetEnvironmentPublisherGrant(ctx, previousMutation.InspectEnvironmentPublisherGrantRequest)
			if err != nil || !reflect.DeepEqual(preservedGrant.Grant, previousGrant.Grant) {
				t.Fatal("apply changed the existing exact grant", err)
			}
			// publication changes do not rotate authority. revoke and replace the
			// exact grant separately before asserting old token/proof retirement.
			mutation := retainedPublisherGrantMutation(t, d, r, updated, members[0].member.PublisherIdentityID, first.assignment.ServiceID)
			if err := d.RevokeEnvironmentPublisherGrant(ctx, RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: mutation, GrantID: first.assignment.GrantID}); err != nil {
				t.Fatal(err)
			}
			if _, err := d.AuthorizeEnvironmentPublisherService(ctx, AuthorizeEnvironmentPublisherServiceRequest{EnvironmentPublisherGrantMutation: mutation, ExpectedPreviousGrantID: environmentPublisherGrantExpected(t, first.assignment.GrantID), IdempotencyKey: "replacement/" + change}); err != nil {
				t.Fatal(err)
			}
			if _, err := d.HeartbeatServiceRun(ctx, first.run.ServiceID, first.run.RunID, first.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("old run survived explicit grant revocation", err)
			}
			if _, err := d.AuthenticatePublisherAccess(ctx, first.access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("old access survived explicit grant revocation", err)
			}
			assertion, err := publisherproof.Sign(members[0].member.PublisherIdentityID, members[0].member.KeyID, first.assignment.GrantID, publisherTestAudience, members[0].private, now)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := d.ExchangePublisherAssertion(ctx, first.access.PublisherIdentity.ID, first.assignment.GrantID, publisherTestAudience, assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("old exact grant remained exchangeable", err)
			}
			var closed bool
			if err := d.pool.QueryRow(ctx, `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, first.run.RunID).Scan(&closed); err != nil || !closed {
				t.Fatal("run not durably closed", closed, err)
			}
			if state, err := d.HeartbeatServiceRun(ctx, other.run.ServiceID, other.run.RunID, other.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
				t.Fatal("mutation disturbed other customer", state, err)
			}
			replacement := start(t, members[0])
			if replacement.assignment.GrantID == first.assignment.GrantID || replacement.run.RunID == first.run.RunID || replacement.assignment.Configuration.Target != "replacement.internal:5432" {
				t.Fatal("replacement retained old authority")
			}
			if change == "target TLS" && (replacement.assignment.TrustRevision <= first.assignment.TrustRevision || replacement.assignment.Configuration.TargetTLS == nil) {
				t.Fatal("target trust did not advance", replacement.assignment)
			}
			first = replacement
		})
	}
	if err := d.RetireEnvironment(ctx, RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: groups[0].ID, ExpectedRevision: groups[0].MutationRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, first.run.ServiceID, first.run.RunID, first.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retired group kept active run", err)
	}
	if state, err := d.HeartbeatServiceRun(ctx, other.run.ServiceID, other.run.RunID, other.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("retirement disturbed other customer", state, err)
	}
}
