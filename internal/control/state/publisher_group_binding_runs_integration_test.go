package state

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationPublisherGroupBindingChangesInvalidateRuns(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}}, Services: map[string]ProjectServiceConfiguration{"db": {PublisherGroup: "customer", Protocol: "postgres", TargetBinding: "group"}}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	groups := []PublisherGroupResource{}
	members := []enrolledGroupReplica{}
	for _, name := range []string{"customer-a", "customer-b"} {
		group, err := d.CreateBoundPublisherGroup(ctx, CreateBoundPublisherGroupRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ExpectedRevision: current.Revision, Now: now, Creation: PublisherGroupCreation{Name: name, Template: "customer", Bindings: PublisherGroupBindings{"db": {Target: name + ".internal:5432"}}}})
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
	type publication struct {
		assignment PublisherGroupServiceAssignment
		access     PublisherAccess
		run        ServiceRunState
	}
	start := func(t *testing.T, member enrolledGroupReplica) publication {
		t.Helper()
		assignments, err := d.GetPublisherGroupAssignments(ctx, member.lease.AccessToken, now)
		if err != nil || len(assignments.Services) != 1 {
			t.Fatal("get assigned publication", assignments, err)
		}
		assignment := assignments.Services[0]
		access := groupAssignmentAccess(t, d, member, assignment, now)
		trust, err := appliedServiceTargetTrust(assignment.Configuration.TargetTLS)
		if err != nil {
			t.Fatal(err)
		}
		metadata := ServiceMetadata{Protocol: assignment.Configuration.Protocol, TLS: trust, PublisherPool: true, TrustRevision: assignment.TrustRevision}
		prepared, err := d.PrepareServiceRun(ctx, assignment.ServiceID, access.PublisherIdentity, "binding-regression/"+assignment.GrantID, now, metadata)
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
			bindings := PublisherGroupBindings{"db": {Target: "replacement.internal:5432"}}
			if change == "target TLS" {
				digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00replacement.internal\x00"))
				binding := bindings["db"]
				binding.TargetTLS = &ProjectTargetTLS{Hostname: "replacement.internal", Digest: hex.EncodeToString(digest[:])}
				bindings["db"] = binding
			}
			updated, err := d.UpdatePublisherGroupBindings(ctx, r.TeamID, r.ProjectKey, groups[0].ID, r.ActorID, current.Revision, bindings, false, now)
			if err != nil {
				t.Fatal(err)
			}
			current.Revision = updated.Revision
			if updated.Services[0].ServiceID != groups[0].Services[0].ServiceID || updated.Services[0].Hostname != groups[0].Services[0].Hostname || updated.Services[0].Port != groups[0].Services[0].Port {
				t.Fatal("mutation replaced reserved endpoint", updated)
			}
			if _, err := d.HeartbeatServiceRun(ctx, first.run.ServiceID, first.run.RunID, first.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("old run survived binding mutation", err)
			}
			if _, err := d.AuthenticatePublisherAccess(ctx, first.access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("old access survived binding mutation", err)
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
	if _, err := d.RemovePublisherGroup(ctx, r.TeamID, r.ProjectKey, groups[0].ID, r.ActorID, current.Revision, false, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.HeartbeatServiceRun(ctx, first.run.ServiceID, first.run.RunID, first.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("retired group kept active run", err)
	}
	if state, err := d.HeartbeatServiceRun(ctx, other.run.ServiceID, other.run.RunID, other.run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("retirement disturbed other customer", state, err)
	}
}
