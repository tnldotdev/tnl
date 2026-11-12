package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
)

func TestIntegrationAppliedProjectConcurrencyRollbackAndSource(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_concurrency")
	r := retainedEnvironmentProject(t, d, now)
	definition := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"web": {Protocol: "http"}})
	request := CreateEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, ActorID: r.ActorID, Name: "production", DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"web": {Address: "localhost:3000"}}, IdempotencyKey: "concurrent", Now: now}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type outcome struct {
		value Environment
		err   error
	}
	done := make(chan outcome, 8)
	for range 8 {
		workers.Go(func() { value, err := d.CreateEnvironment(ctx, request); done <- outcome{value, err} })
	}
	var original Environment
	for range 8 {
		v := awaitIntegrationResult(t, ctx, done)
		if v.err != nil || v.value.MutationRevision != 1 || len(v.value.Services) != 1 {
			t.Fatal("concurrent retry", v.err)
		}
		if original.ID != "" && original.Services[0].ServiceID != v.value.Services[0].ServiceID {
			t.Fatal("retry created another resource")
		}
		original = v.value
	}
	if original.Services[0].Public {
		t.Fatal("HTTP service became a public endpoint")
	}
	if _, err := d.GetPublicURL(ctx, r.ActorID, original.Services[0].ServiceID); err == nil {
		t.Fatal("HTTP service became a public URL")
	}
	for index := range 2 {
		workers.Go(func() {
			value, err := d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: original.ID, ExpectedRevision: 1, DefinitionRevision: definition.Revision, Targets: EnvironmentTargets{"web": {Address: fmt.Sprintf("localhost:%d", 4000+index)}}}, Now: now})
			done <- outcome{value, err}
		})
	}
	winners, conflicts := 0, 0
	for range 2 {
		v := awaitIntegrationResult(t, ctx, done)
		if v.err == nil {
			winners++
		} else if errors.Is(v.err, ErrEnvironmentStale) {
			conflicts++
		} else {
			t.Fatal(v.err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal("optimistic concurrency", winners, conflicts)
	}
	current, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, original.ID, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	other := request
	other.SourceFingerprint = strings.Repeat("b", 64)
	if _, err := d.CreateEnvironment(ctx, other); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("source collision", err)
	}
	// logical services cannot carry a second saved-name authority. allocation
	// failures still exercise transaction rollback after partial materialization.
	if _, err := decodeServiceDefinition([]byte(`{"services":{"web":{"protocol":"http","name":"duplicate"}}}`), definition.ConfigurationHash); !errors.Is(err, ErrServiceDefinitionInvalid) {
		t.Fatal("second name authority", err)
	}
	if err := d.ConfigureIngressServicePorts(ctx, PrimaryIngressPoolID, []tcpport.Range{{First: current.Services[0].Port, Last: current.Services[0].Port}}); err != nil {
		t.Fatal(err)
	}
	grown := environmentDefinition(t, d, r, map[string]ServiceDefinitionService{"web": {Protocol: "http"}, "a-new": {Protocol: "http"}, "z-conflict": {Protocol: "http"}})
	_, err = d.ApplyEnvironment(ctx, ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: current.ID, ExpectedRevision: current.MutationRevision, DefinitionRevision: grown.Revision, Targets: EnvironmentTargets{"web": {Address: "localhost:3000"}, "a-new": {Address: "localhost:7000"}, "z-conflict": {Address: "localhost:8000"}}}, Now: now})
	if !errors.Is(err, ErrServicePortsExhausted) {
		t.Fatal("atomic allocation failure", err)
	}
	after, err := d.GetEnvironment(ctx, r.TeamID, r.ProjectKey, current.ID, r.ActorID)
	if err != nil || !reflect.DeepEqual(after, current) {
		t.Fatal("failed apply committed state", err)
	}
	var count int
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1 AND deleted_at IS NULL`, r.TeamID).Scan(&count); err != nil || count != 1 {
		t.Fatal("failed apply leaked services", count, err)
	}
	var sealed []byte
	if err := d.pool.QueryRow(ctx, `SELECT bindings_ciphertext FROM control.publisher_group_bindings WHERE group_id=(SELECT group_id FROM control.environments WHERE id=$1)`, current.ID).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("localhost")) {
		t.Fatal("target not encrypted", err)
	}
	local, err := normalizeLocalService("preview", LocalServiceDeclaration{Target: "http://localhost:9000", PublicURL: &ProjectServicePublicURL{}})
	if err != nil || local.PublicURL == nil {
		t.Fatal("local URL intent lost", err)
	}
	if err := d.pool.QueryRow(ctx, `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&count); err != nil || count != 0 {
		t.Fatal("declaration allocated shared URL", err)
	}
}

func TestIntegrationAppliedProjectGroupAssignmentsRunsAndRevocation(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	r := retainedEnvironmentProject(t, d, now)
	status, _ := retainedServiceEnvironment(t, d, r, "production", map[string]EnvironmentServicePublication{"web": {Protocol: "http", Target: "app.internal:3000", HTTP: &EnvironmentServiceHTTP{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}}}, "db": {Protocol: "postgres", Target: "db.internal:5432"}})
	staging, _ := retainedServiceEnvironment(t, d, r, "staging", map[string]EnvironmentServicePublication{"stage": {Protocol: "http", Target: "staging.internal:3000"}})
	enrollment := retainedPublisherEnrollment(t, d, r, status, 2)
	a, b := retainedPublisherReplica(t, d, enrollment, now), retainedPublisherReplica(t, d, enrollment, now)
	if a.member.PublisherIdentityID == b.member.PublisherIdentityID || a.member.KeyID == b.member.KeyID || bytes.Equal(a.private, b.private) {
		t.Fatal("replicas share signing identity")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := d.RedeemEnvironmentPublisherEnrollment(t.Context(), enrollment.Key, public, now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("unbounded enrollment", err)
	}
	stage := enrollTestEnvironment(t, d, r, staging)
	if len(stage.assignments.Services) != 1 || stage.assignments.Services[0].Service != "stage" || len(a.assignments.Services) != 2 || len(b.assignments.Services) != 2 {
		t.Fatal("assignment scope leaked")
	}
	stageAccess := environmentAssignmentAccess(t, d, stage, stage.assignments.Services[0], now)
	stageService, err := d.GetServiceForPublisher(t.Context(), stage.assignments.Services[0].ServiceID, stageAccess.PublisherIdentity, now)
	if err != nil {
		t.Fatal(err)
	}
	stageRun := readyAppliedServiceRun(t, d, stageAccess, stage.private, stageService, leases, now, &stage.assignments.Environment)
	if _, err := d.RedeemEnvironmentPublisherEnrollment(t.Context(), stage.enrollment.Key, a.private.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("key enrolled in two environments", err)
	}
	var accesses []PublisherAccess
	var runs []ServiceRunState
	for _, replica := range []environmentPublisherReplica{a, b} {
		for _, assignment := range replica.assignments.Services {
			access := environmentAssignmentAccess(t, d, replica, assignment, now)
			accesses = append(accesses, access)
			prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "replica", now, ServiceMetadata{Protocol: assignment.Configuration.Protocol, PublisherPool: true, TrustRevision: assignment.TrustRevision}, &replica.assignments.Environment)
			if err != nil {
				t.Fatal(err)
			}
			run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
			if err != nil {
				t.Fatal(err)
			}
			runs = append(runs, run)
			installPrivateTestCertificate(t, d, prepared, run, now)
			for _, slot := range run.Connections {
				lease := leases[slot.RelayServiceID].RelayLeaseIdentity
				if _, err := d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
					t.Fatal(err)
				}
				if _, err := d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
					t.Fatal(err)
				}
			}
			if state, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
				t.Fatal("run not ready", err)
			}
		}
		if err := d.AcknowledgeEnvironmentPublisher(t.Context(), replica.lease.AccessToken, replica.assignments.Environment, true, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(runs) != 4 || runs[0].RunID == runs[2].RunID || runs[0].Connections[0].PublisherConnectionID == runs[2].Connections[0].PublisherConnectionID {
		t.Fatal("replicas shared run/connection identity")
	}
	observed, err := d.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, status.ID, r.ActorID)
	if err != nil || len(observed.Members) != 2 || observed.Members[0].ObservedRevision != 1 {
		t.Fatal("ack not observed", err)
	}
	if err := d.RevokeEnvironmentPublisher(t.Context(), environmentPublisherSelection(t, d, r, staging), a.member.PublisherIdentityID, now); !errors.Is(err, ErrEnvironmentNotFound) {
		t.Fatal("revoke crossed environment", err)
	}
	if err := d.RevokeEnvironmentPublisher(t.Context(), environmentPublisherSelection(t, d, r, status), a.member.PublisherIdentityID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetEnvironmentPublisherAssignments(t.Context(), a.lease.AccessToken, now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("revoked lease survived", err)
	}
	for i, run := range runs {
		state, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if i < 2 && !errors.Is(err, ErrServiceAccess) || i >= 2 && (err != nil || state.State != "ready") {
			t.Fatal("replica revoke changed wrong run", i, err)
		}
	}
	previousGrants := map[string]*EnvironmentPublisherGrant{}
	for _, assignment := range b.assignments.Services {
		mutation := retainedPublisherGrantMutation(t, d, r, status, b.member.PublisherIdentityID, assignment.ServiceID)
		state, err := d.GetEnvironmentPublisherGrant(t.Context(), mutation.InspectEnvironmentPublisherGrantRequest)
		if err != nil || state.Grant == nil || state.Grant.ID != assignment.GrantID || state.Grant.RevokedAt != nil {
			t.Fatal("missing exact grant before trust apply", err)
		}
		previousGrants[assignment.ServiceID] = state.Grant
	}
	// the ready staging run has already added its certificate checkpoint. take
	// the complete assignment snapshot after setup and before the actual apply.
	stageBeforeApply, err := d.GetEnvironmentPublisherAssignments(t.Context(), stage.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	targets := status.Targets
	db := targets["db"]
	db.TLS = appliedTargetTrust(t, "database.internal")
	targets["db"] = db
	updated, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: status.ID, ExpectedRevision: status.MutationRevision, DefinitionRevision: status.AppliedDefinitionRevision, Targets: targets}, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	// inspect durable closure before heartbeat or explicit grant revocation can
	// hide an apply cleanup failure. only this replica's changed db run closes.
	for i, run := range runs {
		if i < 2 {
			continue
		}
		changed := run.ServiceID == runs[0].ServiceID
		var closed bool
		if err := d.pool.QueryRow(t.Context(), `SELECT closed_at IS NOT NULL FROM control.service_runs WHERE id=$1`, run.RunID).Scan(&closed); err != nil || closed != changed {
			t.Fatal("trust apply closed the wrong run before grant revocation", i, closed, err)
		}
		state, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64})
		if changed && !errors.Is(err, ErrServiceAccess) || !changed && (err != nil || state.State != "ready") {
			t.Fatal("trust apply changed the wrong run before grant revocation", i, err)
		}
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), stageRun.ServiceID, stageRun.RunID, stageRun.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
		t.Fatal("trust apply disturbed staging before grant revocation", err)
	}
	if assignments, err := d.GetEnvironmentPublisherAssignments(t.Context(), stage.lease.AccessToken, now); err != nil || !reflect.DeepEqual(assignments, stageBeforeApply) {
		t.Fatal("trust apply changed staging assignments", err)
	}
	if err := d.AcknowledgeEnvironmentPublisher(t.Context(), b.lease.AccessToken, b.assignments.Environment, true, now); !errors.Is(err, ErrEnvironmentStale) {
		t.Fatal("stale ack accepted", err)
	}
	current, err := d.GetEnvironmentPublisherAssignments(t.Context(), b.lease.AccessToken, now)
	if err != nil || len(current.Services) != len(previousGrants) {
		t.Fatal(err)
	}
	for _, assignment := range current.Services {
		mutation := retainedPublisherGrantMutation(t, d, r, updated, b.member.PublisherIdentityID, assignment.ServiceID)
		state, err := d.GetEnvironmentPublisherGrant(t.Context(), mutation.InspectEnvironmentPublisherGrantRequest)
		if err != nil || !reflect.DeepEqual(state.Grant, previousGrants[assignment.ServiceID]) || state.Grant == nil || assignment.GrantID != state.Grant.ID {
			t.Fatal("trust apply rotated or changed an exact grant", err)
		}
	}
	for _, assignment := range current.Services {
		if assignment.Service != "db" {
			continue
		}
		if assignment.TrustRevision != 2 || assignment.ServiceID != runs[0].ServiceID {
			t.Fatal("trust replacement changed service identity/revision")
		}
		// apply changes publication facts, never grant authority. exact rotation is
		// a separate authorized operation and invalidates the old token immediately.
		mutation := retainedPublisherGrantMutation(t, d, r, updated, b.member.PublisherIdentityID, assignment.ServiceID)
		if err := d.RevokeEnvironmentPublisherGrant(t.Context(), RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: mutation, GrantID: assignment.GrantID}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.AuthorizeEnvironmentPublisherService(t.Context(), AuthorizeEnvironmentPublisherServiceRequest{EnvironmentPublisherGrantMutation: mutation, ExpectedPreviousGrantID: environmentPublisherGrantExpected(t, assignment.GrantID), IdempotencyKey: "rotate-db"}); err != nil {
			t.Fatal(err)
		}
	}
	for _, run := range runs {
		if run.ServiceID == runs[0].ServiceID {
			if _, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("old trust run survived", err)
			}
		}
	}
	for _, access := range accesses {
		if access.Scope.ServiceID == runs[0].ServiceID {
			if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("rotated exact grant token survived", err)
			}
		}
	}
	page, err := d.ListServiceAudit(t.Context(), r.TeamID, r.ActorID, ServiceAuditFilter{ServiceID: runs[0].ServiceID, Limit: 256}, now)
	if err != nil {
		t.Fatal(err)
	}
	joined, revoked, applied := false, false, false
	for _, event := range page.Events {
		joined = joined || event.EventType == "publisher.join" && event.PublisherIdentityID == a.member.PublisherIdentityID
		revoked = revoked || event.EventType == "publisher.revoke" && event.PublisherIdentityID == a.member.PublisherIdentityID && event.ActorIdentityID == r.ActorID
		applied = applied || event.EventType == "apply" && event.ActorIdentityID == r.ActorID && event.ConfigurationRevision == updated.MutationRevision
	}
	if !joined || !revoked || !applied {
		t.Fatal("missing enrollment/revocation/apply audit", joined, revoked, applied)
	}
	if err := d.RetireEnvironment(t.Context(), RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: updated.ID, ExpectedRevision: updated.MutationRevision, Now: now}); err != nil {
		t.Fatal(err)
	}
	for _, access := range accesses {
		if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("retirement retained grant", err)
		}
	}
	if _, err := d.GetEnvironmentPublisherAssignments(t.Context(), stage.lease.AccessToken, now); err != nil {
		t.Fatal("retirement disturbed staging", err)
	}
	if err := d.RevokePublisherIdentity(t.Context(), r.TeamID, stage.member.PublisherIdentityID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := d.GetEnvironmentPublisherAssignments(t.Context(), stage.lease.AccessToken, now); !errors.Is(err, ErrEnvironmentPublisher) {
		t.Fatal("general revoke retained lease", err)
	}
	stageAudit, err := d.ListServiceAudit(t.Context(), r.TeamID, r.ActorID, ServiceAuditFilter{ServiceID: stage.assignments.Services[0].ServiceID, Limit: 256}, now)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range stageAudit.Events {
		found = found || event.EventType == "publisher.revoke" && event.PublisherIdentityID == stage.member.PublisherIdentityID && event.ActorIdentityID == r.ActorID
	}
	if !found {
		t.Fatal("general revoke omitted audit")
	}
}

func TestIntegrationAppliedProjectGroupReassignmentKeepsSavedService(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_move")
	r := retainedEnvironmentProject(t, d, now)
	trust := appliedTargetTrust(t, "api.internal")
	e, _ := retainedServiceEnvironment(t, d, r, "production", map[string]EnvironmentServicePublication{"api": {Protocol: "http", Target: "api.internal:8443", TargetTLS: trust}, "spare": {Protocol: "tcp", Target: "spare.internal:5432"}})
	a := retainedPublisherReplica(t, d, retainedPublisherEnrollment(t, d, r, e, 1, "api"), now)
	b := retainedPublisherReplica(t, d, retainedPublisherEnrollment(t, d, r, e, 1, "spare"), now)
	assignment := a.assignments.Services[0]
	old := environmentAssignmentAccess(t, d, a, assignment, now)
	visitor, err := d.CreateServiceGrant(t.Context(), assignment.ServiceID, r.ActorID, "team-access", "team", "", nil, now)
	if err != nil {
		t.Fatal(err)
	}
	mutation := retainedPublisherGrantMutation(t, d, r, e, a.member.PublisherIdentityID, assignment.ServiceID)
	if err := d.RevokeEnvironmentPublisherGrant(t.Context(), RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: mutation, GrantID: assignment.GrantID}); err != nil {
		t.Fatal(err)
	}
	mutation.PublisherIdentityID = b.member.PublisherIdentityID
	if _, err := d.AuthorizeEnvironmentPublisherService(t.Context(), AuthorizeEnvironmentPublisherServiceRequest{EnvironmentPublisherGrantMutation: mutation, ExpectedPreviousGrantID: ExpectNoEnvironmentPublisherGrant(), IdempotencyKey: "handoff-api"}); err != nil {
		t.Fatal(err)
	}
	previous, err := d.GetEnvironmentPublisherAssignments(t.Context(), a.lease.AccessToken, now)
	if err != nil || len(previous.Services) != 0 {
		t.Fatal("old replica retained assignment", err)
	}
	current, err := d.GetEnvironmentPublisherAssignments(t.Context(), b.lease.AccessToken, now)
	if err != nil || len(current.Services) != 2 {
		t.Fatal("new replica missing scope", err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), old.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("old exact grant survived handoff", err)
	}
	for _, assigned := range current.Services {
		if assigned.Service != "api" {
			continue
		}
		if assigned.ServiceID != assignment.ServiceID {
			t.Fatal("handoff replaced saved service")
		}
		access := environmentAssignmentAccess(t, d, b, assigned, now)
		tls, err := appliedServiceTargetTrust(trust)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := d.PrepareServiceRun(t.Context(), assigned.ServiceID, access.PublisherIdentity, "tls-handoff", now, ServiceMetadata{Protocol: "http", TLS: tls, PublisherPool: true, TrustRevision: assigned.TrustRevision}, &current.Environment); err != nil {
			t.Fatal("TLS handoff not publishable", err)
		}
		if err := d.RevokeServiceGrant(t.Context(), assigned.ServiceID, r.ActorID, visitor.ID, now); err != nil {
			t.Fatal(err)
		}
		var count int
		if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.visitor_grants WHERE service_id=$1 AND kind='team' AND revoked_at IS NULL`, assigned.ServiceID).Scan(&count); err != nil || count != 0 {
			t.Fatal("visitor revoke not independent", err)
		}
		if err := d.RetireEnvironment(t.Context(), RetireEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, Now: now}); err != nil {
			t.Fatal(err)
		}
		if _, err := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("removed service retained grant", err)
		}
	}
}

func TestIntegrationAppliedProjectStorageRotation(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "applied_rotation")
	r := retainedEnvironmentProject(t, d, now)
	before, _ := retainedServiceEnvironment(t, d, r, "production", map[string]EnvironmentServicePublication{"web": {Protocol: "http", Target: "localhost:3000"}})
	key := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	rotating, err := Open(t.Context(), url, key, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer rotating.Close()
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), url, key, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.GetEnvironment(t.Context(), r.TeamID, r.ProjectKey, before.ID, r.ActorID)
	if err != nil || after.ConfigurationHash != before.ConfigurationHash || !reflect.DeepEqual(after.Targets, before.Targets) {
		t.Fatal("encrypted targets lost after old-key removal", err)
	}
}

func TestIntegrationAppliedProjectLocalDeferredTargets(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_local_descriptors")
	r := retainedEnvironmentProject(t, d, now)
	declarations := map[string]LocalServiceDeclaration{"app": {Target: "app"}, "preview": {Target: "app", PublicURL: &ProjectServicePublicURL{Ephemeral: true}}, "database": {Protocol: "postgres", Target: "compose:postgres:5432"}, "cache": {Protocol: "tcp", Target: "docker:cache-1:6379"}}
	for name, declaration := range declarations {
		normal, err := normalizeLocalService(name, declaration)
		if err != nil || normal.Target != declaration.Target {
			t.Fatal("control resolved descriptor", name, err)
		}
		replay, err := normalizeLocalService(name, normal)
		if err != nil || !reflect.DeepEqual(normal, replay) {
			t.Fatal("descriptor not idempotent", err)
		}
		if normal.PublicURL != nil {
			if !normal.PublicURL.Ephemeral {
				t.Fatal("ephemeral intent lost")
			}
			continue
		}
		request := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: name, WorktreeKey: "checkout", ActorID: r.ActorID, Configuration: declaration, Now: now}
		first, err := d.RealizeLocalProjectService(t.Context(), request)
		if err != nil {
			t.Fatal(err)
		}
		second, err := d.RealizeLocalProjectService(t.Context(), request)
		if err != nil || first.ServiceID != second.ServiceID {
			t.Fatal("local restart replaced ID", err)
		}
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&count); err != nil || count != 0 {
		t.Fatal("deferred declaration allocated URL", err)
	}
}

func TestIntegrationAppliedProjectHTTPSettingsAndTargetTrust(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_public_settings")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := retainedEnvironmentProject(t, d, now)
	trust := appliedTargetTrust(t, "upstream.internal")
	total := 100
	e, _ := retainedServiceEnvironment(t, d, r, "production", map[string]EnvironmentServicePublication{"application": {Protocol: "http", Target: "192.0.2.8:8443", TargetTLS: trust, HTTP: &EnvironmentServiceHTTP{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.10"}}, Limits: &config.WorkLimits{Total: &total}}}})
	id := e.Services[0].ServiceID
	u, err := d.GetService(t.Context(), id, r.ActorID)
	if err != nil || u.Endpoint == nil || u.Endpoint.Public || !strings.HasPrefix(u.Endpoint.Hostname, "application.") || e.Services[0].Public {
		t.Fatal("HTTP policy overrode reachability", err)
	}
	checkIP := func(allowed, denied string) {
		t.Helper()
		q := controlstatedb.New(d.pool)
		if err := d.serviceHTTPSourceAllowed(t.Context(), q, id, netip.MustParseAddr(allowed)); err != nil {
			t.Fatal(err)
		}
		if err := d.serviceHTTPSourceAllowed(t.Context(), q, id, netip.MustParseAddr(denied)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("source policy widened", err)
		}
	}
	checkIP("192.0.2.10", "203.0.113.10")
	replica := enrollTestEnvironment(t, d, r, e)
	a := replica.assignments.Services[0]
	if a.Configuration.TargetTLS == nil || *a.Configuration.TargetTLS != *trust || a.Configuration.HTTP.Access.IP[0] != "192.0.2.10/32" {
		t.Fatal("assignment lost trust/HTTP policy")
	}
	old := environmentAssignmentAccess(t, d, replica, a, now)
	approved, err := d.GetServiceForPublisher(t.Context(), id, old.PublisherIdentity, now)
	if err != nil || approved.HTTPLimits == nil || *approved.HTTPLimits.Total != 100 {
		t.Fatal("publisher lost limits", err)
	}
	targets := e.Targets
	s := targets["application"]
	s.HTTP.Access = &config.Access{Mode: "restricted", IP: []string{"203.0.113.0/24"}}
	s.HTTP.Limits.Total = new(250)
	targets["application"] = s
	updated, err := d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, EnvironmentApplication: EnvironmentApplication{EnvironmentID: e.ID, ExpectedRevision: e.MutationRevision, DefinitionRevision: e.AppliedDefinitionRevision, Targets: targets}, Now: now})
	if err != nil || updated.Services[0].ServiceID != id {
		t.Fatal("HTTP apply replaced service", err)
	}
	checkIP("203.0.113.10", "192.0.2.10")
	mutation := retainedPublisherGrantMutation(t, d, r, updated, replica.member.PublisherIdentityID, id)
	if err := d.RevokeEnvironmentPublisherGrant(t.Context(), RevokeEnvironmentPublisherGrantRequest{EnvironmentPublisherGrantMutation: mutation, GrantID: a.GrantID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.AuthenticatePublisherAccess(t.Context(), old.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("explicit replacement retained old token", err)
	}
	if _, err := d.AuthorizeEnvironmentPublisherService(t.Context(), AuthorizeEnvironmentPublisherServiceRequest{EnvironmentPublisherGrantMutation: mutation, ExpectedPreviousGrantID: environmentPublisherGrantExpected(t, a.GrantID), IdempotencyKey: "http-replacement"}); err != nil {
		t.Fatal(err)
	}
	current, err := d.GetEnvironmentPublisherAssignments(t.Context(), replica.lease.AccessToken, now)
	if err != nil || current.Services[0].Configuration.HTTP.Access.IP[0] != "203.0.113.0/24" || *current.Services[0].Configuration.TargetTLS != *trust || *current.Services[0].Configuration.HTTP.Limits.Total != 250 {
		t.Fatal("updated assignment lost policy/trust", err)
	}
	var group, keyID string
	var sealed []byte
	if err := d.pool.QueryRow(t.Context(), `SELECT binding.group_id,binding.storage_key_id,binding.bindings_ciphertext FROM control.publisher_group_bindings binding JOIN control.environments environment ON environment.group_id=binding.group_id WHERE environment.id=$1`, e.ID).Scan(&group, &keyID, &sealed); err != nil || bytes.Contains(sealed, []byte(trust.Hostname)) || bytes.Contains(sealed, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("trust snapshot not encrypted", err)
	}
	definition := ServiceDefinition{Services: map[string]ServiceDefinitionService{"application": {Protocol: "http"}}}
	_, hash, err := NormalizeServiceDefinition(definition)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeServiceDefinition([]byte(`{"services":{"application":{"protocol":"http","public_url":{"ephemeral":true}}}}`), hash); !errors.Is(err, ErrServiceDefinitionInvalid) {
		t.Fatal("definition accepted ephemeral pooled URL", err)
	}
	data, _, err := d.storageKey.Open(keyID, environmentTargetsContext(group), sealed)
	if err != nil {
		t.Fatal(err)
	}
	var stored storedEnvironmentTargets
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatal(err)
	}
	binding := stored.Bindings["application"]
	period := config.Duration(time.Second)
	binding.HTTP.Limits.Rate = &config.Rate{Per: &period}
	stored.Bindings["application"] = binding
	encoded, err := json.Marshal(stored)
	if err != nil {
		t.Fatal(err)
	}
	corrupt, err := d.storageKey.Seal(environmentTargetsContext(group), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.publisher_group_bindings SET bindings_ciphertext=$2,storage_key_id=$3 WHERE group_id=$1`, group, corrupt, d.storageKey.CurrentID()); err != nil {
		t.Fatal(err)
	}
	if err := d.serviceHTTPSourceAllowed(t.Context(), controlstatedb.New(d.pool), id, netip.MustParseAddr("203.0.113.10")); !errors.Is(err, ErrEnvironmentInvalid) {
		t.Fatal("corrupt stored rate admitted visitor", err)
	}
}
