package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func appliedProjectRequest(t *testing.T, d *Database, now time.Time) ApplyProjectConfigurationRequest {
	t.Helper()
	r := oidcRouteRequest(t, d, now)
	return ApplyProjectConfigurationRequest{TeamID: r.TeamID, ActorID: r.ActingIdentityID, ProjectKey: "example", SourceFingerprint: strings.Repeat("a", 64), Configuration: ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{}, Services: map[string]ProjectServiceConfiguration{"web": {Target: "http://localhost:3000"}}}, Now: now}
}

func TestIntegrationAppliedProjectConcurrencyRollbackAndSource(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_concurrency")
	r := appliedProjectRequest(t, d, now)
	r.Configuration.PublisherGroups = map[string]ProjectPublisherGroup{"production": {}}
	r.Configuration.Services["web"] = ProjectServiceConfiguration{PublisherGroup: "production", Target: "http://localhost:3000"}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	workers := newIntegrationWorkers(t, cancel)
	type outcome struct {
		value AppliedProjectConfiguration
		err   error
	}
	done := make(chan outcome, 8)
	for range 8 {
		workers.Go(func() { v, err := d.ApplyProjectConfiguration(ctx, r); done <- outcome{v, err} })
	}
	var original AppliedProjectConfiguration
	for range 8 {
		v := awaitIntegrationResult(t, ctx, done)
		if v.err != nil || v.value.Revision != 1 || len(v.value.Services) != 1 {
			t.Fatalf("concurrent retry: %#v %v", v.value, v.err)
		}
		if original.Revision != 0 && original.Services[0].ServiceID != v.value.Services[0].ServiceID {
			t.Fatal("retry created another resource")
		}
		original = v.value
	}
	if original.Services[0].Kind != "service" {
		t.Fatal("HTTP without public_url became public")
	}
	for index := range 2 {
		workers.Go(func() {
			c := r
			c.ExpectedRevision = 1
			c.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"web": {PublisherGroup: "production", Target: fmt.Sprintf("http://localhost:%d", 4000+index)}}}
			v, e := d.ApplyProjectConfiguration(ctx, c)
			done <- outcome{v, e}
		})
	}
	winners, conflicts := 0, 0
	for range 2 {
		v := awaitIntegrationResult(t, ctx, done)
		if v.err == nil {
			winners++
		} else if errors.Is(v.err, ErrProjectConfigurationStale) {
			conflicts++
		} else {
			t.Fatal(v.err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatalf("optimistic concurrency winners=%d conflicts=%d", winners, conflicts)
	}
	current, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	otherSource := r
	otherSource.SourceFingerprint = strings.Repeat("b", 64)
	otherSource.ExpectedRevision = current.Revision
	if _, err = d.ApplyProjectConfiguration(ctx, otherSource); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatalf("source collision: %v", err)
	}
	bad := r
	bad.ExpectedRevision = current.Revision
	bad.Configuration = current.Configuration
	bad.Configuration.Services["a-new"] = ProjectServiceConfiguration{PublisherGroup: "production", Target: "http://localhost:7000"}
	bad.Configuration.Services["z-conflict"] = ProjectServiceConfiguration{PublisherGroup: "production", Name: "web", Target: "http://localhost:8000"}
	if _, err = d.ApplyProjectConfiguration(ctx, bad); !errors.Is(err, ErrServiceConflict) {
		t.Fatalf("expected atomic name conflict: %v", err)
	}
	after, err := d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	if after.Revision != current.Revision || after.ConfigurationHash != current.ConfigurationHash || len(after.Services) != 1 {
		t.Fatalf("failed apply committed desired state: %#v", after)
	}
	var count int
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1 AND deleted_at IS NULL`, r.TeamID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("failed apply leaked services: %d %v", count, err)
	}
	var sealed []byte
	if err = d.pool.QueryRow(ctx, `SELECT configuration_ciphertext FROM control.applied_projects WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte("localhost")) {
		t.Fatal("target was not encrypted", err)
	}
	// a local public declaration is metadata only and cannot merge worktree previews.
	deferred := r
	deferred.ExpectedRevision = after.Revision
	deferred.Configuration = after.Configuration
	deferred.Configuration.Services["preview"] = ProjectServiceConfiguration{Target: "http://localhost:9000", PublicURL: &ProjectServicePublicURL{}}
	status, err := d.ApplyProjectConfiguration(ctx, deferred)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range status.Services {
		if s.Service == "preview" && (s.Kind != "local" || s.ServiceID != "") {
			t.Fatalf("local public declaration allocated a shared URL: %#v", s)
		}
	}
}

type enrolledGroupReplica struct {
	member      PublisherGroupMember
	private     ed25519.PrivateKey
	lease       PublisherGroupLease
	assignments PublisherGroupAssignments
}

func enrollAppliedGroup(t *testing.T, d *Database, r ApplyProjectConfigurationRequest, e PublisherGroupEnrollment, now time.Time) enrolledGroupReplica {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m, err := d.RedeemPublisherGroupEnrollment(t.Context(), e.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := d.RedeemPublisherGroupEnrollment(t.Context(), e.Key, public, now)
	if err != nil || retry != m {
		t.Fatal("same key redemption changed member", err)
	}
	assertion, err := publisherproof.Sign(m.PublisherIdentityID, m.KeyID, m.GroupID, "https://control.example/v1/publisher-groups/lease", key, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := d.AcquirePublisherGroupLease(t.Context(), m.PublisherIdentityID, m.GroupID, assertion, "https://control.example/v1/publisher-groups/lease", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.AcquirePublisherGroupLease(t.Context(), m.PublisherIdentityID, m.GroupID, assertion, "https://control.example/v1/publisher-groups/lease", now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatalf("group assertion replay: %v", err)
	}
	assignments, err := d.GetPublisherGroupAssignments(t.Context(), lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	return enrolledGroupReplica{m, key, lease, assignments}
}

func groupAssignmentAccess(t *testing.T, d *Database, replica enrolledGroupReplica, a PublisherGroupServiceAssignment, now time.Time) PublisherAccess {
	t.Helper()
	assertion, err := publisherproof.Sign(replica.member.PublisherIdentityID, replica.member.KeyID, a.GrantID, publisherTestAudience, replica.private, now)
	if err != nil {
		t.Fatal(err)
	}
	access, err := d.ExchangePublisherAssertion(t.Context(), replica.member.PublisherIdentityID, a.GrantID, publisherTestAudience, assertion, "", now)
	if err != nil {
		t.Fatal(err)
	}
	return access
}

func TestIntegrationAppliedProjectGroupAssignmentsRunsAndRevocation(t *testing.T) {
	d, now, _, leases := newPublishRunPrerequisites(t)
	d.managedURLMode = naming.ManagedURLModeSimple
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}, "staging": {}}, Services: map[string]ProjectServiceConfiguration{
		"web":   {PublisherGroup: "production", Name: "production", Target: "http://app.internal:3000", HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}}, Access: &ProjectServiceAccess{Team: true}},
		"db":    {PublisherGroup: "production", Protocol: "postgres", Target: "db.internal:5432", Access: &ProjectServiceAccess{Team: true}},
		"stage": {PublisherGroup: "staging", Target: "http://staging.internal:3000"},
	}}
	status, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	e, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 2, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	a, b := enrollAppliedGroup(t, d, r, e, now), enrollAppliedGroup(t, d, r, e, now)
	if a.member.PublisherIdentityID == b.member.PublisherIdentityID || a.member.KeyID == b.member.KeyID || bytes.Equal(a.private, b.private) {
		t.Fatal("replicas share a signed identity")
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err = d.RedeemPublisherGroupEnrollment(t.Context(), e.Key, public, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("bootstrap capacity was not bounded", err)
	}
	stageEnrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "staging", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	stage := enrollAppliedGroup(t, d, r, stageEnrollment, now)
	if len(stage.assignments.Services) != 1 || stage.assignments.Services[0].Service != "stage" || len(a.assignments.Services) != 2 || len(b.assignments.Services) != 2 {
		t.Fatal("group assignment leaked another group's target")
	}
	if _, err = d.RedeemPublisherGroupEnrollment(t.Context(), stageEnrollment.Key, a.private.Public().(ed25519.PublicKey), now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("one key enrolled in two groups", err)
	}
	var oldAccess []PublisherAccess
	var serviceRuns []ServiceRunState
	for _, replica := range []enrolledGroupReplica{a, b} {
		for _, assignment := range replica.assignments.Services {
			access := groupAssignmentAccess(t, d, replica, assignment, now)
			oldAccess = append(oldAccess, access)
			if assignment.Kind == "service" {
				trust, err := appliedServiceTargetTrust(assignment.Configuration.TargetTLS)
				if err != nil {
					t.Fatal(err)
				}
				metadata := ServiceMetadata{Protocol: assignment.Configuration.Protocol, TLS: trust, PublisherPool: true, TrustRevision: assignment.TrustRevision}
				prepared, err := d.PrepareServiceRun(t.Context(), assignment.ServiceID, access.PublisherIdentity, "group", now, metadata)
				if err != nil {
					t.Fatal(err)
				}
				run, err := d.StartServiceRun(t.Context(), assignment.ServiceID, prepared.RunID, prepared.RunNumber, access.PublisherIdentity, now)
				if err != nil {
					t.Fatal(err)
				}
				serviceRuns = append(serviceRuns, run)
				installPrivateTestCertificate(t, d, prepared, run, now)
				for _, slot := range run.Connections {
					lease := leases[slot.RelayServiceID].RelayLeaseIdentity
					if _, err = d.ClaimServicePublisherConnection(t.Context(), slot.PublisherConnectionID, assignment.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
						t.Fatal(err)
					}
					if _, err = d.ReadyServicePublisherConnection(t.Context(), slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
						t.Fatal(err)
					}
				}
				if state, err := d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil || state.State != "ready" {
					t.Fatalf("group private run not ready: %+v %v", state, err)
				}
			} else {
				t.Fatal("group HTTP selected superseded public URL run")
			}
		}
		if err = d.AcknowledgePublisherGroupConfiguration(t.Context(), replica.lease.AccessToken, status.Revision, status.ConfigurationHash, true, now); err != nil {
			t.Fatal(err)
		}
	}
	if len(serviceRuns) != 4 || serviceRuns[0].Connections[0].PublisherConnectionID == serviceRuns[2].Connections[0].PublisherConnectionID || serviceRuns[0].RunID == serviceRuns[2].RunID {
		t.Fatal("private replicas share run identity or publisher assignment")
	}
	status, err = d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Members) != 3 || status.Members[0].ObservedRevision != 1 {
		t.Fatal("member acknowledgement was not observed")
	}
	if err = d.RevokePublisherGroupMember(t.Context(), r.TeamID, r.ProjectKey, "staging", a.member.PublisherIdentityID, r.ActorID, now); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatal("member revocation crossed group scope", err)
	}
	if err = d.RevokePublisherGroupMember(t.Context(), r.TeamID, r.ProjectKey, "production", a.member.PublisherIdentityID, r.ActorID, now); err != nil {
		t.Fatal("admin member revocation", err)
	}
	if _, err = d.GetPublisherGroupAssignments(t.Context(), a.lease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("revoked replica retained group lease", err)
	}
	if _, err = d.HeartbeatServiceRun(t.Context(), serviceRuns[0].ServiceID, serviceRuns[0].RunID, serviceRuns[0].Token, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked replica retained private run", err)
	}
	if _, err = d.HeartbeatServiceRun(t.Context(), serviceRuns[1].ServiceID, serviceRuns[1].RunID, serviceRuns[1].Token, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("revoked replica retained service HTTP run", err)
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), serviceRuns[2].ServiceID, serviceRuns[2].RunID, serviceRuns[2].Token, now); err != nil || state.State != "ready" {
		t.Fatal("revoking one replica disturbed its peer private run", err)
	}
	if state, err := d.HeartbeatServiceRun(t.Context(), serviceRuns[3].ServiceID, serviceRuns[3].RunID, serviceRuns[3].Token, now); err != nil || state.State != "ready" {
		t.Fatal("revoking one replica disturbed its peer HTTP run", err)
	}
	// a trust change keeps the saved service ID, closes old runs, and replaces
	// exact grants before any replica can acknowledge or run the new revision.
	r.ExpectedRevision = 1
	r.Configuration.PublisherGroups["production"] = ProjectPublisherGroup{Description: "updated production group"}
	db := r.Configuration.Services["db"]
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00database.internal\x00"))
	db.TargetTLS = &ProjectTargetTLS{Hostname: "database.internal", Digest: hex.EncodeToString(digest[:])}
	r.Configuration.Services["db"] = db
	updated, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if err = d.AcknowledgePublisherGroupConfiguration(t.Context(), b.lease.AccessToken, 1, status.ConfigurationHash, true, now); !errors.Is(err, ErrProjectConfigurationStale) {
		t.Fatal("stale ack was accepted", err)
	}
	newAssignments, err := d.GetPublisherGroupAssignments(t.Context(), b.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, assignment := range newAssignments.Services {
		if assignment.Service == "db" && assignment.TrustRevision != 2 {
			t.Fatal("trust revision did not advance")
		}
	}
	for _, run := range serviceRuns {
		if run.ServiceID != serviceRuns[0].ServiceID {
			continue
		}
		if _, err = d.HeartbeatServiceRun(t.Context(), run.ServiceID, run.RunID, run.Token, now); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("old private run survived trust change", err)
		}
	}
	for _, access := range oldAccess {
		if access.Scope.ServiceID == serviceRuns[0].ServiceID {
			if _, err = d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("old private access survived replacement", err)
			}
		}
	}
	page, err := d.ListServiceAudit(t.Context(), r.TeamID, r.ActorID, ServiceAuditFilter{ServiceID: serviceRuns[0].ServiceID, Limit: 256}, now)
	if err != nil {
		t.Fatal(err)
	}
	enrolled, revoked, described := false, false, false
	for _, event := range page.Events {
		if event.EventType == "group.update" {
			if event.PublisherIdentityID == a.member.PublisherIdentityID && event.ActorIdentityID == "" {
				enrolled = true
			}
			if event.PublisherIdentityID == a.member.PublisherIdentityID && event.ActorIdentityID == r.ActorID {
				revoked = true
			}
			if event.PublisherIdentityID == "" && event.ActorIdentityID == r.ActorID && event.ConfigurationRevision == 2 {
				described = true
			}
		}
	}
	if !enrolled || !revoked || !described {
		t.Fatalf("missing group audit facts: enrolled=%t revoked=%t description=%t", enrolled, revoked, described)
	}
	r.ExpectedRevision = updated.Revision
	delete(r.Configuration.PublisherGroups, "production")
	delete(r.Configuration.Services, "web")
	delete(r.Configuration.Services, "db")
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetPublisherGroupAssignments(t.Context(), a.lease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("removed group retained assignments", err)
	}
	for _, access := range oldAccess {
		if _, err = d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("removed group retained native grants", err)
		}
	}
	if _, err = d.GetPublisherGroupAssignments(t.Context(), stage.lease.AccessToken, now); err != nil {
		t.Fatal("removing production disturbed staging", err)
	}
	if err = d.RevokePublisherIdentity(t.Context(), r.TeamID, stage.member.PublisherIdentityID, r.ActorID, now); err != nil {
		t.Fatal("general admin identity revocation", err)
	}
	if _, err = d.GetPublisherGroupAssignments(t.Context(), stage.lease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("general admin revoke retained group access", err)
	}
	stageAudit, err := d.ListServiceAudit(t.Context(), r.TeamID, r.ActorID, ServiceAuditFilter{ServiceID: stage.assignments.Services[0].ServiceID, Limit: 256}, now)
	if err != nil {
		t.Fatal(err)
	}
	generalRevoked := false
	for _, event := range stageAudit.Events {
		if event.EventType == "group.update" && event.PublisherIdentityID == stage.member.PublisherIdentityID && event.ActorIdentityID == r.ActorID {
			generalRevoked = true
		}
	}
	if !generalRevoked {
		t.Fatal("general admin revoke omitted group audit fact")
	}
}

func TestIntegrationAppliedProjectGroupReassignmentKeepsSavedService(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_move")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}, "staging": {}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "production", Target: "https://api.internal:8443", Access: &ProjectServiceAccess{Team: true}}}}
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00api.internal\x00"))
	service := r.Configuration.Services["api"]
	service.TargetTLS = &ProjectTargetTLS{Hostname: "api.internal", Digest: hex.EncodeToString(digest[:])}
	r.Configuration.Services["api"] = service
	initial, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	var replicas []enrolledGroupReplica
	for _, group := range []string{"production", "staging"} {
		e, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, group, r.ActorID, 1, time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		replicas = append(replicas, enrollAppliedGroup(t, d, r, e, now))
	}
	old := groupAssignmentAccess(t, d, replicas[0], replicas[0].assignments.Services[0], now)
	service.PublisherGroup = "staging"
	service.Access = nil
	r.Configuration.Services["api"] = service
	r.ExpectedRevision = 1
	updated, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Services[0].ServiceID != initial.Services[0].ServiceID {
		t.Fatal("moving group replaced the saved service")
	}
	production, err := d.GetPublisherGroupAssignments(t.Context(), replicas[0].lease.AccessToken, now)
	if err != nil || len(production.Services) != 0 {
		t.Fatal("old group retained assignment", err)
	}
	staging, err := d.GetPublisherGroupAssignments(t.Context(), replicas[1].lease.AccessToken, now)
	if err != nil || len(staging.Services) != 1 {
		t.Fatal("new group did not receive assignment", err)
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), old.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("old group retained publication grant", err)
	}
	current := groupAssignmentAccess(t, d, replicas[1], staging.Services[0], now)
	a := staging.Services[0]
	trust, err := appliedServiceTargetTrust(service.TargetTLS)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.PrepareServiceRun(t.Context(), a.ServiceID, current.PublisherIdentity, "http", now, ServiceMetadata{Protocol: "http", TLS: trust, PublisherPool: true, TrustRevision: a.TrustRevision}); err != nil {
		t.Fatal("private HTTP/TLS assignment is not publishable", err)
	}
	var teamGrants int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.service_grants WHERE service_id=$1 AND kind='team' AND revoked_at IS NULL`, a.ServiceID).Scan(&teamGrants); err != nil || teamGrants != 0 {
		t.Fatal("removed declarative team access survived", err)
	}
	r.ExpectedRevision = 2
	delete(r.Configuration.Services, "api")
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	if _, err = d.AuthenticatePublisherAccess(t.Context(), current.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("removed service retained exact grant", err)
	}
}

func TestIntegrationAppliedProjectStorageRotation(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "applied_rotation")
	r := appliedProjectRequest(t, d, now)
	before, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	rotating, err := Open(t.Context(), databaseURL, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	defer rotating.Close()
	if err = rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(t.Context(), databaseURL, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after, err := reopened.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, r.ActorID)
	if err != nil || after.ConfigurationHash != before.ConfigurationHash || after.Configuration.Services["web"].Target != before.Configuration.Services["web"].Target {
		t.Fatal("applied target cannot be read after dropping the old key", err)
	}
}

func TestIntegrationAppliedProjectLocalDeferredTargets(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_local_descriptors")
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"app":      {Target: "app"},
		"preview":  {Target: "app", PublicURL: &ProjectServicePublicURL{Ephemeral: true}},
		"database": {Protocol: "postgres", Target: "compose:postgres:5432"},
		"cache":    {Protocol: "tcp", Target: "docker:cache-1:6379"},
	}}
	status, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	for name, service := range r.Configuration.Services {
		if status.Configuration.Services[name].Target != service.Target {
			t.Fatal("control resolved a local discovery descriptor")
		}
	}
	if !status.Configuration.Services["preview"].PublicURL.Ephemeral {
		t.Fatal("deferred ephemeral URL intent was lost")
	}
	var publicURLs int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.public_urls WHERE team_id=$1`, r.TeamID).Scan(&publicURLs); err != nil || publicURLs != 0 {
		t.Fatal("deferred local target allocated a public URL", err)
	}
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal("local descriptor retry was not idempotent", err)
	}
}

func TestIntegrationAppliedProjectHTTPSettingsAndTargetTrust(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "applied_public_settings")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := appliedProjectRequest(t, d, now)
	trust := appliedTargetTrust(t, "upstream.internal")
	total := 100
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{"web": {
		PublisherGroup: "production", Name: "application", Target: "https://192.0.2.8:8443", TargetTLS: trust,
		HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.10"}}, Limits: &config.WorkLimits{Total: &total}},
	}}}
	status, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	id := status.Services[0].ServiceID
	u, err := d.GetService(t.Context(), id, r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	if u.Endpoint == nil || u.Endpoint.Public || !strings.HasPrefix(u.Endpoint.Hostname, "application.") || status.Services[0].Public {
		t.Fatalf("HTTP settings overrode group reachability: %+v", u)
	}
	checkIP := func(allowed, denied string) {
		t.Helper()
		q := controlstatedb.New(d.pool)
		if err := d.serviceHTTPSourceAllowed(t.Context(), q, id, netip.MustParseAddr(allowed)); err != nil {
			t.Fatal(err)
		}
		if err := d.serviceHTTPSourceAllowed(t.Context(), q, id, netip.MustParseAddr(denied)); !errors.Is(err, ErrServiceAccess) {
			t.Fatal("service HTTP source filter widened", err)
		}
	}
	checkIP("192.0.2.10", "203.0.113.10")
	enrollment, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, enrollment, now)
	a := replica.assignments.Services[0]
	if a.Configuration.TargetTLS == nil || *a.Configuration.TargetTLS != *trust || a.Configuration.HTTP.Access.IP[0] != "192.0.2.10/32" {
		t.Fatalf("assignment lost target trust or HTTP settings: %+v", a.Configuration)
	}
	old := groupAssignmentAccess(t, d, replica, a, now)
	approved, err := d.GetServiceForPublisher(t.Context(), id, old.PublisherIdentity, now)
	if err != nil || approved.HTTPLimits == nil || *approved.HTTPLimits.Total != 100 {
		t.Fatal("publisher did not receive approved HTTP limits", err)
	}
	s := r.Configuration.Services["web"]
	s.HTTP.Access = &config.Access{Mode: "restricted", IP: []string{"203.0.113.0/24"}}
	s.HTTP.Limits.Total = new(250)
	r.Configuration.Services["web"] = s
	r.ExpectedRevision = 1
	updated, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Services[0].ServiceID != id {
		t.Fatal("changing HTTP settings replaced its service")
	}
	checkIP("203.0.113.10", "192.0.2.10")
	if _, err = d.AuthenticatePublisherAccess(t.Context(), old.Token, "", now); !errors.Is(err, ErrPublisherIdentity) {
		t.Fatal("replaced desired state retained its old grant", err)
	}
	current, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if current.Services[0].Configuration.HTTP.Access.IP[0] != "203.0.113.0/24" || *current.Services[0].Configuration.TargetTLS != *trust {
		t.Fatal("updated assignment dropped HTTP policy or target trust")
	}
	if *current.Services[0].Configuration.HTTP.Limits.Total != 250 {
		t.Fatal("updated HTTP limits lost")
	}
	var sealed []byte
	if err = d.pool.QueryRow(t.Context(), `SELECT configuration_ciphertext FROM control.applied_projects WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey).Scan(&sealed); err != nil || bytes.Contains(sealed, []byte(trust.Hostname)) || bytes.Contains(sealed, []byte("BEGIN CERTIFICATE")) {
		t.Fatal("target metadata snapshot was not encrypted", err)
	}
	// a true remote ephemeral declaration cannot silently turn into a saved pool.
	bad := r
	bad.ExpectedRevision = updated.Revision
	invalidService := bad.Configuration.Services["web"]
	invalidService.PublicURL = &ProjectServicePublicURL{Ephemeral: true}
	bad.Configuration.Services["web"] = invalidService
	if _, err = d.ApplyProjectConfiguration(t.Context(), bad); !errors.Is(err, ErrProjectConfigurationInvalid) {
		t.Fatal("unsupported ephemeral pooled URL was silently accepted", err)
	}
	// a corrupt stored rate must deny admission instead of reaching pointer
	// conversion in the publisher projection.
	s.PublicURL = nil
	period := config.Duration(time.Second)
	s.HTTP.Limits.Rate = &config.Rate{Per: &period}
	bad.Configuration.Services["web"] = s
	encoded, err := json.Marshal(bad.Configuration)
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := d.storageKey.Seal(appliedProjectContext(r.TeamID, r.ProjectKey), encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.applied_projects SET configuration_ciphertext=$3,storage_key_id=$4 WHERE team_id=$1 AND project_key=$2`, r.TeamID, r.ProjectKey, encrypted, d.storageKey.CurrentID()); err != nil {
		t.Fatal(err)
	}
	if err = d.serviceHTTPSourceAllowed(t.Context(), controlstatedb.New(d.pool), id, netip.MustParseAddr("203.0.113.10")); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("malformed stored HTTP limits admitted a visitor", err)
	}
}
