package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestIntegrationAppliedProjectLocalRealizationOwnership(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_provenance")
	base := oidcRouteRequest(t, d, now)
	ctx := t.Context()
	if _, err := d.pool.Exec(ctx, `UPDATE control.teams SET kind='organization' WHERE id=$1`, base.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, now, base.ActingIdentityID, base.TeamID, "local-reader", TeamRoleMember)
	unrelated, err := d.CreateServiceAt(ctx, base.TeamID, base.ActingIdentityID, "db", "manual-db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	configuration := ProjectConfiguration{Services: map[string]ProjectServiceConfiguration{
		"db":  {Protocol: "postgres", Target: "localhost:5432", Access: &ProjectServiceAccess{Team: true}},
		"web": {Target: "app", PublicURL: &ProjectServicePublicURL{}, Access: &ProjectServiceAccess{Team: true}},
	}}
	r := ApplyProjectConfigurationRequest{TeamID: base.TeamID, ProjectKey: "local-project", SourceFingerprint: strings.Repeat("a", 64), ActorID: base.ActingIdentityID, Configuration: configuration, Now: now}
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, SourceFingerprint: r.SourceFingerprint, Service: "db", WorktreeKey: "checkout-a", ActorID: r.ActorID, Configuration: configuration.Services["db"], Now: now}
	first, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	if first.ServiceID == unrelated.ID || first.Metadata == nil {
		t.Fatal("local runtime adopted an unrelated name")
	}
	retry, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil || retry.ServiceID != first.ServiceID {
		t.Fatal("realization retry changed private ID", err)
	}
	local.WorktreeKey = "checkout-b"
	second, err := d.RealizeLocalProjectService(ctx, local)
	if err != nil || second.ServiceID == first.ServiceID {
		t.Fatal("worktrees share a service", err)
	}
	public := createTestPublicURL(t, d, base, now)
	local.Service, local.WorktreeKey, local.PublicURLID, local.Configuration = "web", "checkout-a", public.ID, configuration.Services["web"]
	if _, err = d.RealizeLocalProjectService(ctx, local); err != nil {
		t.Fatal(err)
	}
	if _, err = d.RealizeLocalProjectService(ctx, RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "another-project", SourceFingerprint: r.SourceFingerprint, Service: "web", WorktreeKey: "checkout-a", ActorID: r.ActorID, Configuration: local.Configuration, PublicURLID: public.ID, Now: now}); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("public resource adopted by unrelated project", err)
	}
	status, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal("first apply collided with legitimate startup", err)
	}
	for _, s := range status.Services {
		if s.Kind != "local" || s.ServiceID != "" {
			t.Fatal("apply allocated a shared local resource")
		}
	}
	var count int
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.services WHERE team_id=$1 AND deleted_at IS NULL`, r.TeamID).Scan(&count); err != nil || count != 3 {
		t.Fatal("apply duplicated local service", count, err)
	}
	if _, err = d.GetProjectConfiguration(ctx, r.TeamID, r.ProjectKey, member.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("member read manager configuration", err)
	}
	if _, err = d.ConfigureService(ctx, first.ServiceID, r.ActorID, *first.Metadata, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("direct managed definition changed", err)
	}
	if err = d.DeleteService(ctx, first.ServiceID, r.ActorID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("direct service deleted", err)
	}
	var configuredGrant string
	if err = d.pool.QueryRow(ctx, `SELECT visitor_grant_id FROM control.local_project_services WHERE service_id=$1`, first.ServiceID).Scan(&configuredGrant); err != nil {
		t.Fatal(err)
	}
	if err = d.RevokeServiceGrant(ctx, first.ServiceID, r.ActorID, configuredGrant, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("configured team grant revoked directly", err)
	}
	extra, err := d.CreateServiceGrant(ctx, first.ServiceID, r.ActorID, "extra-visitor", "identity", member.IdentityID, nil, now)
	if err != nil {
		t.Fatal("extra visitor grant was blanket denied", err)
	}
	if err = d.RevokeServiceGrant(ctx, first.ServiceID, r.ActorID, extra.ID, now); err != nil {
		t.Fatal(err)
	}
	var publicGrant string
	if err = d.pool.QueryRow(ctx, `SELECT visitor_grant_id FROM control.local_project_services WHERE public_url_id=$1`, public.ID).Scan(&publicGrant); err != nil {
		t.Fatal(err)
	}
	if err = d.RevokeVisitorGrant(ctx, public.ID, r.ActorID, publicGrant, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("configured local public team grant revoked directly", err)
	}
	r.ExpectedRevision = status.Revision
	r.Configuration = status.Configuration
	for key, s := range r.Configuration.Services {
		s.Access = nil
		r.Configuration.Services[key] = s
	}
	if _, err = d.ApplyProjectConfiguration(ctx, r); err != nil {
		t.Fatal(err)
	}
	for _, grant := range []string{configuredGrant, extra.ID} {
		var revoked bool
		if err = d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.service_grants WHERE id=$1`, grant).Scan(&revoked); err != nil || !revoked {
			t.Fatal("apply restored revoked or removed access", err)
		}
	}
	var revoked bool
	if err = d.pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM control.visitor_grants WHERE id=$1`, publicGrant).Scan(&revoked); err != nil || !revoked {
		t.Fatal("apply did not remove local public team access", err)
	}
	local.Configuration = r.Configuration.Services["web"]
	if _, err = d.RealizeLocalProjectService(ctx, local); err != nil {
		t.Fatal("restart after access removal", err)
	}
	if err = d.pool.QueryRow(ctx, `SELECT count(*) FROM control.visitor_grants WHERE public_url_id=$1 AND kind='team' AND revoked_at IS NULL`, public.ID).Scan(&count); err != nil || count != 0 {
		t.Fatal("restart restored removed team access", count, err)
	}
	if _, err = d.GetProjectPublicMetadata(ctx, r.TeamID, r.ProjectKey, member.IdentityID, now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatal("removed team access still exposed local public metadata", err)
	}
	local.SourceFingerprint = strings.Repeat("b", 64)
	if _, err = d.RealizeLocalProjectService(ctx, local); !errors.Is(err, ErrProjectSourceConflict) {
		t.Fatal("source conflict accepted", err)
	}
}

func TestIntegrationAppliedProjectLocalEphemeralRealizationAfterExpiry(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "local_ephemeral")
	r := oidcRouteRequest(t, d, now)
	r.Ephemeral = true
	first := createTestPublicURL(t, d, r, now)
	local := RealizeLocalProjectServiceRequest{TeamID: r.TeamID, ProjectKey: "ephemeral", SourceFingerprint: strings.Repeat("a", 64), Service: "web", WorktreeKey: "checkout", ActorID: r.ActingIdentityID, PublicURLID: first.ID, Configuration: ProjectServiceConfiguration{Target: "app", PublicURL: &ProjectServicePublicURL{Ephemeral: true}, Access: &ProjectServiceAccess{Team: true}}, Now: now}
	if _, err := d.RealizeLocalProjectService(t.Context(), local); err != nil {
		t.Fatal(err)
	}
	r.IdempotencyKey = "replacement"
	r.RequestDigest = sha256.Sum256([]byte("replacement"))
	r.CanonicalHostname = strings.Replace(r.CanonicalHostname, "demo.", "other.", 1)
	second := createTestPublicURL(t, d, r, now.Add(time.Second))
	local.PublicURLID = second.ID
	if _, err := d.RealizeLocalProjectService(t.Context(), local); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("healthy local binding was silently replaced", err)
	}
	if first.ExpiresAt == nil {
		t.Fatal("ephemeral URL has no deadline")
	}
	if count, err := d.DeleteExpiredEphemeralPublicURLs(t.Context(), *first.ExpiresAt); err != nil || count != 1 {
		t.Fatal("runtime expiry did not remove exactly the old URL", count, err)
	}
	local.Now = *first.ExpiresAt
	realized, err := d.RealizeLocalProjectService(t.Context(), local)
	if err != nil || realized.ServiceID != second.ID {
		t.Fatal("expired worktree binding prevented restart", err)
	}
	var active int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.visitor_grants WHERE public_url_id=$1 AND kind='team' AND revoked_at IS NULL`, first.ID).Scan(&active); err != nil || active != 0 {
		t.Fatal("expiry replacement left the old team grant active", err)
	}
}

func TestIntegrationAppliedProjectManagedGroupGrantsAndSafeMetadata(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "managed_projection")
	d.managedURLMode = naming.ManagedURLModeSimple
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"production": {}}, Services: map[string]ProjectServiceConfiguration{
		"public": {PublisherGroup: "production", Target: "http://secret.internal:3000", Access: &ProjectServiceAccess{Team: true}},
		"db":     {PublisherGroup: "production", Protocol: "postgres", Target: "db.internal:5432"},
	}}
	status, err := d.ApplyProjectConfiguration(t.Context(), r)
	if err != nil {
		t.Fatal(err)
	}
	var publicID string
	for _, s := range status.Services {
		if s.Service == "public" {
			publicID = s.ServiceID
		}
	}
	if err = d.DeleteService(t.Context(), publicID, r.ActorID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("direct service deletion succeeded", err)
	}
	if _, err = d.GetPublicURL(t.Context(), r.ActorID, publicID); err == nil {
		t.Fatal("service became a public URL")
	}
	if _, err := d.pool.Exec(t.Context(), `UPDATE control.teams SET kind='organization' WHERE id=$1`, r.TeamID); err != nil {
		t.Fatal(err)
	}
	member := addAuthorityMember(t, d, now, r.ActorID, r.TeamID, "metadata-reader", TeamRoleMember)
	projection, err := d.GetProjectPublicMetadata(t.Context(), r.TeamID, r.ProjectKey, member.IdentityID, now)
	if !errors.Is(err, ErrPublicURLAccess) || len(projection.Services) != 0 {
		t.Fatal("managed access granted public URL metadata permission", projection, err)
	}
	encoded, _ := json.Marshal(projection)
	for _, value := range []string{"configuration", "target", "secret.internal", "db.internal", "grant", "publisher", "tls"} {
		if strings.Contains(string(encoded), value) {
			t.Fatal("projection leaked manager data", value)
		}
	}
	if _, err = d.GetProjectConfiguration(t.Context(), r.TeamID, r.ProjectKey, member.IdentityID); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("visitor read full configuration", err)
	}
	outsider := finalVisitorIdentity(t, d, now, "projection-outsider@example.test")
	if _, err = d.GetProjectPublicMetadata(t.Context(), r.TeamID, r.ProjectKey, outsider, now); !errors.Is(err, ErrPublicURLAccess) {
		t.Fatal("ungranted visitor read project source", err)
	}
	e, err := d.IssuePublisherGroupEnrollment(t.Context(), r.TeamID, r.ProjectKey, "production", r.ActorID, 1, time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	replica := enrollAppliedGroup(t, d, r, e, now)
	a := replica.assignments.Services[0]
	if err = d.RevokePublisherGrant(t.Context(), r.TeamID, replica.member.PublisherIdentityID, a.GrantID, r.ActorID, now); !errors.Is(err, ErrProjectManaged) {
		t.Fatal("managed group grant revoked directly", err)
	}
	if current, e := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now); e != nil || len(current.Services) != 2 {
		t.Fatal("guard disturbed group poll", e)
	}
	// legacy or exceptional revoked state must not be silently recreated by an
	// unrelated apply, and must not turn healthy sibling assignments into 401.
	if _, err = d.pool.Exec(t.Context(), `UPDATE control.publisher_grants SET revoked_at=$2 WHERE id=$1`, a.GrantID, now); err != nil {
		t.Fatal(err)
	}
	r.ExpectedRevision = status.Revision
	r.Configuration = status.Configuration
	r.Configuration.PublisherGroups["production"] = ProjectPublisherGroup{Description: "updated description"}
	if _, err = d.ApplyProjectConfiguration(t.Context(), r); err != nil {
		t.Fatal(err)
	}
	current, err := d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now)
	if err != nil || len(current.Services) != 1 {
		t.Fatal("one revoked grant broke sibling poll", current, err)
	}
	var grant string
	if err = d.pool.QueryRow(t.Context(), `SELECT grant_id FROM control.publisher_group_service_grants WHERE publisher_identity_id=$1 AND service=$2`, replica.member.PublisherIdentityID, a.Service).Scan(&grant); err != nil || grant != a.GrantID {
		t.Fatal("unrelated apply recreated revoked grant", err)
	}
	if err = d.RevokePublisherGroupMember(t.Context(), r.TeamID, r.ProjectKey, "production", replica.member.PublisherIdentityID, r.ActorID, now); err != nil {
		t.Fatal(err)
	}
	if _, err = d.GetPublisherGroupAssignments(t.Context(), replica.lease.AccessToken, now); !errors.Is(err, ErrPublisherGroup) {
		t.Fatal("operational revoke was not immediate", err)
	}
}

func TestIntegrationPrivateVisitorAssignmentReleaseIsExact(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "release_assignment")
	r := oidcRouteRequest(t, d, now)
	service, err := d.CreateServiceAt(t.Context(), r.TeamID, r.ActingIdentityID, "db", "db", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := d.EnrollVisitorDevice(t.Context(), r.ActingIdentityID, public, now)
	if err != nil {
		t.Fatal(err)
	}
	leases := map[string]IngressLease{}
	for index := range 2 {
		lease, e := d.RegisterIngress(t.Context(), IngressRegistration{IngressID: fmt.Sprintf("release-%d", index), IngressRunID: fmt.Sprintf("run-%d", index), ProtocolVersion: 1, ConnectionCapacity: 1, ConnectorAddress: fmt.Sprintf("127.0.0.1:%d", 7400+index), ConnectorTLSServerName: "private.example.test"}, now, time.Hour)
		if e != nil {
			t.Fatal(e)
		}
		leases[lease.IngressID] = lease
	}
	sessions, err := d.CreateVisitorIngressAssignments(t.Context(), r.ActingIdentityID, device.ID, service.ID, "startup", now)
	if err != nil {
		t.Fatal(err)
	}
	other := finalVisitorIdentity(t, d, now, "other@example.test")
	if err = d.ReleaseVisitorIngressAssignment(t.Context(), other, sessions[0].ID, now); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("other identity released assignment", err)
	}
	for range 2 {
		if err = d.ReleaseVisitorIngressAssignment(t.Context(), r.ActingIdentityID, sessions[0].ID, now); err != nil {
			t.Fatal("release not retry-stable", err)
		}
	}
	var pending int
	if err = d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_sessions WHERE assigned_ingress_id=$1 AND bound_at IS NULL AND revoked_at IS NULL`, sessions[0].IngressID).Scan(&pending); err != nil || pending != 0 {
		t.Fatal("release did not free reservation", pending, err)
	}
	sibling := sessions[1]
	hello := tunnelv1.ConnectorSessionHello{ProtocolVersion: tunnelv1.Version, Kind: "connector_session", SessionID: sibling.ID, ServiceID: service.ID, Subject: tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorHumanDevice, IdentityID: r.ActingIdentityID, DeviceID: device.ID}, Credential: sibling.Credential, Nonce: make([]byte, 32), Signature: make([]byte, ed25519.SignatureSize)}
	digest, err := hello.Claim().Digest()
	if err != nil {
		t.Fatal(err)
	}
	hello.Signature = ed25519.Sign(key, digest)
	if _, err = d.AuthenticateVisitorConnector(t.Context(), leases[sibling.IngressID].IngressLeaseIdentity, hello.Claim(), netip.MustParseAddr("192.0.2.10"), now); err != nil {
		t.Fatal("release invalidated healthy sibling", err)
	}
	if err = d.ReleaseVisitorIngressAssignment(t.Context(), r.ActingIdentityID, sibling.ID, now); err != nil {
		t.Fatal("bound shutdown release failed", err)
	}
	var revoked bool
	if err = d.pool.QueryRow(t.Context(), `SELECT revoked_at IS NOT NULL AND bound_at IS NOT NULL FROM control.connector_sessions WHERE id=$1`, sibling.ID).Scan(&revoked); err != nil || !revoked {
		t.Fatal("bound release not visible to active recheck", err)
	}
}
