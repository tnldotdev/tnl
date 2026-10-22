package public

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationAppliedProjectHTTPContracts(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "applied_project_http")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team := session.Identity.Memberships[0].TeamID
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", h)
	owner, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	anonymous, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	group := "production"
	body := controlv1.ApplyProjectConfigurationRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), ExpectedRevision: 0, Configuration: controlv1.ProjectConfiguration{PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"web": {PublisherGroup: &group, Target: "http://app.internal:3000"}}}}
	body.Configuration.Oauth = true
	body.Configuration.Services["local-app"] = controlv1.ProjectServiceConfiguration{Target: "app", PublicUrl: &controlv1.ProjectServicePublicURL{}}
	body.Configuration.Services["local-private"] = controlv1.ProjectServiceConfiguration{Target: "app"}
	body.Configuration.Webhooks = map[string]controlv1.ProjectWebhook{"payments": {Service: "local-app", Path: "/hooks/payments", Provider: controlv1.Custom}}
	name, hostname, mode := "website", "upstream.internal", controlv1.Restricted
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + hostname + "\x00"))
	body.Configuration.Services["public"] = controlv1.ProjectServiceConfiguration{PublisherGroup: &group, Name: &name, Target: "https://192.0.2.5:8443", TargetTls: &controlv1.ProjectTargetTLS{Hostname: hostname, Digest: hex.EncodeToString(digest[:])}, Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectPublicAccess{Mode: &mode}}}
	if _, err = anonymous.ApplyProjectConfiguration(ctx, "example", body); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous desired-state mutation", err)
	}
	applied, err := owner.ApplyProjectConfiguration(ctx, "example", body)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Revision != 1 || len(applied.Services) != 4 || !applied.Configuration.Oauth || len(applied.Configuration.Webhooks) != 1 {
		t.Fatalf("wire configuration: %+v", applied)
	}
	endpoint := applied.Configuration.Webhooks["payments"]
	if endpoint.Delivery == nil || *endpoint.Delivery != "fanout" || endpoint.Methods == nil || len(*endpoint.Methods) != 1 || (*endpoint.Methods)[0] != "POST" {
		t.Fatal("wire root declaration lost webhook defaults")
	}
	rawAPI, err := controlv1.NewClientWithResponses(server.URL, controlv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	auth := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	}
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	var missing map[string]any
	if err = json.Unmarshal(encoded, &missing); err != nil {
		t.Fatal(err)
	}
	delete(missing, "expected_revision")
	missingBytes, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	missingReply, err := rawAPI.ApplyProjectConfigurationWithBodyWithResponse(ctx, "example", "application/json", bytes.NewReader(missingBytes), auth)
	if err != nil || missingReply.StatusCode() != 400 {
		t.Fatal("content replay accepted a missing expected_revision", err)
	}
	var unknown map[string]any
	if err = json.Unmarshal(encoded, &unknown); err != nil {
		t.Fatal(err)
	}
	secret := "must-not-leak-webhook-secret"
	unknown["configuration"].(map[string]any)["webhooks"].(map[string]any)["payments"].(map[string]any)["signing_secret"] = secret
	unknownBytes, err := json.Marshal(unknown)
	if err != nil {
		t.Fatal(err)
	}
	unknownReply, err := rawAPI.ApplyProjectConfigurationWithBodyWithResponse(ctx, "example", "application/json", bytes.NewReader(unknownBytes), auth)
	if err != nil || unknownReply.StatusCode() != 400 || bytes.Contains(unknownReply.Body, []byte(secret)) {
		t.Fatal("webhook source secret was accepted or exposed", err)
	}
	enrollment, err := owner.CreatePublisherGroupEnrollment(ctx, "example", group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: team, MaxMembers: 2, ExpiresIn: 600})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := anonymous.RedeemPublisherGroupEnrollment(ctx, enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	if member.GroupId != enrollment.GroupId || member.GroupName != group {
		t.Fatal("enrollment changed group scope")
	}
	proof, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.GroupId, server.URL+"/v1/publisher-groups/lease", private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := anonymous.AcquirePublisherGroupLease(ctx, controlv1.PublisherGroupLeaseRequest{PublisherIdentityId: member.PublisherIdentityId, GroupId: member.GroupId, Assertion: proof})
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := anonymous.GetPublisherGroupAssignments(ctx, lease.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	byService := map[string]controlv1.PublisherGroupServiceAssignment{}
	for _, assignment := range assignments.Services {
		byService[assignment.Service] = assignment
	}
	web, pub := byService["web"], byService["public"]
	assertManaged := func(err error) {
		t.Helper()
		var problem *clientcontrol.ProblemError
		if !errors.Is(err, clientcontrol.ErrProjectManaged) || !errors.Is(err, clientcontrol.ErrStatusConflict) || !errors.As(err, &problem) || problem.Status != 409 || problem.Problem.Code != controlv1.ProjectManaged || problem.Problem.RequestId == "" || problem.Problem.Detail != "resource is managed by project configuration; change the declaration and run tnl apply" {
			t.Fatalf("managed conflict lost its code, cause or authored problem: %v", err)
		}
	}
	_, managedErr := owner.ConfigureService(ctx, web.ServiceId, controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP, PublisherPool: true, TrustRevision: web.TrustRevision})
	assertManaged(managedErr)
	assertManaged(owner.DeleteService(ctx, web.ServiceId))
	assertManaged(owner.RevokePublisherGrant(ctx, team, member.PublisherIdentityId, web.GrantId))
	_, managedErr = owner.CreatePublisherGrant(ctx, member.PublisherIdentityId, controlv1.CreatePublisherGrantRequest{TeamId: team, ServiceId: &web.ServiceId})
	assertManaged(managedErr)
	projection, err := owner.GetProjectPublicMetadata(ctx, team, "example")
	if err != nil || len(projection.Services) != 0 {
		t.Fatal("service leaked into public URL metadata", projection, err)
	}
	local, err := owner.RealizeLocalProjectService(ctx, "example", "local-app", controlv1.RealizeLocalProjectServiceRequest{TeamId: team, SourceFingerprint: body.SourceFingerprint, WorktreeKey: "checkout-a", Configuration: body.Configuration.Services["local-app"]})
	if err == nil || local.ServiceId != "" {
		t.Fatal("public realization accepted a missing exact public URL ID")
	}
	local, err = owner.RealizeLocalProjectService(ctx, "example", "local-private", controlv1.RealizeLocalProjectServiceRequest{TeamId: team, SourceFingerprint: body.SourceFingerprint, WorktreeKey: "checkout-a", Configuration: body.Configuration.Services["local-private"]})
	if err != nil || local.ServiceId == "" || local.Metadata == nil || local.Metadata.Protocol != controlv1.ServiceProtocolHTTP {
		t.Fatal("local realization wire lost its approved resource metadata", local, err)
	}
	lookup := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: body.SourceFingerprint, WorktreeKey: "checkout-a"}
	bound, err := owner.GetLocalProjectService(ctx, "example", "local-private", lookup)
	if err != nil || bound.ServiceId != local.ServiceId || bound.Metadata == nil || bound.Metadata.Protocol != local.Metadata.Protocol {
		t.Fatal("read-only wire lookup lost exact local identity", bound, err)
	}
	if _, err = anonymous.GetLocalProjectService(ctx, "example", "local-private", lookup); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous caller read local provenance", err)
	}
	lookup.SourceFingerprint = strings.Repeat("b", 64)
	if _, err = owner.GetLocalProjectService(ctx, "example", "local-private", lookup); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("wire lookup accepted a stale source fingerprint", err)
	}
	lookup.SourceFingerprint, lookup.WorktreeKey = body.SourceFingerprint, "checkout-missing"
	if _, err = owner.GetLocalProjectService(ctx, "example", "local-private", lookup); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("wire lookup fell back to another worktree", err)
	}
	device, err := owner.EnrollVisitorDevice(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	for index := range 2 {
		if _, err = d.RegisterIngress(ctx, controlstate.IngressRegistration{IngressID: fmt.Sprintf("release-http-%d", index), IngressRunID: fmt.Sprintf("release-http-run-%d", index), ProtocolVersion: 1, ConnectionCapacity: 1, ConnectorAddress: fmt.Sprintf("127.0.0.1:%d", 8400+index), ConnectorTLSServerName: "private.example.test"}, now, time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	sessions, err := owner.CreateVisitorIngressAssignments(ctx, local.ServiceId, device.Id, "startup")
	if err != nil || len(sessions) != 2 {
		t.Fatal("HTTP assignment setup failed", err)
	}
	if err = anonymous.ReleaseVisitorIngressAssignment(ctx, sessions[0].ConnectorSessionId); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous release succeeded", err)
	}
	for range 2 {
		if err = owner.ReleaseVisitorIngressAssignment(ctx, sessions[0].ConnectorSessionId); err != nil {
			t.Fatal("HTTP release not retry-stable", err)
		}
	}
	if _, err = d.GetVisitorIngressTransportTrust(ctx, session.Identity.Identity.ID, sessions[0].ConnectorSessionId, now); !errors.Is(err, controlstate.ErrServiceAccess) {
		t.Fatal("released assignment still authorized trust", err)
	}
	single, err := owner.CreateVisitorIngressAssignment(ctx, local.ServiceId, device.Id, sessions[1].IngressId, "renewal")
	if err != nil || single.IngressId != sessions[0].IngressId || single.Subject.DeviceId == nil || *single.Subject.DeviceId != device.Id || single.ServiceId != local.ServiceId {
		t.Fatal("single assignment wire required replacing its sibling", single, err)
	}
	if _, err = owner.CreateVisitorIngressAssignment(ctx, local.ServiceId, device.Id, sessions[1].IngressId, "over-capacity"); !errors.Is(err, clientcontrol.ErrUnavailable) {
		t.Fatal("single assignment overbooked pending capacity", err)
	}
	if err = owner.ReleaseVisitorIngressAssignment(ctx, single.ConnectorSessionId); err != nil {
		t.Fatal(err)
	}
	if _, err = anonymous.CreateVisitorIngressAssignment(ctx, local.ServiceId, device.Id, sessions[1].IngressId, "anonymous"); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("single assignment did not require a person session", err)
	}
	if len(assignments.Services) != 2 || web.Configuration.Target != "app.internal:3000" || web.GrantId == "" || web.TrustRevision != 1 || web.Configuration.TargetTls != nil {
		t.Fatalf("wire assignment: %+v", assignments)
	}
	if pub.ServiceKind != "service" || pub.Configuration.TargetTls == nil || pub.Configuration.TargetTls.Hostname != hostname || pub.Configuration.PublicUrl != nil || pub.Configuration.Http == nil || pub.Configuration.Http.Access.Mode == nil || *pub.Configuration.Http.Access.Mode != mode {
		t.Fatal("wire dropped service HTTP scope or target trust")
	}
	if pub.Configuration.Target != "192.0.2.5:8443" {
		t.Fatal("assigned wire configuration lost its target address")
	}
	if err = anonymous.AcknowledgePublisherGroupConfiguration(ctx, lease.AccessToken, controlv1.PublisherGroupAcknowledgement{Revision: assignments.Revision, ConfigurationHash: assignments.ConfigurationHash, Healthy: true}); err != nil {
		t.Fatal(err)
	}
	current, err := owner.GetProjectConfiguration(ctx, team, "example")
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Members) != 1 || current.Members[0].ObservedRevision != 1 || !current.Members[0].Healthy {
		t.Fatal("wire status lost acknowledgement")
	}
	if !current.Configuration.Oauth || len(current.Configuration.Webhooks) != 1 || current.Revision != 1 {
		t.Fatal("wire status lost root state or invalid metadata changed the revision")
	}
	// a group lease is not a person's session, and a session is not a group lease.
	if _, err = anonymous.GetPublisherGroupAssignments(ctx, session.AccessToken.String()); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("person session accepted as group lease", err)
	}
	groupAsPerson, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(lease.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = groupAsPerson.GetProjectConfiguration(ctx, team, "example"); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("group read manager configuration", err)
	}
	if _, err = groupAsPerson.CreateVisitorIngressAssignment(ctx, local.ServiceId, device.Id, "", "group-as-person"); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("group lease created a person assignment", err)
	}
	if err = groupAsPerson.RevokePublisherGroupMember(ctx, team, "example", group, member.PublisherIdentityId); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("group lease revoked a member as a person", err)
	}
	namespaceRequest := controlv1.RenamePublisherNamespaceRequest{TeamId: team, NamespaceLabel: "live", ExpectedRevision: current.Revision, IdempotencyKey: "namespace-http"}
	for _, client := range []*clientcontrol.Client{anonymous, groupAsPerson} {
		if _, err := client.RenamePublisherNamespace(ctx, "example", group, namespaceRequest); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
			t.Fatal("namespace mutation accepted non-manager credentials", err)
		}
	}
	renamed, err := owner.RenamePublisherNamespace(ctx, "example", group, namespaceRequest)
	if err != nil || renamed.Revision != current.Revision+1 {
		t.Fatal("namespace POST failed", err)
	}
	retry, err := owner.RenamePublisherNamespace(ctx, "example", group, namespaceRequest)
	a, _ := json.Marshal(renamed)
	b, _ := json.Marshal(retry)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("namespace POST reply was not exact", err)
	}
	namespaceRequest.NamespaceLabel = "different"
	if _, err := owner.RenamePublisherNamespace(ctx, "example", group, namespaceRequest); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("namespace POST key accepted changed body", err)
	}
	if err = owner.RevokePublisherGroupMember(ctx, team, "example", group, member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	if _, err = anonymous.GetPublisherGroupAssignments(ctx, lease.AccessToken); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("revoked group member retained HTTP lease", err)
	}
}
