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

var testProjectSource = controlv1.GitProjectSource{GitOrigin: "https://example.test/example.git", ConfigurationPath: "tnl.yml"}

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
	h, err := NewHandler(Config{ControlURL: server.URL, ManagedURLMode: naming.ManagedURLModeSimple}, DatabaseStores(d), d, nil)
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
	if _, err := anonymous.ResolveProjectSource(ctx, testProjectSource); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous source resolution", err)
	}
	resolved, err := owner.ResolveProjectSource(ctx, testProjectSource)
	if err != nil || resolved.SourceFingerprint != "a4c232311b1a5083342e81207d920e296029c9181e4a45f9f3492a13216aa45c" {
		t.Fatal("source resolution changed the existing identity algorithm", err)
	}
	project := resolved.ProjectKey
	if before, err := owner.ListProjects(ctx, controlv1.ListProjectsParams{TeamId: team}); err != nil || len(before.Projects) != 0 {
		t.Fatal("source resolution created project state", err)
	}
	body := controlv1.ApplyProjectConfigurationRequest{TeamId: team, Source: &testProjectSource, ExpectedRevision: 0, Configuration: controlv1.ProjectConfiguration{PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {}}, Services: map[string]controlv1.ProjectServiceConfiguration{"web": {PublisherGroup: &group, Target: "http://app.internal:3000"}}}}
	body.Configuration.Oauth = true
	body.Configuration.Services["local-app"] = controlv1.ProjectServiceConfiguration{Target: "app", PublicUrl: &controlv1.ProjectServicePublicURL{}}
	body.Configuration.Services["local-private"] = controlv1.ProjectServiceConfiguration{Target: "app"}
	body.Configuration.Webhooks = map[string]controlv1.ProjectWebhook{"payments": {Service: "local-app", Path: "/hooks/payments", Provider: controlv1.Custom}}
	name, hostname, mode := "website", "upstream.internal", controlv1.Restricted
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + hostname + "\x00"))
	body.Configuration.Services["public"] = controlv1.ProjectServiceConfiguration{PublisherGroup: &group, Name: &name, Target: "https://192.0.2.5:8443", TargetTls: &controlv1.ProjectTargetTLS{Hostname: hostname, Digest: hex.EncodeToString(digest[:])}, Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectPublicAccess{Mode: &mode}}}
	if _, err = anonymous.ApplyProjectConfiguration(ctx, project, body); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous desired-state mutation", err)
	}
	applied, err := owner.ApplyProjectConfiguration(ctx, project, body)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Revision != 1 || len(applied.Services) != 4 || !applied.Configuration.Oauth || len(applied.Configuration.Webhooks) != 1 {
		t.Fatalf("wire configuration: %+v", applied)
	}
	if applied.Configuration.Services["public"].TargetTls.Digest != hex.EncodeToString(digest[:]) {
		t.Fatal("control did not return the derived project trust digest")
	}
	// another session can discover and read the project without any local state.
	second, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := clientcontrol.New(server.URL, server.Client(), second.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	page, err := reader.ListProjects(ctx, controlv1.ListProjectsParams{TeamId: team})
	if err != nil || len(page.Projects) != 1 || page.Projects[0].ProjectKey != project || page.Projects[0].Revision != 1 {
		t.Fatal("project discovery lost its usable selector", page, err)
	}
	discovered, err := reader.GetProjectConfiguration(ctx, page.Projects[0].TeamId, page.Projects[0].ProjectKey)
	if err != nil || discovered.Groups == nil || len(*discovered.Groups) != 1 || (*discovered.Groups)[0].Id == "" {
		t.Fatal("discovered selector did not resolve group detail", err)
	}
	replay := controlv1.ApplyProjectConfigurationRequest{TeamId: team, Configuration: discovered.Configuration}
	if result, err := reader.ApplyProjectConfiguration(ctx, project, replay); err != nil || result.Revision != discovered.Revision || result.SourceFingerprint != resolved.SourceFingerprint {
		t.Fatal("same-content replay required a caller fingerprint or changed the saved source", err)
	}
	changed := replay.Configuration.Services["web"]
	changed.Target = "different.internal:3000"
	replay.Configuration.Services["web"] = changed
	if _, err := reader.ApplyProjectConfiguration(ctx, project, replay); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("different configuration accepted a stale revision", err)
	}
	otherSource := testProjectSource
	otherSource.ConfigurationPath = "another/tnl.yml"
	replay.Source = &otherSource
	if _, err := reader.ApplyProjectConfiguration(ctx, project, replay); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("apply rebound the saved project to another source", err)
	}
	if _, err = reader.ListProjects(ctx, controlv1.ListProjectsParams{TeamId: "team_other"}); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("project discovery crossed teams", err)
	}
	if _, err = anonymous.ListProjects(ctx, controlv1.ListProjectsParams{TeamId: team}); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("project discovery accepted anonymous access", err)
	}
	preview, err := owner.CreatePreview(ctx, team, "discovery-preview")
	if err != nil {
		t.Fatal(err)
	}
	previews, err := reader.ListPreviews(ctx, controlv1.ListPreviewsParams{TeamId: team})
	if err != nil || len(previews.Previews) != 1 || previews.Previews[0].Id != preview.Id {
		t.Fatal("creator preview was not discoverable from another session", err)
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
	missingReply, err := rawAPI.ApplyProjectConfigurationWithBodyWithResponse(ctx, project, "application/json", bytes.NewReader(missingBytes), auth)
	if err != nil || missingReply.StatusCode() != 400 {
		t.Fatal("content replay accepted a missing expected_revision", err)
	}
	missing["expected_revision"] = 0
	missing["source_fingerprint"] = resolved.SourceFingerprint
	legacyBytes, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	legacyReply, err := rawAPI.ApplyProjectConfigurationWithBodyWithResponse(ctx, project, "application/json", bytes.NewReader(legacyBytes), auth)
	if err != nil || legacyReply.StatusCode() != 400 {
		t.Fatal("apply still accepted the retired caller fingerprint field", err)
	}
	delete(missing, "source_fingerprint")
	missing["configuration"].(map[string]any)["services"].(map[string]any)["public"].(map[string]any)["target_tls"].(map[string]any)["digest"] = strings.Repeat("f", 64)
	forgedBytes, err := json.Marshal(missing)
	if err != nil {
		t.Fatal(err)
	}
	forgedReply, err := rawAPI.ApplyProjectConfigurationWithBodyWithResponse(ctx, project, "application/json", bytes.NewReader(forgedBytes), auth)
	if err != nil || forgedReply.StatusCode() != 400 {
		t.Fatal("apply accepted a forged trust digest", err)
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
	unknownReply, err := rawAPI.ApplyProjectConfigurationWithBodyWithResponse(ctx, project, "application/json", bytes.NewReader(unknownBytes), auth)
	if err != nil || unknownReply.StatusCode() != 400 || bytes.Contains(unknownReply.Body, []byte(secret)) {
		t.Fatal("webhook source secret was accepted or exposed", err)
	}
	enrollment, err := owner.CreatePublisherGroupEnrollment(ctx, project, group, controlv1.CreatePublisherGroupEnrollmentRequest{TeamId: team, MaxMembers: 2, ExpiresIn: 600})
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
	proof, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.GroupId, server.URL+"/v1/publisher/groups/lease", private, now)
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
	_, managedErr := owner.ConfigureService(ctx, web.ServiceId, controlv1.UpdateServiceRequest{Protocol: controlv1.ServiceProtocolHTTP, PublisherPool: true, ExpectedTrustRevision: web.TrustRevision})
	assertManaged(managedErr)
	assertManaged(owner.DeleteService(ctx, web.ServiceId))
	assertManaged(owner.RevokePublisherGrant(ctx, team, member.PublisherIdentityId, web.GrantId))
	_, managedErr = owner.CreatePublisherGrant(ctx, member.PublisherIdentityId, controlv1.CreatePublisherGrantRequest{TeamId: team, ServiceId: &web.ServiceId})
	assertManaged(managedErr)
	projection, err := owner.GetProjectPublicMetadata(ctx, team, project)
	if err != nil || len(projection.Services) != 0 {
		t.Fatal("service leaked into public URL metadata", projection, err)
	}
	local, err := owner.RealizeLocalProjectService(ctx, project, "local-app", controlv1.RealizeLocalProjectServiceRequest{TeamId: team, SourceFingerprint: applied.SourceFingerprint, WorktreeKey: "checkout-a", Configuration: body.Configuration.Services["local-app"]})
	if err == nil || local.ServiceId != "" {
		t.Fatal("public realization accepted a missing exact public URL ID")
	}
	local, err = owner.RealizeLocalProjectService(ctx, project, "local-private", controlv1.RealizeLocalProjectServiceRequest{TeamId: team, SourceFingerprint: applied.SourceFingerprint, WorktreeKey: "checkout-a", Configuration: body.Configuration.Services["local-private"]})
	if err != nil || local.ServiceId == "" || local.Metadata == nil || local.Metadata.Protocol != controlv1.ServiceProtocolHTTP {
		t.Fatal("local realization wire lost its approved resource metadata", local, err)
	}
	lookup := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: applied.SourceFingerprint, WorktreeKey: "checkout-a"}
	bound, err := owner.GetLocalProjectService(ctx, project, "local-private", lookup)
	if err != nil || bound.ServiceId != local.ServiceId || bound.Metadata == nil || bound.Metadata.Protocol != local.Metadata.Protocol {
		t.Fatal("read-only wire lookup lost exact local identity", bound, err)
	}
	if _, err = anonymous.GetLocalProjectService(ctx, project, "local-private", lookup); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous caller read local provenance", err)
	}
	lookup.SourceFingerprint = strings.Repeat("b", 64)
	if _, err = owner.GetLocalProjectService(ctx, project, "local-private", lookup); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("wire lookup accepted a stale source fingerprint", err)
	}
	lookup.SourceFingerprint, lookup.WorktreeKey = applied.SourceFingerprint, "checkout-missing"
	if _, err = owner.GetLocalProjectService(ctx, project, "local-private", lookup); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("wire lookup fell back to another worktree", err)
	}
	device, err := owner.EnrollVisitorDevice(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = anonymous.SelectServiceRun(ctx, local.ServiceId, device.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("native signing snapshot did not require a person session", err)
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
	current, err := owner.GetProjectConfiguration(ctx, team, project)
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
	if _, err = groupAsPerson.GetProjectConfiguration(ctx, team, project); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("group read manager configuration", err)
	}
	if _, err = groupAsPerson.SelectServiceRun(ctx, local.ServiceId, device.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("group lease selected a person's native run", err)
	}
	if err = groupAsPerson.RevokePublisherGroupMember(ctx, team, project, group, member.PublisherIdentityId); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("group lease revoked a member as a person", err)
	}
	namespaceRequest := controlv1.RenamePublisherNamespaceRequest{TeamId: team, NamespaceLabel: "live", ExpectedRevision: current.Revision, IdempotencyKey: "namespace-http"}
	for _, client := range []*clientcontrol.Client{anonymous, groupAsPerson} {
		if _, err := client.RenamePublisherNamespace(ctx, project, group, namespaceRequest); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
			t.Fatal("namespace mutation accepted non-manager credentials", err)
		}
	}
	renamed, err := owner.RenamePublisherNamespace(ctx, project, group, namespaceRequest)
	if err != nil || renamed.Revision != current.Revision+1 {
		t.Fatal("namespace POST failed", err)
	}
	retry, err := owner.RenamePublisherNamespace(ctx, project, group, namespaceRequest)
	a, _ := json.Marshal(renamed)
	b, _ := json.Marshal(retry)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("namespace POST reply was not exact", err)
	}
	namespaceRequest.NamespaceLabel = "different"
	if _, err := owner.RenamePublisherNamespace(ctx, project, group, namespaceRequest); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("namespace POST key accepted changed body", err)
	}
	if err = owner.RevokePublisherGroupMember(ctx, team, project, group, member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	if _, err = anonymous.GetPublisherGroupAssignments(ctx, lease.AccessToken); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("revoked group member retained HTTP lease", err)
	}
}
