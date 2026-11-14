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
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
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
	if err := d.ConfigureIngressServicePorts(ctx, controlstate.PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
		t.Fatal(err)
	}
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
	deployment := "production"
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
	body := controlv1.ApplyProjectConfigurationRequest{TeamId: team, Source: &testProjectSource, ExpectedRevision: 0, Configuration: controlv1.ProjectConfiguration{Settings: &controlv1.DeploymentSettings{}, Services: map[string]controlv1.ProjectServiceConfiguration{"web": {Target: "http://app.internal:3000"}}}}
	body.Configuration.Oauth = true
	body.Configuration.Services["local-app"] = controlv1.ProjectServiceConfiguration{Target: "app", PublicUrl: &controlv1.ProjectServicePublicURL{}}
	body.Configuration.Services["local-private"] = controlv1.ProjectServiceConfiguration{Target: "app"}
	body.Configuration.Webhooks = map[string]controlv1.ProjectWebhook{"payments": {Service: "local-app", Path: "/hooks/payments", Provider: controlv1.Custom}}
	name, hostname, mode := "website", "upstream.internal", controlv1.Restricted
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + hostname + "\x00"))
	body.Configuration.Services["public"] = controlv1.ProjectServiceConfiguration{Name: &name, Public: new(true), Target: "https://192.0.2.5:8443", TargetTls: &controlv1.ProjectTargetTLS{Hostname: hostname, Digest: hex.EncodeToString(digest[:])}, Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectPublicAccess{Mode: &mode}}}
	body.Deployment = deployment
	body.ServiceDeclarations = controlv1.ProjectServiceDeclarations{"web": "http", "public": "http", "local-app": "http", "local-private": "http"}
	localBody := body
	localBody.Deployment = "local"
	localBody.Configuration = controlv1.ProjectConfiguration{Oauth: true, Webhooks: body.Configuration.Webhooks, Services: map[string]controlv1.ProjectServiceConfiguration{"local-app": body.Configuration.Services["local-app"], "local-private": body.Configuration.Services["local-private"]}}
	body.Configuration.Oauth = false
	body.Configuration.Webhooks = map[string]controlv1.ProjectWebhook{}
	delete(body.Configuration.Services, "local-app")
	delete(body.Configuration.Services, "local-private")
	if _, err = anonymous.ApplyProjectConfiguration(ctx, project, body); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous desired-state mutation", err)
	}
	localApplied, err := owner.ApplyProjectConfiguration(ctx, project, localBody)
	if err != nil || !localApplied.Configuration.Oauth || len(localApplied.Configuration.Webhooks) != 1 || len(localApplied.Services) != 2 {
		t.Fatal("local wire configuration lost integration declarations", localApplied, err)
	}
	body.ExpectedRevision = localApplied.Revision
	applied, err := owner.ApplyProjectConfiguration(ctx, project, body)
	if err != nil {
		t.Fatal(err)
	}
	if applied.Revision != 2 || len(applied.Services) != 2 || applied.Configuration.Oauth || len(applied.Configuration.Webhooks) != 0 {
		t.Fatalf("wire configuration: %+v", applied)
	}
	if applied.Configuration.Services["public"].TargetTls.Digest != hex.EncodeToString(digest[:]) {
		t.Fatal("control did not return the derived project trust digest")
	}
	for _, service := range applied.Services {
		wantPublic := service.Service == "public"
		public := service.Public != nil && *service.Public
		if public != wantPublic || wantPublic && (service.Port == nil || *service.Port != 25443) || !wantPublic && service.Port != nil && *service.Port != 0 {
			t.Fatal("wire per-service exposure allocated or exposed another binding", service)
		}
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
	if err != nil || len(page.Projects) != 1 || page.Projects[0].ProjectKey != project || page.Projects[0].Revision != 2 {
		t.Fatal("project discovery lost its usable selector", page, err)
	}
	discovered, err := reader.GetProjectConfiguration(ctx, page.Projects[0].TeamId, page.Projects[0].ProjectKey, deployment)
	if err != nil || discovered.Deployments == nil || len(*discovered.Deployments) != 1 || (*discovered.Deployments)[0].Id == "" {
		t.Fatal("discovered selector did not resolve deployment detail", err)
	}
	status, err := reader.GetProjectStatus(ctx, project, controlv1.GetProjectStatusParams{TeamId: team})
	if err != nil || status.Revision != discovered.Revision || len(status.Publications) != 4 {
		t.Fatal("HTTP project status lost declarations", status, err)
	}
	if _, err = anonymous.GetProjectStatus(ctx, project, controlv1.GetProjectStatusParams{TeamId: team}); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("project status accepted anonymous access", err)
	}
	if _, err = reader.GetProjectStatus(ctx, project, controlv1.GetProjectStatusParams{TeamId: "other-team"}); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("project status crossed teams", err)
	}
	replay := controlv1.ApplyProjectConfigurationRequest{TeamId: team, Deployment: deployment, ServiceDeclarations: discovered.ServiceDeclarations, Configuration: discovered.Configuration}
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
	endpoint := localApplied.Configuration.Webhooks["payments"]
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
	for _, nested := range []bool{false, true} {
		var invalid map[string]any
		if err := json.Unmarshal(encoded, &invalid); err != nil {
			t.Fatal(err)
		}
		configuration := invalid["configuration"].(map[string]any)
		if nested {
			configuration["services"].(map[string]any)["web"].(map[string]any)["unknown"] = true
		} else {
			configuration["unknown"] = true
		}
		data, err := json.Marshal(invalid)
		if err != nil {
			t.Fatal(err)
		}
		response, err := rawAPI.ApplyProjectConfigurationWithBodyWithResponse(ctx, project, "application/json", bytes.NewReader(data), auth)
		if err != nil || response.StatusCode() != http.StatusBadRequest {
			t.Fatal("apply accepted an unknown field", nested, err)
		}
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
	missing["expected_revision"] = "0"
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
	localEncoded, err := json.Marshal(localBody)
	if err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal(localEncoded, &unknown); err != nil {
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
	enrollment, err := owner.CreateDeploymentPublisherEnrollment(ctx, team, project, deployment, "http-contract-enrollment", controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{"web", "public"}, MaxMembers: new(2), ExpiresIn: new(600)})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := anonymous.RedeemDeploymentPublisherEnrollment(ctx, enrollment.EnrollmentKey, public)
	if err != nil {
		t.Fatal(err)
	}
	if member.DeploymentId != enrollment.DeploymentId || member.DeploymentName != deployment {
		t.Fatal("enrollment changed deployment scope")
	}
	proof, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.DeploymentId, server.URL+"/v1/publisher/deployments/lease", private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := anonymous.AcquireDeploymentPublisherLease(ctx, controlv1.DeploymentPublisherLeaseRequest{PublisherIdentityId: member.PublisherIdentityId, DeploymentId: member.DeploymentId, Assertion: proof})
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := anonymous.GetDeploymentPublisherAssignments(ctx, lease.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	byService := map[string]controlv1.DeploymentPublisherServiceAssignment{}
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
	if err != nil || len(projection.Services) != 1 {
		t.Fatal("public metadata omitted the public binding or leaked private bindings", projection, err)
	}
	projected := projection.Services[0]
	if projected.Service != "public" || projected.ServiceId == nil || *projected.ServiceId != pub.ServiceId || projected.PublicUrlId != nil || projected.Port != 25443 {
		t.Fatal("public service projection changed resource identity or port", projected)
	}
	local, err := owner.RealizeLocalProjectService(ctx, project, "local-app", controlv1.RealizeLocalProjectServiceRequest{TeamId: team, SourceFingerprint: applied.SourceFingerprint, WorktreeKey: "checkout-a", Configuration: localBody.Configuration.Services["local-app"]})
	if err == nil || local.ServiceId != "" {
		t.Fatal("public realization accepted a missing exact public URL ID")
	}
	local, err = owner.RealizeLocalProjectService(ctx, project, "local-private", controlv1.RealizeLocalProjectServiceRequest{TeamId: team, SourceFingerprint: applied.SourceFingerprint, WorktreeKey: "checkout-a", Configuration: localBody.Configuration.Services["local-private"]})
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
	if err = anonymous.AcknowledgeDeploymentPublisherConfiguration(ctx, lease.AccessToken, controlv1.DeploymentPublisherAcknowledgement{Revision: assignments.Revision, ConfigurationHash: assignments.ConfigurationHash, Healthy: true}); err != nil {
		t.Fatal(err)
	}
	current, err := owner.GetProjectConfiguration(ctx, team, project, deployment)
	if err != nil {
		t.Fatal(err)
	}
	if len(current.Members) != 1 || current.Members[0].ObservedRevision != 1 || !current.Members[0].Healthy {
		t.Fatal("wire status lost acknowledgement")
	}
	if current.Configuration.Oauth || len(current.Configuration.Webhooks) != 0 || current.Revision != applied.Revision {
		t.Fatal("remote wire status borrowed local state or invalid metadata changed the revision")
	}
	localStatus, err := owner.GetProjectConfiguration(ctx, team, project, "local")
	if err != nil || !localStatus.Configuration.Oauth || len(localStatus.Configuration.Webhooks) != 1 || localStatus.Revision != current.Revision {
		t.Fatal("remote apply changed local root state", localStatus, err)
	}
	// a publisher lease is not a person's session, and a session is not a publisher lease.
	if _, err = anonymous.GetDeploymentPublisherAssignments(ctx, session.AccessToken.String()); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("person session accepted as publisher lease", err)
	}
	publisherAsPerson, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(lease.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = publisherAsPerson.GetProjectConfiguration(ctx, team, project, deployment); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("publisher read manager configuration", err)
	}
	if _, err = publisherAsPerson.SelectServiceRun(ctx, local.ServiceId, device.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("publisher lease selected a person's native run", err)
	}
	if err = publisherAsPerson.RevokeDeploymentPublisher(ctx, team, project, deployment, member.PublisherIdentityId); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("publisher lease revoked a member as a person", err)
	}
	namespaceRequest := controlv1.RenameDeploymentNamespaceRequest{TeamId: team, NamespaceLabel: "live", ExpectedRevision: current.Revision, IdempotencyKey: "namespace-http"}
	for _, client := range []*clientcontrol.Client{anonymous, publisherAsPerson} {
		if _, err := client.RenameDeploymentNamespace(ctx, project, deployment, namespaceRequest); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
			t.Fatal("namespace mutation accepted non-manager credentials", err)
		}
	}
	renamed, err := owner.RenameDeploymentNamespace(ctx, project, deployment, namespaceRequest)
	if err != nil || renamed.Revision != current.Revision+1 {
		t.Fatal("namespace POST failed", err)
	}
	retry, err := owner.RenameDeploymentNamespace(ctx, project, deployment, namespaceRequest)
	a, _ := json.Marshal(renamed)
	b, _ := json.Marshal(retry)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("namespace POST reply was not exact", err)
	}
	namespaceRequest.NamespaceLabel = "different"
	if _, err := owner.RenameDeploymentNamespace(ctx, project, deployment, namespaceRequest); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("namespace POST key accepted changed body", err)
	}
	if err = owner.RevokeDeploymentPublisher(ctx, team, project, deployment, member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	if _, err = anonymous.GetDeploymentPublisherAssignments(ctx, lease.AccessToken); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("revoked deployment publisher retained HTTP lease", err)
	}
	retirement := controlv1.RetireProjectJSONRequestBody{TeamId: team, ExpectedRevision: renamed.Revision}
	if _, err = anonymous.RetireProject(ctx, project, retirement); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous project retirement", err)
	}
	retired, err := owner.RetireProject(ctx, project, retirement)
	if err != nil || retired.RetiredAt == nil || retired.Revision != renamed.Revision+1 || len(retired.Services) != 0 {
		t.Fatal("HTTP retirement lost its revision or retained resources", retired, err)
	}
	if retry, err := owner.RetireProject(ctx, project, retirement); err != nil || retry.Revision != retired.Revision {
		t.Fatal("HTTP retirement retry changed state", retry, err)
	}
	if page, err := owner.ListProjects(ctx, controlv1.ListProjectsParams{TeamId: team}); err != nil || len(page.Projects) != 0 {
		t.Fatal("retired HTTP project remained discoverable", page, err)
	}
	if detail, err := owner.GetProjectConfiguration(ctx, team, project, "local"); err != nil || detail.RetiredAt == nil || detail.SourceFingerprint != resolved.SourceFingerprint {
		t.Fatal("retired HTTP project lost source identity", detail, err)
	}
	if _, err := owner.RetireProject(ctx, "missing", retirement); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("retiring a missing project did not return not found", err)
	}
}
