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
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// retained fixtures create saved resources through the real canonical HTTP API.
// they never reconcile a project or infer grants from a definition.
func retainedHTTPEnvironment(t *testing.T, owner *clientcontrol.Client, team, project, name string, services map[string]controlv1.ServiceDefinitionService, targets controlv1.EnvironmentTargets) controlv1.Environment {
	t.Helper()
	definition, err := owner.CreateServiceDefinition(t.Context(), project, controlv1.CreateServiceDefinitionRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Definition: controlv1.ServiceDefinition{Services: services}})
	if err != nil {
		t.Fatal("create service definition", err)
	}
	environment, err := owner.CreateEnvironment(t.Context(), project, controlv1.CreateEnvironmentRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Name: name, DefinitionRevision: &definition.Revision, Targets: targets, IdempotencyKey: "create/" + name})
	if err != nil {
		t.Fatal("create environment", err)
	}
	return environment
}

func retainedHTTPEnrollment(t *testing.T, owner *clientcontrol.Client, environment controlv1.Environment, services []string, members int) controlv1.EnvironmentPublisherEnrollment {
	t.Helper()
	enrollment, err := owner.CreateEnvironmentPublisherEnrollment(t.Context(), environment.ProjectKey, environment.Id, "", controlv1.CreateEnvironmentPublisherEnrollmentRequest{TeamId: environment.TeamId, ExpectedRevision: environment.MutationRevision, ConfigurationHash: environment.ConfigurationHash, Services: services, MaxMembers: members, ExpiresIn: 600})
	if err != nil {
		t.Fatal("issue exact environment enrollment", err)
	}
	return enrollment
}

func assertRetainedHTTPRemoved(t *testing.T, client *http.Client, server, token, method, path string) {
	t.Helper()
	r, err := http.NewRequestWithContext(t.Context(), method, server+path, strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusNotFound || bytes.Contains(body, []byte(token)) {
		t.Fatal("retired endpoint remained available or leaked credentials", method, path, response.StatusCode, err)
	}
}

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
	definition := controlv1.CreateServiceDefinitionRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Definition: controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"web": {Protocol: "http"}, "public": {Protocol: "http"}}}}
	if _, err := anonymous.CreateServiceDefinition(ctx, "example", definition); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous desired-state mutation", err)
	}
	hostname, mode := "upstream.internal", controlv1.Restricted
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00" + hostname + "\x00"))
	environment := retainedHTTPEnvironment(t, owner, team, "example", "production", definition.Definition.Services, controlv1.EnvironmentTargets{
		"web":    {Address: new("http://app.internal:3000")},
		"public": {Address: new("https://192.0.2.5:8443"), Tls: &controlv1.EnvironmentTargetTLS{Hostname: &hostname, Digest: new(hex.EncodeToString(digest[:]))}, Http: &controlv1.EnvironmentServiceHTTP{Access: &controlv1.ProjectPublicAccess{Mode: &mode}}},
	})
	if environment.MutationRevision != 1 || len(environment.Services) != 2 {
		t.Fatal("wire environment lost saved services")
	}
	rawAPI, err := controlv1.NewClientWithResponses(server.URL, controlv1.WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	auth := func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	}
	missing, err := rawAPI.ApplyEnvironmentWithBodyWithResponse(ctx, "example", environment.Id, "application/json", strings.NewReader(`{"team_id":"`+team+`","definition_revision":1}`), auth)
	if err != nil || missing.StatusCode() != 400 {
		t.Fatal("content replay accepted missing expected_revision", err)
	}
	// the remote root-declaration wire is retired. actual local integration
	// declaration/default/secret assertions run at its surviving owner below.
	for _, extra := range []string{`"oauth":true`, `"webhooks":{"payments":{"service":"web","path":"/hooks/payments","provider":"custom"}}`} {
		body := `{"team_id":"` + team + `","source_fingerprint":"` + definition.SourceFingerprint + `","definition":{"services":{"web":{"protocol":"http"}},` + extra + `}}`
		reply, err := rawAPI.CreateServiceDefinitionWithBodyWithResponse(ctx, "example", "application/json", strings.NewReader(body), auth)
		if err != nil || reply.StatusCode() != 400 {
			t.Fatal("definition accepted retired integration state", err)
		}
	}
	t.Run("local integration declarations and URL purposes", func(t *testing.T) {
		exerciseRetainedLocalIntegrationDeclarations(t, owner, d, session, server.URL)
	})
	enrollment := retainedHTTPEnrollment(t, owner, environment, []string{"web", "public"}, 2)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	member, err := anonymous.RedeemEnvironmentPublisherEnrollment(ctx, enrollment.EnrollmentKey, public)
	if err != nil || member.EnvironmentId != environment.Id || enrollment.Ref != environment.Ref {
		t.Fatal("enrollment changed environment scope", err)
	}
	proof, err := publisherproof.Sign(member.PublisherIdentityId, member.KeyId, member.EnvironmentId, server.URL+"/v1/environment-publishers/lease", private, now)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := anonymous.AcquireEnvironmentPublisherLease(ctx, controlv1.EnvironmentPublisherProof{PublisherIdentityId: member.PublisherIdentityId, EnvironmentId: member.EnvironmentId, Assertion: proof})
	if err != nil {
		t.Fatal(err)
	}
	assignments, err := anonymous.GetEnvironmentPublisherAssignments(ctx, lease.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := rawAPI.GetEnvironmentPublisherAssignmentsWithResponse(ctx, func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+lease.AccessToken)
		return nil
	})
	if err != nil || wire.JSON200 == nil || wire.HTTPResponse.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("read canonical assignment envelope", err)
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(wire.Body, &envelope); err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"publisher", "environment", "services", "certificate_state_plans"} {
		if len(envelope[required]) == 0 || string(envelope[required]) == "null" {
			t.Fatal("assignment envelope omitted required facts", required)
		}
	}
	var wireServices []map[string]json.RawMessage
	if err := json.Unmarshal(envelope["services"], &wireServices); err != nil {
		t.Fatal(err)
	}
	for _, service := range wireServices {
		for _, retired := range []string{"service_kind", "environment", "public_url_id"} {
			if _, found := service[retired]; found {
				t.Fatal("assignment retained a retired public URL or per-service environment shape", retired)
			}
		}
		var configuration map[string]json.RawMessage
		if err := json.Unmarshal(service["configuration"], &configuration); err != nil {
			t.Fatal("assignment omitted its publication configuration", err)
		}
		if _, found := configuration["public_url"]; found {
			t.Fatal("saved service assignment exposed nested public URL configuration")
		}
	}
	savedIDs := map[string]string{}
	for _, service := range environment.Services {
		savedIDs[service.Service] = service.ServiceId
	}
	byService := map[string]controlv1.EnvironmentPublisherAssignment{}
	for _, assignment := range assignments.Services {
		if assignment.ServiceId != savedIDs[assignment.Service] || assignment.ServiceId == "" || assignment.GrantId == "" || assignment.TrustRevision < 1 || assignment.Configuration.Protocol == "" || assignment.Configuration.Target == "" {
			t.Fatal("assignment did not name a saved service and complete publication facts")
		}
		byService[assignment.Service] = assignment
	}
	web, pub := byService["web"], byService["public"]
	assertManaged := func(err error) {
		t.Helper()
		var problem *clientcontrol.ProblemError
		if !errors.Is(err, clientcontrol.ErrProjectManaged) || !errors.Is(err, clientcontrol.ErrStatusConflict) || !errors.As(err, &problem) || problem.Status != 409 || problem.Problem.Code != controlv1.ProjectManaged || problem.Problem.RequestId == "" || problem.Problem.Detail != "resource is managed by project configuration; change the declaration and run tnl apply" {
			t.Fatalf("managed conflict lost HTTP problem: %v", err)
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
		t.Fatal("environment service leaked into public URL metadata", err)
	}
	localRequest := controlv1.RealizeLocalProjectServiceRequest{TeamId: team, SourceFingerprint: definition.SourceFingerprint, WorktreeKey: "checkout-a", Configuration: controlv1.LocalServiceDeclaration{Target: "app", PublicUrl: &controlv1.ProjectServicePublicURL{}}}
	local, err := owner.RealizeLocalProjectService(ctx, "example", "local-app", localRequest)
	if err == nil || local.ServiceId != "" {
		t.Fatal("public realization accepted missing exact public URL ID")
	}
	localRequest.Configuration.PublicUrl = nil
	local, err = owner.RealizeLocalProjectService(ctx, "example", "local-private", localRequest)
	if err != nil || local.ServiceId == "" || local.Metadata == nil || local.Metadata.Protocol != controlv1.ServiceProtocolHTTP {
		t.Fatal("local realization lost approved metadata", err)
	}
	lookup := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: definition.SourceFingerprint, WorktreeKey: "checkout-a"}
	bound, err := owner.GetLocalProjectService(ctx, "example", "local-private", lookup)
	if err != nil || bound.ServiceId != local.ServiceId || bound.Metadata == nil || bound.Metadata.Protocol != local.Metadata.Protocol {
		t.Fatal("lookup lost exact local identity", err)
	}
	if _, err := anonymous.GetLocalProjectService(ctx, "example", "local-private", lookup); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("anonymous read local provenance", err)
	}
	lookup.SourceFingerprint = strings.Repeat("b", 64)
	if _, err := owner.GetLocalProjectService(ctx, "example", "local-private", lookup); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("lookup accepted stale source", err)
	}
	lookup.SourceFingerprint, lookup.WorktreeKey = definition.SourceFingerprint, "checkout-missing"
	if _, err := owner.GetLocalProjectService(ctx, "example", "local-private", lookup); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("lookup fell back to another worktree", err)
	}
	device, err := owner.EnrollVisitorDevice(ctx, public)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anonymous.SelectServiceRun(ctx, local.ServiceId, device.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("signing snapshot did not require person session", err)
	}
	if len(assignments.Services) != 2 || assignments.Publisher != member || assignments.Environment.EnvironmentId != environment.Id || assignments.Environment.MutationRevision != 1 || assignments.Environment.ConfigurationHash != environment.ConfigurationHash || web.Configuration.Protocol != "http" || web.Configuration.Target != "app.internal:3000" || web.GrantId == "" || web.TrustRevision != 1 || web.Configuration.TargetTls != nil {
		t.Fatal("wire assignment lost exact publication facts")
	}
	if pub.Configuration.Protocol != "http" || pub.Configuration.TargetTls == nil || pub.Configuration.TargetTls.Hostname != hostname || pub.Configuration.Http == nil || pub.Configuration.Http.Access == nil || pub.Configuration.Http.Access.Mode == nil || *pub.Configuration.Http.Access.Mode != mode || pub.Configuration.Target != "192.0.2.5:8443" {
		t.Fatal("wire dropped HTTP scope or target trust")
	}
	if err := anonymous.AcknowledgeEnvironmentPublisher(ctx, lease.AccessToken, controlv1.EnvironmentPublisherAcknowledgement{Environment: assignments.Environment, Healthy: true}); err != nil {
		t.Fatal(err)
	}
	members, err := owner.ListEnvironmentPublishers(ctx, team, "example", environment.Id)
	if err != nil || len(members) != 1 || members[0].ObservedRevision != 1 || !members[0].Healthy {
		t.Fatal("status lost acknowledgement", err)
	}
	if _, err := anonymous.GetEnvironmentPublisherAssignments(ctx, session.AccessToken.String()); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("person session accepted as publisher lease", err)
	}
	publisherAsPerson, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(lease.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := publisherAsPerson.GetEnvironment(ctx, team, "example", environment.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("replica read manager targets", err)
	}
	if _, err := publisherAsPerson.SelectServiceRun(ctx, local.ServiceId, device.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("replica selected person's native run", err)
	}
	if err := publisherAsPerson.RevokeEnvironmentPublisher(ctx, team, "example", environment.Id, member.PublisherIdentityId); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("replica revoked a publisher as manager", err)
	}
	// stable endpoint scope no longer has a separately mutable publisher namespace.
	for _, retired := range []struct{ method, path string }{
		{http.MethodPut, "/v1/projects/example/configuration"},
		{http.MethodGet, "/v1/projects/example/configuration?team_id=" + team},
		{http.MethodPost, "/v1/projects/example/publisher-groups/production/namespace/rename"},
		{http.MethodPost, "/v1/projects/example/publisher-groups/production/rename"},
		{http.MethodPost, "/v1/projects/example/publisher-groups/production/enrollments"},
		{http.MethodPost, "/v1/publisher-groups/enroll"},
		{http.MethodPost, "/v1/publisher-groups/lease"},
		{http.MethodGet, "/v1/publisher-groups/assignments"},
		{http.MethodPost, "/v1/publisher-groups/ack"},
	} {
		assertRetainedHTTPRemoved(t, server.Client(), server.URL, session.AccessToken.String(), retired.method, retired.path)
	}
	current, err := owner.GetEnvironment(ctx, team, "example", environment.Id)
	a, _ := json.Marshal(current)
	b, _ := json.Marshal(environment)
	if err != nil || !bytes.Equal(a, b) {
		t.Fatal("rejected retired mutation changed saved environment", err)
	}
	if err := owner.RevokeEnvironmentPublisher(ctx, team, "example", environment.Id, member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	if _, err := anonymous.GetEnvironmentPublisherAssignments(ctx, lease.AccessToken); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("revoked publisher retained lease", err)
	}
}

func exerciseRetainedLocalIntegrationDeclarations(t *testing.T, owner *clientcontrol.Client, d *controlstate.Database, session controlstate.ControlSession, server string) {
	t.Helper()
	ctx := t.Context()
	project := t.TempDir()
	path := filepath.Join(project, "tnl.json")
	const declaration = `{"version":1,"tnl":{"oauth":true,"services":{"local-app":{"protocol":"http"}},"environments":{"local":{"targets":{"local-app":{"address":"http://127.0.0.1:3000","public_url":{}}}}},"webhooks":{"payments":{"service":"local-app","path":"/hooks/payments","provider":"custom"}}}}`
	if err := os.WriteFile(path, []byte(declaration), 0o600); err != nil {
		t.Fatal(err)
	}
	document, err := config.LoadDocument(path)
	if err != nil || document.TNL == nil || !document.TNL.OAuth || len(document.TNL.Webhooks) != 1 {
		t.Fatal("local publisher configuration lost OAuth intent or webhook declaration", err)
	}
	// URL purpose is the surviving control wire. declarations and signing secrets
	// are local publisher inputs, not additional public URL request fields.
	member := session.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(ctx, session.Identity.Identity.ID, member.TeamID)
	if err != nil || len(domains) == 0 {
		t.Fatal("select integration URL domain", err)
	}
	for _, purpose := range []controlv1.PublicURLPurpose{controlv1.Oauth, controlv1.Webhooks} {
		url, err := owner.CreatePublicURL(ctx, controlv1.CreatePublicURLRequest{TeamId: member.TeamID, DomainId: domains[0].ID, MembershipId: &member.ID, CanonicalHostname: string(purpose) + "." + member.ManagedLabel + ".example.test", Target: "", PublicUrlScope: controlv1.Member, Purpose: purpose}, "retained-integration/"+string(purpose))
		if err != nil || url.Purpose != purpose || url.Target != "" || url.Ephemeral {
			t.Fatal("integration URL creation lost its targetless handler purpose", err)
		}
		read, err := owner.GetPublicURL(ctx, url.Id)
		if err != nil || read.Purpose != purpose || read.Target != "" || read.Id != url.Id {
			t.Fatal("integration URL read changed its purpose or identity", err)
		}
	}
	state, err := clientstate.OpenWithOptions(ctx, filepath.Join(t.TempDir(), "client-state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := state.Close(); err != nil {
			t.Error(err)
		}
	})
	scope := clientstate.IntegrationScope{PrimaryProjectRoot: project, Namespace: member.ManagedLabel + ".example.test"}
	tunnel, err := state.BeginTunnel(ctx, clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Project: project, Service: "local-app", Target: "http://127.0.0.1:3000", IntegrationScope: scope})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := tunnel.Finish(finish, nil); err != nil {
			t.Error(err)
		}
	})
	definition, _, err := document.TNL.Webhooks["payments"].DefinitionBytes()
	if err != nil {
		t.Fatal(err)
	}
	if err := tunnel.RegisterWebhookEndpoint(ctx, "payments", definition); err != nil {
		t.Fatal("register actual local publisher webhook declaration", err)
	}
	registered, err := state.ActiveWebhookDefinitions(ctx, server, scope)
	if err != nil || len(registered) != 1 || registered["payments"].Service != "local-app" || registered["payments"].Path != "/hooks/payments" || registered["payments"].Provider != "custom" || registered["payments"].Delivery != "fanout" || !slices.Equal(registered["payments"].Methods, []string{http.MethodPost}) {
		t.Fatal("local publication registration/read lost webhook values or normalized defaults", err)
	}
	const secret = "must-not-leak-webhook-secret"
	// this is an otherwise valid accepted webhook, not an unsupported ancestor.
	var body map[string]any
	if err := json.Unmarshal(definition, &body); err != nil {
		t.Fatal(err)
	}
	body["signing_secret"] = secret
	bad, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	err = tunnel.RegisterWebhookEndpoint(ctx, "payments", bad)
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("local publication accepted or reflected a nested webhook signing secret")
	}
	after, err := state.ActiveWebhookDefinitions(ctx, server, scope)
	if err != nil || !reflect.DeepEqual(after, registered) {
		t.Fatal("rejected webhook secret changed accepted local publication state", err)
	}
	invalid := strings.Replace(declaration, `"provider":"custom"`, `"provider":"custom","signing_secret":"`+secret+`"`, 1)
	if err := os.WriteFile(path, []byte(invalid), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.LoadDocument(path); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("supported nested local webhook source accepted or reflected a signing secret")
	}
}
