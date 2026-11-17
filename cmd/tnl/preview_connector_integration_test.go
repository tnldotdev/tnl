package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this composes real state, HTTP APIs and command presentation. certificate
// preparation proves current connector authority, not connector data traffic.
func TestIntegrationConnectorOnlyPreviewAttachmentAndPresentation(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "connector_preview")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	reviewer, err := d.CreateOIDCControlSession(ctx, "example.test", controlstate.OIDCIdentity{
		Issuer: "https://identity.fixture.test", Subject: "connector-reviewer", DisplayName: "Reviewer",
		AssertionDigest: sha256.Sum256([]byte("connector-reviewer")), AssertionExpiry: now.Add(time.Hour),
	}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	api, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, ManagedDomain: "example.test",
		OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}},
		controlpublic.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := controlauthority.NewHandler(controlauthority.Config{ControlURL: server.URL, ManagedDomain: "example.test",
		OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, d)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pattern := authority.Handler(r); pattern != "/" {
			authority.ServeHTTP(w, r)
		} else {
			api.ServeHTTP(w, r)
		}
	}))
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	ownerAuthority, err := clientauthority.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	reviewerAuthority, err := clientauthority.New(server.URL, server.Client(), reviewer.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	team, err := ownerAuthority.CreateTeam(ctx, authorityv1.CreateTeamRequest{DisplayName: "connector-preview"}, "connector-preview")
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := ownerAuthority.CreateTeamInvitation(ctx, team.Id, authorityv1.CreateInvitationRequest{
		MemberSlug: "reviewer", InitialRole: "member", ExpiresAt: now.Add(time.Hour)}, "reviewer")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reviewerAuthority.AcceptInvitation(ctx, invitation.Secret); err != nil {
		t.Fatal(err)
	}
	ownerControl, err := clientcontrol.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	reviewerControl, err := clientcontrol.New(server.URL, server.Client(), reviewer.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	root, stateDir := t.TempDir(), filepath.Join(t.TempDir(), "state")
	configPath := filepath.Join(root, "tnl.json")
	if err := os.WriteFile(configPath, []byte(`{"version":1,"tnl":{"services":{"web":{},"private":{}},"deployments":{"local":{"targets":{"web":{"public":true},"private":{"public":false}}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	project, err := loadProjectConfiguration(ctx, cli{ConfigPath: configPath}, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	source := project.LocalPublicationIdentity()
	services := map[string]controlv1.Service{}
	preview, err := ownerControl.CreatePreview(ctx, team.Id, "connector-preview")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"web", "private"} {
		local, err := ownerControl.RealizeLocalProjectService(ctx, source.Key, name, controlv1.RealizeLocalProjectServiceRequest{
			TeamId: team.Id, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(),
			WorktreeLabel: new(project.Worktree.Label.FullLabel), Configuration: controlv1.ProjectServiceConfiguration{
				Name: &name, Protocol: new(controlv1.ServiceProtocolHTTP), Target: "app", Public: new(name == "web"),
			}})
		if err != nil {
			t.Fatal("realize preview service", name, err)
		}
		saved, err := ownerControl.GetService(ctx, local.ServiceId)
		if err != nil || saved.Endpoint == nil || saved.Endpoint.Public != (name == "web") {
			t.Fatal("service lost its actual reachability", name, err)
		}
		services[name] = saved
		attached, err := ownerControl.AddPreviewService(ctx, preview.Id, saved.Id)
		if err != nil || !slices.Contains(attached.ServiceIds, saved.Id) {
			t.Fatal("HTTP attachment rejected the enabled connector-only service", name, err)
		}
	}
	public, private := services["web"], services["private"]
	persisted, err := d.GetPreview(ctx, preview.Id)
	if err != nil || len(persisted.ServiceIDs) != 2 || !slices.Contains(persisted.ServiceIDs, private.Id) || !slices.Contains(persisted.ServiceIDs, public.Id) {
		t.Fatal("API attachment did not persist both reachability types", persisted, err)
	}
	if _, err := ownerControl.SetPreviewTeamAccess(ctx, preview.Id, true); err != nil {
		t.Fatal(err)
	}
	// an HTTP share can capture the connector-only service, but its browser
	// permission must not become native connector authority.
	shared, err := ownerControl.CreateShare(ctx, preview.Id, "connector-preview-share", controlv1.CreateShareRequest{
		ServiceIds: []string{public.Id, private.Id}, EntryServiceId: public.Id, ExpiresAt: now.Add(time.Hour),
	})
	if err != nil || !slices.Contains(shared.Share.ServiceIds, private.Id) {
		t.Fatal("preview share did not capture the attached service", err)
	}
	publicKey, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	device, err := reviewerControl.EnrollVisitorDevice(ctx, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, server.URL, now); err != nil {
		t.Fatal(err)
	}
	deviceSource, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: "device", DeviceId: device.Id})
	if err != nil {
		t.Fatal(err)
	}
	resource := controlv1.VisitorResourceScope{Kind: "service", Id: private.Id}
	reviewerContext := controlstate.WithControlPrincipal(ctx, controlstate.ControlPrincipal{
		IdentityID: reviewer.Identity.Identity.ID, SessionID: reviewer.SessionID,
	})
	assertDenied := func(err error, operation string) {
		t.Helper()
		reason, _ := failure.ReasonOf(err)
		var problem *clientcontrol.ProblemError
		if reason != failure.ServerDenied || !errors.As(err, &problem) || problem.Status != http.StatusForbidden || problem.Problem.Code != controlv1.Forbidden {
			t.Fatal(operation+" did not retain the actual forbidden decision", err)
		}
	}
	assertConnectorDenied := func() {
		t.Helper()
		rows, err := reviewerControl.ListAvailableServices(ctx, controlv1.ServiceAccessPathConnector)
		if err != nil || len(rows) != 0 {
			t.Fatal("preview attachment/share/team access granted connector discovery", rows, err)
		}
		_, tokenErr := reviewerControl.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: resource, Source: deviceSource})
		assertDenied(tokenErr, "device permission without an independent connector grant")
		_, apiCertificateErr := reviewerControl.IssueServiceClientCertificate(ctx, private.Id, device.Id, csr)
		assertDenied(apiCertificateErr, "connector certificate without an independent connector grant")
		// retain the independent owning-state decision as well as the real API.
		_, certificateErr := d.IssueVisitorClientCertificate(reviewerContext, server.URL,
			visitorscope.Scope{Kind: visitorscope.Service, ID: private.Id}, controlstate.DeviceTokenSource{DeviceID: device.Id}, csr, time.Now())
		if !errors.Is(certificateErr, controlstate.ErrVisitorPermission) {
			t.Fatal("preview HTTP permission became connector client-certificate authority", certificateErr)
		}
	}
	assertConnectorDenied()
	browserSource, err := json.Marshal(controlv1.VisitorTokenControlSessionSource{Kind: "control_session", PreviewId: &preview.Id})
	if err != nil {
		t.Fatal(err)
	}
	if permission, err := reviewerControl.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: resource, Source: browserSource}); err != nil || permission.VisitorToken == "" {
		t.Fatal("negative connector assertion used an inactive preview-team grant", err)
	}
	shareSource, err := json.Marshal(shared.TokenSource)
	if err != nil {
		t.Fatal(err)
	}
	if permission, err := reviewerControl.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: resource, Source: shareSource}); err != nil || permission.VisitorToken == "" {
		t.Fatal("negative connector assertion used an inactive captured HTTP share", err)
	}
	// neither valid HTTP source can issue a connector client certificate.
	for _, source := range []controlstate.VisitorTokenSource{
		controlstate.ShareTokenSource{ShareID: shared.Share.Id, Secret: shared.TokenSource.Secret},
		controlstate.BrowserTokenSource{PreviewID: preview.Id},
	} {
		if _, err := d.IssueVisitorClientCertificate(reviewerContext, server.URL, visitorscope.Scope{Kind: visitorscope.Service, ID: private.Id},
			source, csr, now); !errors.Is(err, controlstate.ErrVisitorPermission) {
			t.Fatal("HTTP share or preview-team source issued connector client-certificate authority", err)
		}
	}
	grant, err := ownerControl.CreateServiceGrant(ctx, private.Id, "independent-connector-grant", controlv1.CreateServiceGrantRequest{
		Kind: "identity", IdentityId: new(reviewer.Identity.Identity.ID),
	})
	if err != nil {
		t.Fatal(err)
	}
	rows, err := reviewerControl.ListAvailableServices(ctx, controlv1.ServiceAccessPathConnector)
	if err != nil || len(rows) != 1 || rows[0].Id != private.Id || rows[0].VisitorAccess != "identity_grant" ||
		rows[0].Endpoint == nil || rows[0].Endpoint.Public {
		t.Fatal("independent connector grant lost the service's actual reachability", rows, err)
	}
	certificate, err := reviewerControl.IssueServiceClientCertificate(ctx, private.Id, device.Id, csr)
	if err != nil || certificate.ServiceId != private.Id || certificate.CertificatePem == "" || certificate.IssuerPem == "" || !certificate.ExpiresAt.After(now) {
		t.Fatal("independently authorized connector preparation failed", err)
	}
	block, _ := pem.Decode([]byte(certificate.CertificatePem))
	if block == nil {
		t.Fatal("connector preparation did not issue an actual certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !bytes.Equal(leaf.RawSubjectPublicKeyInfo, mustPreviewPublicKey(t, publicKey)) {
		t.Fatal("connector certificate did not bind the actual device key", err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(certificate.IssuerPem)) {
		t.Fatal("connector preparation returned an invalid issuer")
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: roots, CurrentTime: time.Now(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil || !leaf.NotAfter.Equal(certificate.ExpiresAt) {
		t.Fatal("connector certificate failed actual issuer/expiry verification", err)
	}
	scope, subject, err := visitortoken.CertificateIssuanceBinding(chains)
	digest, digestErr := visitortoken.KeyDigest(publicKey)
	if err != nil || digestErr != nil || scope != (visitorscope.Scope{Kind: visitorscope.Service, ID: private.Id}) ||
		subject != (visitortoken.Device{IdentityID: reviewer.Identity.Identity.ID, SessionID: reviewer.SessionID, DeviceID: device.Id, KeySHA256: digest}) {
		t.Fatal("connector certificate crossed its exact service, person, session or device binding", err, digestErr)
	}
	if rows, err := reviewerControl.ListAvailableServices(ctx, controlv1.ServiceAccessPathPublicEndpoint); err != nil ||
		len(rows) != 1 || rows[0].Id != public.Id || rows[0].VisitorAccess != "preview_team" {
		t.Fatal("connector-only attachment was presented as publicly visitable", rows, err)
	}
	state, err := clientstate.Open(ctx, stateDir)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Server(ctx, server.URL)
	if err == nil {
		err = store.SavePreviewID(ctx, team.Id, project.Root, preview.Id)
	}
	closeErr := state.Close()
	if err != nil || closeErr != nil {
		t.Fatal("save actual preview for command presentation", err, closeErr)
	}
	call := func(args ...string) ([]byte, error) {
		t.Helper()
		argv := append([]string{"--config", configPath, "--no-telemetry"}, args...)
		argv = append(argv, "--server", server.URL, "--access-token", owner.AccessToken.String(), "--team", team.Id, "--state-dir", stateDir)
		var output, diagnostics bytes.Buffer
		err := run(ctx, argv, &output, &diagnostics)
		if diagnostics.Len() != 0 {
			t.Errorf("unexpected command diagnostics: %s", &diagnostics)
		}
		return output.Bytes(), err
	}
	for _, mode := range []string{"human", "json"} {
		output, err := call("share", "--output="+mode)
		if err != nil || !bytes.Contains(output, []byte("https://"+public.Endpoint.Hostname)) {
			t.Fatalf("public sibling share presentation failed: %v %s", err, output)
		}
		for _, misleading := range []string{private.Id, private.Endpoint.Hostname, `"private"`} {
			if bytes.Contains(output, []byte(misleading)) {
				t.Fatalf("connector-only service appeared in public-link presentation: %s", output)
			}
		}
		if mode == "json" {
			var printed struct {
				ServiceIDs []string                      `json:"service_ids"`
				Services   map[string]shareServiceResult `json:"services"`
			}
			if err := json.Unmarshal(output, &printed); err != nil || !slices.Equal(printed.ServiceIDs, []string{public.Id}) ||
				len(printed.Services) != 1 || printed.Services["web"].ServiceID != public.Id {
				t.Fatalf("share presentation widened the public service set: %v %s", err, output)
			}
		}
	}
	for _, args := range [][]string{{"share", "--service=private"}, {"share", "link", "create", private.Id}} {
		output, err := call(args...)
		if reason, _ := failure.ReasonOf(err); reason != failure.ShareInputInvalid || len(output) != 0 {
			t.Fatalf("connector-only service got a misleading public share link: %v %s", err, output)
		}
	}
	if err := ownerControl.RevokeServiceGrant(ctx, private.Id, grant.Id); err != nil {
		t.Fatal(err)
	}
	assertConnectorDenied()
	if current, err := ownerControl.GetShare(ctx, shared.Share.Id); err != nil || current.RevokedAt != nil {
		t.Fatal("connector revocation test accidentally revoked the independent HTTP share", err)
	}
	if current, err := ownerControl.GetPreview(ctx, preview.Id); err != nil || current.TeamAccessEnabled == nil || !*current.TeamAccessEnabled ||
		!slices.Contains(current.ServiceIds, private.Id) {
		t.Fatal("connector revocation changed preview attachment or HTTP team permission", err)
	}
	t.Log("proved API attachment, current independently granted connector certificate preparation/revocation, and human/JSON public-link exclusion; no connector traffic was sent")
}

func mustPreviewPublicKey(t *testing.T, key ed25519.PublicKey) []byte {
	t.Helper()
	encoded, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
