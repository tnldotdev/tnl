package controlapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type feedbackPolicyBrowserVerifier struct{}

func (feedbackPolicyBrowserVerifier) Verify(context.Context, string) (oidcauth.Identity, error) {
	return oidcauth.Identity{}, oidcauth.ErrUnauthenticated
}

type feedbackPolicyAPIFixture struct {
	t           *testing.T
	database    *controlstate.Database
	databaseURL string
	now         time.Time
	owner       controlstate.ControlSession
	membership  controlstate.Membership
	publicURL   controlstate.PublicURL
	run         controlstate.PublishRunSetup
	preview     controlstate.Preview
	mux         *http.ServeMux
}

func newFeedbackPolicyAPIFixture(t *testing.T, cfg Config) feedbackPolicyAPIFixture {
	t.Helper()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "feedback_policy_api")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(database.Close)
	now := time.Now().UTC()
	const managedDomain = "policy.example.test"
	const loginToken = "tnl_login_AAECAwQFBgcICQoLDA0ODw.EBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8"
	verifier, err := credentials.ParseLoginToken(credentials.LoginToken(loginToken))
	if err != nil {
		t.Fatal(err)
	}
	session, err := database.CreateBuiltinControlSession(t.Context(), managedDomain, verifier.SourceRevision(), time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	membership := session.Identity.Memberships[0]
	domains, err := database.ListTeamDomains(t.Context(), membership.IdentityID, membership.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, err := database.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{
		TeamID: membership.TeamID, DomainID: domains[0].ID, ActingIdentityID: membership.IdentityID,
		IdempotencyKey: "policy-url", RequestDigest: sha256.Sum256([]byte("policy-url")), CanonicalHostname: "web." + managedDomain,
		Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeShared, Purpose: controlstate.PublicURLPurposeApp,
		DNSState: controlstate.PublicURLDNSUnmanaged, PolicyRevision: 1, ManagedURLMode: naming.ManagedURLModeSimple,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	for slot := range 2 {
		name := fmt.Sprintf("policy-relay-%d", slot)
		if _, err := database.RegisterRelay(t.Context(), controlstate.RelayRegistration{
			RelayServiceID: name, RelayID: name + "-1", RelayRunID: name + "-run", ProtocolVersion: 1,
			RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test", InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 10, StreamCapacity: 10,
		}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	setup, err := database.CreatePublishRun(t.Context(), controlstate.PublishRunRequest{
		PublicURLID: publicURL.ID, TeamID: membership.TeamID, ActingIdentityID: membership.IdentityID, MembershipID: membership.ID,
		RetrySecret: bytes.Repeat([]byte{7}, 32), IdempotencyKey: "policy-run", RequestDigest: sha256.Sum256([]byte("policy-run")),
		PolicyRevision: 1, ExpectedMutationRevision: publicURL.MutationRevision,
		CertificateCacheKey: "policy-cert", CertificateScope: "public-url", CertificateIdentifiers: []string{publicURL.CanonicalHostname}, CertificateChallenge: "tls-alpn-01",
	}, now, time.Hour, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	preview, err := database.CreatePreview(t.Context(), membership.TeamID, membership.IdentityID, "policy-preview", now)
	if err != nil {
		t.Fatal(err)
	}
	publicURL, err = database.GetPublicURLForAuthorization(t.Context(), publicURL.ID)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AddPreviewPublicURL(t.Context(), controlstate.AddPreviewPublicURLRequest{
		PreviewID: preview.ID, PublicURLID: publicURL.ID, TeamID: membership.TeamID, IdentityID: membership.IdentityID, PolicyRevision: 1, ExpectedMutationRevision: publicURL.MutationRevision,
	}, now); err != nil {
		t.Fatal(err)
	}
	cfg.ManagedDomain, cfg.ManagedURLMode, cfg.LoginToken = managedDomain, naming.ManagedURLModeSimple, loginToken
	mux := testHandler(t, cfg, database, database, nil)
	if _, err := authorityapi.Register(mux, authorityapi.Config{BrowserOIDCVerifier: feedbackPolicyBrowserVerifier{}, LoginToken: loginToken}, database); err != nil {
		t.Fatal(err)
	}
	return feedbackPolicyAPIFixture{t: t, database: database, databaseURL: databaseURL, now: now,
		owner: session, membership: membership, publicURL: publicURL, run: setup, preview: preview, mux: mux}
}

func (f feedbackPolicyAPIFixture) call(method, path, body, token, key string, status int) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	if key != "" {
		r.Header.Set("Idempotency-Key", key)
	}
	w := httptest.NewRecorder()
	f.mux.ServeHTTP(w, r)
	if w.Code != status {
		f.t.Fatalf("%s %s = %d %s, want %d", method, path, w.Code, w.Body.String(), status)
	}
	return w
}

func TestIntegrationFeedbackPolicyDirectAPIEnforcement(t *testing.T) {
	f := newFeedbackPolicyAPIFixture(t, Config{})
	session, membership, setup, preview := f.owner, f.membership, f.run, f.preview
	call := f.call
	runPath := "/v1/publish-runs/" + setup.PublishRunID + "/feedback"
	report := fmt.Sprintf(`{"preview_id":%q,"publish_run_number":1,"service":"web","page_path":"/","report":{"text":"Review","display_name":"pretends signed-in"},"evidence":{"schema_version":1,"actions":[],"failed_requests":[]},"source_at_report":{"schema_version":1,"head_commit":"","project_path":"","branch":"","changed_files":[],"complete":false},"access":{"allowed_ip":true}}`, preview.ID)
	created := call("POST", runPath, report, setup.PublishRunToken.String(), "initial", 201)
	var thread controlv1.FeedbackThread
	if err := json.Unmarshal(created.Body.Bytes(), &thread); err != nil {
		t.Fatal(err)
	}
	policyPath := "/v1/teams/" + membership.TeamID + "/feedback-policy"
	call("PUT", policyPath, `{"require_sign_in":true}`, session.AccessToken.String(), "", 200)
	rejected := call("POST", runPath, report, setup.PublishRunToken.String(), "required", 401)
	if !strings.Contains(rejected.Body.String(), `"code":"feedback_sign_in_required"`) {
		t.Fatalf("classification=%s", rejected.Body.String())
	}
	for _, action := range []string{"reply", "thread.resolved", "thread.reopened"} {
		body := fmt.Sprintf(`{"publish_run_number":1,"type":%q,"text":"Review","access":{"allowed_ip":true}}`, action)
		call("POST", runPath+"/"+thread.Id+"/events", body, setup.PublishRunToken.String(), action+"-required", 401)
	}
	metadata := fmt.Sprintf(`{"publish_run_number":1,"preview_id":%q,"access":{"allowed_ip":true}}`, preview.ID)
	current := call("POST", runPath+"/access", metadata, setup.PublishRunToken.String(), "", 200)
	if !strings.Contains(current.Body.String(), `"require_sign_in":true`) {
		t.Fatalf("live metadata=%s", current.Body.String())
	}
	call("POST", runPath+"/access", metadata, "", "", 401)
	call("POST", runPath+"/access", strings.Replace(metadata, `"allowed_ip":true`, `"allowed_ip":false`, 1), setup.PublishRunToken.String(), "", 403)
	call("POST", runPath+"/access", strings.Replace(metadata, preview.ID, "pv_0123456789abcdefghijkl", 1), setup.PublishRunToken.String(), "", 403)
	// shared reads keep their original access requirements with sign-in required.
	call("POST", runPath+"/query", metadata, setup.PublishRunToken.String(), "", 200)
	call("POST", runPath+"/"+thread.Id+"/query", metadata, setup.PublishRunToken.String(), "", 200)
	call("POST", runPath+"/"+thread.Id+"/events/query", metadata, setup.PublishRunToken.String(), "", 200)
	call("PUT", policyPath, `{"require_sign_in":false}`, session.AccessToken.String(), "", 200)
	call("POST", runPath, report, setup.PublishRunToken.String(), "optional-again", 201)
	for _, action := range []string{"reply", "thread.resolved", "thread.reopened"} {
		body := fmt.Sprintf(`{"publish_run_number":1,"type":%q,"text":"Review","access":{"allowed_ip":true}}`, action)
		call("POST", runPath+"/"+thread.Id+"/events", body, setup.PublishRunToken.String(), action+"-optional", 201)
	}
}

func (f feedbackPolicyAPIFixture) authentication() controlstate.PublishRunAuthentication {
	return controlstate.PublishRunAuthentication{
		PublishRunID: f.run.PublishRunID, PublicURLID: f.run.PublicURLID, PublishRunNumber: f.run.PublishRunNumber, PublishRunToken: f.run.PublishRunToken,
	}
}

func (f feedbackPolicyAPIFixture) browserSession(issuedAt time.Time, accessLifetime, browserLifetime time.Duration) (controlstate.ControlSession, string) {
	f.t.Helper()
	if err := f.database.EnableBrowserAccess(f.t.Context(), f.authentication(), f.now); err != nil {
		f.t.Fatal(err)
	}
	if err := f.database.EnableShareAccess(f.t.Context(), f.authentication(), f.preview.ID); err != nil {
		f.t.Fatal(err)
	}
	connection, err := pgx.Connect(f.t.Context(), f.databaseURL)
	if err != nil {
		f.t.Fatal(err)
	}
	defer connection.Close(f.t.Context())
	// browser handoffs require a ready run; certificate readiness is covered by
	// the publisher integration tests rather than this feedback HTTP boundary.
	if _, err := connection.Exec(f.t.Context(), `UPDATE control.publish_runs SET state = 'ready', ready_at = $2 WHERE id = $1`, f.run.PublishRunID, f.now); err != nil {
		f.t.Fatal(err)
	}
	session, err := f.database.CreateOIDCControlSession(f.t.Context(), "policy.example.test", controlstate.OIDCIdentity{
		Issuer: "https://issuer.example.test", Subject: "external-reviewer", DisplayName: "verified external reviewer",
		AssertionDigest: sha256.Sum256([]byte(f.t.Name())), AssertionExpiry: issuedAt.Add(time.Minute),
	}, accessLifetime, 24*time.Hour, issuedAt)
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.database.GetTeam(f.t.Context(), session.Identity.Identity.ID, f.membership.TeamID); !errors.Is(err, controlstate.ErrTeamNotFound) {
		f.t.Fatalf("external reviewer unexpectedly has preview-team membership: %v", err)
	}
	handoff, err := f.database.IssueBrowserHandoff(f.t.Context(), controlstate.BrowserLoginAttempt{
		PreviewID: f.preview.ID, PublicURLID: f.publicURL.ID, ReturnPath: "/",
	}, controlstate.BrowserAccessSession{
		IdentityID: session.Identity.Identity.ID, DisplayName: "stale browser name", AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, ExpiresAt: issuedAt.Add(browserLifetime),
	}, issuedAt)
	if err != nil {
		f.t.Fatal(err)
	}
	cookie, _, _, _, _, err := f.database.RedeemBrowserHandoff(f.t.Context(), f.authentication(), handoff.Token, issuedAt)
	if err != nil {
		f.t.Fatal(err)
	}
	return session, cookie
}

func (f feedbackPolicyAPIFixture) report(access controlv1.FeedbackReviewerAccess) string {
	f.t.Helper()
	body := controlv1.CreateFeedbackReportRequest{
		PreviewId: f.preview.ID, PublishRunNumber: int64(f.run.PublishRunNumber), Service: "web", PagePath: "/", Access: access,
		Evidence: controlv1.FeedbackEvidence{SchemaVersion: 1}, SourceAtReport: controlv1.SourceState{SchemaVersion: 1, ChangedFiles: []controlv1.SourceFileState{}, Complete: false},
	}
	body.Report.Text, body.Report.DisplayName = "Review", new("forged author")
	payload, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	return string(payload)
}

func (f feedbackPolicyAPIFixture) requireSignIn() {
	f.t.Helper()
	if _, err := f.database.SetTeamFeedbackPolicy(f.t.Context(), f.membership.IdentityID, f.membership.TeamID, true, f.now); err != nil {
		f.t.Fatal(err)
	}
}

func assertFeedbackPolicyAuthor(t *testing.T, author *controlv1.FeedbackAuthor, identityID string) {
	t.Helper()
	if author == nil || !author.Verified || author.IdentityId == nil || *author.IdentityId != identityID || author.DisplayName != "verified external reviewer" {
		t.Fatalf("feedback did not retain current verified identity: %+v", author)
	}
}

func TestIntegrationFeedbackPolicySignedExternalReviewerHTTP(t *testing.T) {
	for _, admission := range []string{"IP", "share"} {
		t.Run(admission, func(t *testing.T) {
			f := newFeedbackPolicyAPIFixture(t, Config{})
			f.requireSignIn()
			session, cookie := f.browserSession(f.now, time.Hour, time.Hour)
			if access, err := f.database.BrowserAuthorization(t.Context(), f.publicURL.ID, cookie, f.now); err != nil || access.VisitAllowed || access.Identity.IdentityID != session.Identity.Identity.ID {
				t.Fatalf("external identity alone admitted visitor: %+v, %v", access, err)
			}
			access := controlv1.FeedbackReviewerAccess{AllowedIp: admission == "IP", BrowserCookieSecret: &cookie}
			if admission == "share" {
				secret := bytes.Repeat([]byte{1}, 32)
				share, err := f.database.CreateShare(t.Context(), controlstate.CreateShareRequest{
					PreviewID: f.preview.ID, TeamID: f.membership.TeamID, ActingIdentityID: f.membership.IdentityID, IdempotencyKey: "external-share",
					SecretFingerprint: sha256.Sum256(secret), ExpiresAt: f.now.Add(time.Hour), PolicyRevision: 1,
					PublicURLs: []controlstate.AuthorizedSharePublicURL{{PublicURLID: f.publicURL.ID, ExpectedMutationRevision: f.publicURL.MutationRevision}},
				}, f.now)
				if err != nil {
					t.Fatal(err)
				}
				redemption, err := f.database.RedeemShare(t.Context(), f.authentication(), share.ID, secret, nil, f.now)
				if err != nil {
					t.Fatal(err)
				}
				access.ShareId, access.CookieSecret = &share.ID, &redemption.CookieSecret
			}
			runPath := "/v1/publish-runs/" + f.run.PublishRunID + "/feedback"
			created := f.call(http.MethodPost, runPath, f.report(access), f.run.PublishRunToken.String(), "signed-report", http.StatusCreated)
			var thread controlv1.FeedbackThread
			if err := json.Unmarshal(created.Body.Bytes(), &thread); err != nil {
				t.Fatal(err)
			}
			assertFeedbackPolicyAuthor(t, thread.Report.Author, session.Identity.Identity.ID)
			for _, action := range []controlv1.FeedbackEventType{controlv1.Reply, controlv1.ThreadResolved, controlv1.ThreadReopened} {
				payload, err := json.Marshal(controlv1.AppendReviewerFeedbackEventRequest{
					PublishRunNumber: int64(f.run.PublishRunNumber), Type: action, Text: new("More detail"), Access: access,
				})
				if err != nil {
					t.Fatal(err)
				}
				appended := f.call(http.MethodPost, runPath+"/"+thread.Id+"/events", string(payload), f.run.PublishRunToken.String(), string(action), http.StatusCreated)
				var event controlv1.FeedbackEvent
				if err := json.Unmarshal(appended.Body.Bytes(), &event); err != nil {
					t.Fatal(err)
				}
				assertFeedbackPolicyAuthor(t, event.Author, session.Identity.Identity.ID)
			}
		})
	}
}

func TestIntegrationFeedbackPolicyExpiredBrowserSessionHTTP(t *testing.T) {
	f := newFeedbackPolicyAPIFixture(t, Config{})
	f.requireSignIn()
	_, cookie := f.browserSession(f.now.Add(-2*time.Hour), time.Hour, time.Hour)
	access := controlv1.FeedbackReviewerAccess{AllowedIp: true, BrowserCookieSecret: &cookie}
	response := f.call(http.MethodPost, "/v1/publish-runs/"+f.run.PublishRunID+"/feedback", f.report(access), f.run.PublishRunToken.String(), "expired-session", http.StatusForbidden)
	var problem controlv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != controlv1.Forbidden || problem.Detail != "public URL access denied" {
		t.Fatalf("expired credential was not an access failure: %+v, %v", problem, err)
	}
	page, err := f.database.ListFeedbackForPublicURL(t.Context(), f.preview.ID, f.publicURL.ID, "", "", "")
	if err != nil || len(page.Threads) != 0 {
		t.Fatalf("expired session saved feedback: %+v, %v", page, err)
	}
}

func TestIntegrationFeedbackPolicyBrowserRefreshUnavailableHTTP(t *testing.T) {
	var database atomic.Pointer[controlstate.Database]
	var unavailable atomic.Bool
	var refreshCalls atomic.Int64
	unavailable.Store(true)
	authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/refresh" {
			t.Errorf("unexpected authority request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		refreshCalls.Add(1)
		if unavailable.Load() {
			http.Error(w, "upstream-credential-secret", http.StatusServiceUnavailable)
			return
		}
		var body authorityv1.RefreshControlSessionRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			http.Error(w, "invalid refresh", 400)
			return
		}
		session, err := database.Load().RefreshControlSession(r.Context(), credentials.RefreshToken(body.RefreshToken), 0, time.Hour, time.Now())
		if err != nil {
			t.Error(err)
			http.Error(w, "refresh failed", 500)
			return
		}
		writeJSON(w, http.StatusOK, authorityv1.ControlSessionResponse{
			SessionId: session.SessionID, AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(), AccessExpiresAt: session.AccessExpiresAt, RefreshExpiresAt: session.RefreshExpiresAt,
			Identity: authorityv1.IdentityContext{Identity: authorityv1.Identity{Id: session.Identity.Identity.ID}},
		})
	}))
	defer authority.Close()
	f := newFeedbackPolicyAPIFixture(t, Config{BrowserOIDCClientID: "test-browser-client", OIDCIssuer: "https://issuer.example.test", ControlURL: authority.URL, HTTPClient: authority.Client()})
	database.Store(f.database)
	runPath := "/v1/publish-runs/" + f.run.PublishRunID + "/feedback"
	initial := f.call(http.MethodPost, runPath, f.report(controlv1.FeedbackReviewerAccess{AllowedIp: true}), f.run.PublishRunToken.String(), "initial", http.StatusCreated)
	var thread controlv1.FeedbackThread
	if err := json.Unmarshal(initial.Body.Bytes(), &thread); err != nil {
		t.Fatal(err)
	}
	f.requireSignIn()
	session, cookie := f.browserSession(f.now, 20*time.Second, time.Hour)
	access := controlv1.FeedbackReviewerAccess{AllowedIp: true, BrowserCookieSecret: &cookie}
	assertUnavailable := func(response *httptest.ResponseRecorder) {
		t.Helper()
		var problem controlv1.Problem
		if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || problem.Code != controlv1.Unavailable || problem.Detail != "browser sign-in is unavailable" || strings.Contains(response.Body.String(), "upstream-credential-secret") {
			t.Fatalf("refresh failure lost availability classification: %+v, %v", problem, err)
		}
	}
	assertUnavailable(f.call(http.MethodPost, runPath, f.report(access), f.run.PublishRunToken.String(), "refresh-report", http.StatusServiceUnavailable))
	for _, action := range []controlv1.FeedbackEventType{controlv1.Reply, controlv1.ThreadResolved, controlv1.ThreadReopened} {
		payload, err := json.Marshal(controlv1.AppendReviewerFeedbackEventRequest{PublishRunNumber: int64(f.run.PublishRunNumber), Type: action, Text: new("More detail"), Access: access})
		if err != nil {
			t.Fatal(err)
		}
		assertUnavailable(f.call(http.MethodPost, runPath+"/"+thread.Id+"/events", string(payload), f.run.PublishRunToken.String(), string(action), http.StatusServiceUnavailable))
	}
	if refreshCalls.Load() != 4 {
		t.Fatalf("reviewer writes did not reach authority refresh: %d", refreshCalls.Load())
	}
	events, err := f.database.ListFeedbackEventsForThread(t.Context(), thread.Id, 0)
	if err != nil || len(events.Events) != 1 {
		t.Fatalf("failed refresh saved feedback: %+v, %v", events, err)
	}
	unavailable.Store(false)
	recovered := f.call(http.MethodPost, runPath, f.report(access), f.run.PublishRunToken.String(), "refresh-report", http.StatusCreated)
	var result controlv1.FeedbackThread
	if err := json.Unmarshal(recovered.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	assertFeedbackPolicyAuthor(t, result.Report.Author, session.Identity.Identity.ID)
	if refreshCalls.Load() != 5 {
		t.Fatalf("recovered refresh calls=%d", refreshCalls.Load())
	}
}
