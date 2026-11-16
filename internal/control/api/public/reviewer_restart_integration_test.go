package public

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil/visitorfixture"
	"github.com/tnldotdev/tnl/internal/transport/targettransport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

// each frontend captures one immutable run. only the browser transport changes
// on restart; its hostname, cookie jar, and authenticated reviewer stay the same.
func reviewerHTTPRun(t *testing.T, control *clientcontrol.Client, service controlstate.ServiceRecord, run controlstate.ServiceHTTPRun, preview, project, target string) (*http.Transport, func()) {
	t.Helper()
	until := time.Now().Add(time.Minute)
	header := tunnelv1.ServiceForwardingHeader{ServiceStreamHeader: tunnelv1.ServiceStreamHeader{
		ProtocolVersion: tunnelv1.Version, Kind: tunnelv1.ServiceForwardingStream,
		ServiceID: service.ID, ServiceRunID: run.RunID, RunNumber: uint64(run.Number), SourceIP: "192.0.2.9",
		VisitorConnectionID: "vc_" + strings.Repeat("V", 22), PublisherConnectionID: "pc_" + strings.Repeat("P", 22),
		ConnectionAssignmentRevision: 1, ExpiresAt: until,
		PublicService: &tunnelv1.PublicServiceAdmission{IngressID: "ingress", IngressRunID: "ir_" + strings.Repeat("I", 22), IngressLeaseRevision: 1, DestinationPort: 443}},
		RelayID: "relay", RelayServiceID: "relay-service", RelayRunID: "rr_" + strings.Repeat("R", 22), RelayLeaseRevision: 1, LeaseExpiresAt: until}
	frontend, closeFrontend, err := publisherservice.PrepareHTTP(t.Context(), publisherservice.HTTP{
		Control: control, Subject: run.Subject, RunID: run.RunID, Number: run.Number, Token: run.Token,
		Hostname: service.Placement.Hostname, Port: 443, Header: header, Source: netip.MustParseAddrPort("192.0.2.9:1234"),
		Feedback: true, PreviewID: preview, ProjectService: "web", ProjectRoot: project,
		ReserveCapacity: func(context.Context) error { return nil },
	})
	if err != nil {
		t.Fatal("prepare real reviewer HTTP frontend", err)
	}
	application := servicestream.HTTPTarget{Address: strings.TrimPrefix(target, "http://"), Transport: targettransport.Transport{Protocol: config.ProtocolHTTP}}
	certificate := visitorfixture.Certificate(t, service.Placement.Hostname)
	var mu sync.Mutex
	var joins []func()
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: visitorfixture.Roots(t, certificate)},
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			visitor, raw := net.Pipe()
			server := tls.Server(raw, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, NextProtos: []string{"http/1.1"}})
			done := make(chan error, 1)
			go func() {
				defer server.Close()
				done <- frontend.Forward(t.Context(), server, application)
			}()
			mu.Lock()
			joins = append(joins, func() {
				_ = visitor.Close()
				select {
				case err := <-done:
					if err != nil {
						t.Error("reviewer HTTP frontend cleanup", err)
					}
				case <-time.After(5 * time.Second):
					t.Error("reviewer HTTP frontend did not join")
				}
			})
			mu.Unlock()
			return visitor, nil
		}}
	stop := sync.OnceFunc(func() {
		transport.CloseIdleConnections()
		mu.Lock()
		defer mu.Unlock()
		for _, join := range joins {
			join()
		}
		closeFrontend()
	})
	t.Cleanup(stop)
	return transport, stop
}

func TestIntegrationReviewerHTTPVisitAndFeedbackSurviveAppRestart(t *testing.T) {
	f := newCompanyHTTPFixture(t, "reviewer_http_restart")
	owner, creator := f.basic("restart-owner"), f.basic("restart-share-creator")
	ctx := controlstate.WithControlPrincipal(t.Context(), f.principal(owner))
	team, err := f.d.CreateTeam(ctx, controlstate.CreateTeamRequest{IdentityID: owner.Identity.Identity.Id,
		DisplayName: "reviewer-restart", MemberSlug: "owner", IdempotencyKey: "team", RequestDigest: sha256.Sum256([]byte("team"))}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := f.d.CreateTeamInvitation(ctx, controlstate.CreateInvitationRequest{
		IdentityID: owner.Identity.Identity.Id, TeamID: team.ID, MemberSlug: "share-creator", InitialRole: controlstate.TeamRoleAdmin,
		IdempotencyKey: "creator", ExpiresAt: f.now.Add(time.Hour), RetrySecret: bytes.Repeat([]byte{7}, 32),
	}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AcceptInvitation(t.Context(), creator.Identity.Identity.Id, credentials.InvitationToken(invitation.Secret), f.now); err != nil {
		t.Fatal(err)
	}
	member := f.membership(owner.Identity.Identity.Id, team.ID)
	relays := newAuditCompositionRelays(t, f.d, f.now)
	service, old := publishBrowserService(t, f, ctx, owner.Identity.Identity.Id, team.ID, member.ID, "web", relays)
	creatorCtx := controlstate.WithControlPrincipal(t.Context(), f.principal(creator))
	preview, err := f.d.CreatePreview(creatorCtx, team.ID, creator.Identity.Identity.Id, "http-reviewer-restart", f.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.AddPreviewService(creatorCtx, controlstate.AddPreviewServiceRequest{PreviewID: preview.ID, ServiceID: service.ID, TeamID: team.ID, IdentityID: creator.Identity.Identity.Id}, f.now); err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{29}, 32)
	share, err := f.d.CreateShare(creatorCtx, controlstate.CreateShareRequest{PreviewID: preview.ID, TeamID: team.ID,
		ActingIdentityID: creator.Identity.Identity.Id, IdempotencyKey: "http-restart-share", SecretFingerprint: sha256.Sum256(secret),
		ExpiresAt: f.now.Add(time.Hour), ServiceIDs: []string{service.ID}, EntryServiceID: service.ID}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.d.PrepareVisitorSigningKeys(ctx, f.server.URL, f.now); err != nil {
		t.Fatal(err)
	}
	api, err := NewHandler(Config{ControlURL: f.server.URL, HTTPClient: f.server.Client()}, DatabaseStores(f.d), f.d, nil)
	if err != nil {
		t.Fatal(err)
	}
	var redemptions, signins, permissions atomic.Int32
	f.mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/share-redemptions"):
			redemptions.Add(1)
		case strings.HasSuffix(r.URL.Path, "/browser/handoff"):
			signins.Add(1)
		case r.URL.Path == "/v1/visitor-tokens":
			permissions.Add(1)
		}
		api.ServeHTTP(w, r)
	}))
	control, err := clientcontrol.New(f.server.URL, f.server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	jar, _ := cookiejar.New(nil)
	project := t.TempDir()
	target := func(version string) *httptest.Server {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Cookie") != "" {
				t.Error("publisher-owned reviewer cookies reached the app")
			}
			_, _ = io.WriteString(w, version)
		}))
		t.Cleanup(server.Close)
		return server
	}
	first := target("app-before-restart")
	oldTransport, stopOld := reviewerHTTPRun(t, control, service, old, preview.ID, project, first.URL)
	defer stopOld()
	browser := &http.Client{Jar: jar, Timeout: 5 * time.Second, Transport: oldTransport}
	origin := "https://" + service.Placement.Hostname
	visit := func(path string, status int, contains string) {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, origin+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Sec-Fetch-Mode", "navigate")
		request.Header.Set("Sec-Fetch-Dest", "document")
		response, err := browser.Do(request)
		if err != nil {
			t.Fatal("reviewer navigation", err)
		}
		body, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || response.StatusCode != status || !strings.Contains(string(body), contains) {
			t.Fatalf("reviewer navigation: status=%d body=%s read=%v close=%v", response.StatusCode, body, err, closeErr)
		}
	}
	visit("/__tnl/share/"+share.ID+"."+base64.RawURLEncoding.EncodeToString(secret), http.StatusOK, "app-before-restart")
	reviewer := f.basic("restart-http-reviewer")
	handoff, err := f.d.IssueBrowserHandoff(t.Context(), controlstate.BrowserLoginAttempt{PreviewID: preview.ID, Subject: old.Subject, ServiceRunIDs: []string{old.RunID}, ReturnPath: "/"},
		controlstate.BrowserAccessSession{IdentityID: reviewer.Identity.Identity.Id, DisplayName: "Reviewer",
			AccessToken: reviewer.AccessToken, RefreshToken: reviewer.RefreshToken, AccessExpiresAt: f.now.Add(30 * time.Minute), ExpiresAt: f.now.Add(time.Hour)}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	visit("/__tnl/team/handoff/"+handoff.Token, http.StatusOK, "app-before-restart")
	report := func(key string, status int) controlv1.FeedbackThread {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, origin+"/__tnl/feedback",
			strings.NewReader(`{"schema_version":1,"text":"Review `+key+`","page_path":"/","evidence":{"schema_version":1}}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Origin", origin)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response, err := browser.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if err != nil || closeErr != nil || response.StatusCode != status {
			t.Fatalf("reviewer report %s: %d %s read=%v close=%v", key, response.StatusCode, body, err, closeErr)
		}
		var thread controlv1.FeedbackThread
		if status == http.StatusOK {
			if err := json.Unmarshal(body, &thread); err != nil {
				t.Fatal(err)
			}
			if thread.Report.Author == nil || !thread.Report.Author.Verified || thread.Report.Author.IdentityId == nil ||
				*thread.Report.Author.IdentityId != reviewer.Identity.Identity.Id {
				t.Fatal("HTTP feedback lost the verified reviewer")
			}
		}
		return thread
	}
	report("before-restart", http.StatusOK)
	if redemptions.Load() != 1 || signins.Load() != 1 {
		t.Fatal("initial browser visit did not redeem exactly one share and sign-in")
	}
	stopOld()
	first.Close()
	if err := f.d.CloseServiceRun(ctx, service.ID, old.RunID, old.Token.String(), f.now); err != nil {
		t.Fatal(err)
	}
	restarted, current := publishBrowserService(t, f, ctx, owner.Identity.Identity.Id, team.ID, member.ID, "web", relays)
	if restarted.ID != service.ID || current.RunID == old.RunID || current.Number <= old.Number {
		t.Fatal("ordinary app restart did not replace its run")
	}
	second := target("app-after-restart")
	currentTransport, stopCurrent := reviewerHTTPRun(t, control, service, current, preview.ID, project, second.URL)
	defer stopCurrent()
	browser.Transport = currentTransport
	// deterministically simulate an idle browser losing only its short-lived
	// visitor cookie. long-lived share and sign-in cookies remain untouched.
	host, _ := url.Parse(origin)
	forgetPermission := func() {
		jar.SetCookies(host, []*http.Cookie{{Name: httpaccess.VisitorTokenCookie, Path: "/", Secure: true, MaxAge: -1}})
	}
	before := permissions.Load()
	forgetPermission()
	visit("/", http.StatusOK, "app-after-restart")
	visit("/__tnl/team/session", http.StatusOK, `"signed_in":true`)
	report("after-restart", http.StatusOK)
	if permissions.Load() <= before || redemptions.Load() != 1 || signins.Load() != 1 {
		t.Fatal("restart reused old permission or required another share redemption/sign-in")
	}
	// remove a separate share creator, not the still-authorized publisher owner.
	creatorMember := f.membership(creator.Identity.Identity.Id, team.ID)
	if err := f.d.RemoveMembership(ctx, owner.Identity.Identity.Id, team.ID, creatorMember.ID, f.now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.d.ReadPublisherVisitorPolicy(ctx, current.Subject, current.RunID, current.Number, current.Token.String(), 0, f.now); err != nil {
		t.Fatal("creator removal unexpectedly revoked the publisher", err)
	}
	forgetPermission()
	visit("/", http.StatusForbidden, "visitor session expired")
	report("removed-creator", http.StatusForbidden)
	if redemptions.Load() != 1 || signins.Load() != 1 {
		t.Fatal("creator denial attempted another manual redemption/sign-in")
	}
}
