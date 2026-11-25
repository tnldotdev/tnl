package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationServiceShareManagerLookup(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	clientstate.UseMemoryKeychainForTesting()
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "share_manager_lookup")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now); err != nil {
		t.Fatal(err)
	}
	person := func(subject, email string) controlstate.ControlSession {
		t.Helper()
		session, err := d.CreateOIDCControlSession(ctx, "example.test", controlstate.OIDCIdentity{
			Issuer: "https://identity.fixture.test", Subject: subject, DisplayName: subject,
			NormalizedEmail: email, EmailVerified: true, AssertionDigest: sha256.Sum256([]byte("share-manager/" + subject)), AssertionExpiry: now.Add(time.Hour),
		}, time.Hour, 24*time.Hour, now)
		if err != nil {
			t.Fatal(err)
		}
		return session
	}
	owner, admin := person("operator", "owner@example.test"), person("manager", "manager@example.test")
	mux := http.NewServeMux()
	var loseInvitationResponse atomic.Bool
	var lostInvitationID atomic.Value
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	control, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, controlpublic.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := controlauthority.NewHandler(controlauthority.Config{ControlURL: server.URL, ManagedDomain: "example.test", OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, d)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := authority.Handler(r)
		if pattern != "/" {
			authority.ServeHTTP(w, r)
		} else {
			if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/invitations") && loseInvitationResponse.CompareAndSwap(true, false) {
				recorded := httptest.NewRecorder()
				control.ServeHTTP(recorded, r)
				var invitation controlv1.ServiceInvitationCreation
				if recorded.Code != http.StatusCreated || json.Unmarshal(recorded.Body.Bytes(), &invitation) != nil || invitation.Credential == "" {
					t.Error("lost-response fixture did not commit an invitation")
				}
				lostInvitationID.Store(invitation.Invitation.Id)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = conn.Close()
				return
			}
			control.ServeHTTP(w, r)
		}
	}))
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	ownerAuthority, err := clientauthority.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	adminAuthority, err := clientauthority.New(server.URL, server.Client(), admin.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	team, err := ownerAuthority.CreateTeam(ctx, authorityv1.CreateTeamRequest{DisplayName: "share-managers"}, "share-managers")
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := ownerAuthority.CreateTeamInvitation(ctx, team.Id, authorityv1.CreateInvitationRequest{MemberSlug: "manager", InitialRole: "admin", ExpiresAt: now.Add(time.Hour)}, "manager-membership")
	if err != nil {
		t.Fatal(err)
	}
	membership, err := adminAuthority.AcceptInvitation(ctx, invitation.Secret)
	if err != nil {
		t.Fatal(err)
	}
	ownerControl, err := clientcontrol.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	adminControl, err := clientcontrol.New(server.URL, server.Client(), admin.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	t.Run("checkout shares only accounts and revokes the receipt ID", func(t *testing.T) {
		t.Setenv("TNL_OUTPUT", "auto")
		state := filepath.Join(t.TempDir(), "state")
		path := filepath.Join(t.TempDir(), "tnl.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"tnl":{"services":{"accounts":{},"api":{}},"deployments":{"local":{"targets":{"accounts":{"public":true},"api":{"public":true}}}}}}`), 0600); err != nil {
			t.Fatal(err)
		}
		project, err := loadProjectConfiguration(ctx, cli{ConfigPath: path}, state)
		if err != nil {
			t.Fatal(err)
		}
		source := project.LocalPublicationIdentity()
		preview, err := ownerControl.CreatePreview(ctx, team.Id, "accounts-checkout")
		if err != nil {
			t.Fatal(err)
		}
		services := make(map[string]controlv1.Service, 2)
		for _, name := range []string{"accounts", "api"} {
			local, err := ownerControl.RealizeLocalProjectService(ctx, source.Key, name, controlv1.RealizeLocalProjectServiceRequest{
				TeamId: team.Id, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), WorktreeLabel: new(project.Worktree.Label.FullLabel),
				Configuration: controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocolHTTP), Target: "app", Public: new(true)},
			})
			if err != nil {
				t.Fatal("realize checkout service", name, err)
			}
			saved, err := ownerControl.GetService(ctx, local.ServiceId)
			if err != nil || saved.Endpoint == nil || !saved.Endpoint.Public {
				t.Fatal("load public checkout service", name, err)
			}
			services[name] = saved
			if _, err := ownerControl.AddPreviewService(ctx, preview.Id, saved.Id); err != nil {
				t.Fatal("attach checkout service", name, err)
			}
		}
		db, err := clientstate.Open(ctx, state)
		if err != nil {
			t.Fatal(err)
		}
		store, err := db.Server(ctx, server.URL)
		if err == nil {
			err = store.SavePreviewID(ctx, team.Id, project.LocalWorktreeKey(), preview.Id)
		}
		if err := errors.Join(err, db.Close()); err != nil {
			t.Fatal(err)
		}
		invoke := func(args ...string) (string, error) {
			t.Helper()
			argv := append([]string{"--config", path, "--no-telemetry", "share"}, args...)
			argv = append(argv, "--server", server.URL, "--access-token", owner.AccessToken.String(), "--team", team.Id, "--state-dir", state)
			var output, diagnostics bytes.Buffer
			err := run(ctx, argv, &output, &diagnostics)
			if diagnostics.Len() != 0 {
				t.Fatal("share wrote unexpected diagnostics")
			}
			return output.String(), err
		}
		// neither a typo nor an omitted selector should be substituted for the other.
		if out, err := invoke("acounts", "--expires-in", "1h", "--output=json"); out != "" || err == nil {
			t.Fatal("mistyped selector produced a share")
		} else if reason, _ := failure.ReasonOf(err); reason != failure.ShareInputInvalid {
			t.Fatal("mistyped selector did not return a share input error", err)
		}
		if shares, err := ownerControl.ListTeamShares(ctx, team.Id); err != nil || len(shares) != 0 {
			t.Fatal("mistyped selector created a share in control", err)
		}
		sourceFromLink := func(link string, service controlv1.Service) controlv1.VisitorTokenShareSource {
			t.Helper()
			value, ok := strings.CutPrefix(link, "https://"+service.Endpoint.Hostname+"/__tnl/share/")
			id, secret, _ := strings.Cut(value, ".")
			if !ok || !opaqueid.Valid(id, opaqueid.SharePrefix) || !serviceShareSecret(value, id) {
				t.Fatal("output was not one exact share link for the selected service")
			}
			return controlv1.VisitorTokenShareSource{Kind: controlv1.VisitorTokenShare, ShareId: id, Secret: secret}
		}
		api, accounts := services["api"], services["accounts"]
		raw, err := invoke("api", "--expires-in", "1h")
		apiLink, newline := strings.CutSuffix(raw, "\n")
		if err != nil || !newline {
			t.Fatal("default share did not print one link", err)
		}
		apiSource := sourceFromLink(apiLink, api)
		started := time.Now()
		raw, err = invoke("accounts", "--expires-in", "1h", "--output", "json")
		var receipt struct {
			SchemaVersion int       `json:"schema_version"`
			ShareID       string    `json:"share_id"`
			EntryURL      string    `json:"entry_url"`
			ServiceIDs    []string  `json:"service_ids"`
			ExpiresAt     time.Time `json:"expires_at"`
		}
		if err != nil || json.Unmarshal([]byte(raw), &receipt) != nil || receipt.SchemaVersion != 1 ||
			!slices.Equal(receipt.ServiceIDs, []string{accounts.Id}) || receipt.ExpiresAt.Before(started.Add(time.Hour).Truncate(time.Microsecond)) ||
			receipt.ExpiresAt.After(time.Now().Add(time.Hour)) {
			t.Fatal("checkout share did not return one scoped one-hour receipt", err)
		}
		accountsSource := sourceFromLink(receipt.EntryURL, accounts)
		if accountsSource.ShareId != receipt.ShareID || accountsSource.ShareId == apiSource.ShareId {
			t.Fatal("link and revocation ID did not identify the same new share")
		}
		saved, err := ownerControl.GetShare(ctx, receipt.ShareID)
		if err != nil || saved.Scope != "service" || saved.PreviewId != nil || saved.TeamId != team.Id ||
			!slices.Equal(saved.ServiceIds, receipt.ServiceIDs) || saved.EntryServiceId != accounts.Id || !saved.ExpiresAt.Equal(receipt.ExpiresAt) || saved.RevokedAt != nil {
			t.Fatal("receipt did not match the saved share", err)
		}
		assertPermission := func(tokenSource controlv1.VisitorTokenShareSource, service controlv1.Service, allowed bool) {
			t.Helper()
			body, err := json.Marshal(tokenSource)
			if err != nil {
				t.Fatal("could not encode share source")
			}
			scope := controlv1.VisitorResourceScope{Kind: "service", Id: service.Id}
			result, err := ownerControl.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: scope, Source: body})
			reason, _ := failure.ReasonOf(err)
			if allowed && (err != nil || result.Resource != scope || result.VisitorToken == "") ||
				!allowed && (reason != failure.ServerDenied || result.VisitorToken != "") {
				t.Fatalf("unexpected visitor permission for service %s (want allowed=%t): %s", service.Id, allowed, reason)
			}
		}
		assertPermission(accountsSource, accounts, true)
		assertPermission(accountsSource, api, false)
		if out, err := invoke("revoke", receipt.ShareID); err != nil || out != "Revoked share "+receipt.ShareID+"\n" {
			t.Fatal("revoking the receipt ID did not confirm the exact share", err)
		}
		revoked, err := ownerControl.GetShare(ctx, receipt.ShareID)
		if err != nil || revoked.RevokedAt == nil || !slices.Equal(revoked.ServiceIds, receipt.ServiceIDs) {
			t.Fatal("control did not revoke the exact captured share", err)
		}
		assertPermission(accountsSource, accounts, false)
		assertPermission(apiSource, api, true)
	})
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/share/project.git"}} {
		if output, err := exec.CommandContext(ctx, "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("fixture git: %v %s", err, output)
		}
	}
	configFile, state := filepath.Join(root, "tnl.json"), filepath.Join(root, "state")
	if err := os.WriteFile(configFile, []byte(`{"version":1,"tnl":{"services":{"remote":{},"localdb":{}},"deployments":{"production":{"targets":{"remote":{"address":"http://app.internal:3000"}}},"staging":{"targets":{"remote":{"address":"http://staging.internal:3000"}}},"local":{"targets":{"localdb":{}}}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	call := func(token, command string, args ...string) ([]byte, error) {
		t.Helper()
		argv := []string{"--config", configFile, "--no-telemetry"}
		if command == "apply" {
			argv = append(argv, "apply")
		} else {
			argv = append(argv, "share", "service", command)
		}
		argv = append(argv, args...)
		if command != "apply" && !slices.Contains(args, "--deployment") {
			for _, arg := range args {
				if arg == "remote" {
					argv = append(argv, "--deployment", "production")
					break
				}
			}
		}
		argv = append(argv, "--server", server.URL, "--access-token", token, "--team", team.Id, "--state-dir", state, "--output=json")
		var output, diagnostics bytes.Buffer
		err := run(ctx, argv, &output, &diagnostics)
		if diagnostics.Len() != 0 {
			t.Fatalf("signed-in management prompted for more authorization: %s", &diagnostics)
		}
		return output.Bytes(), err
	}
	data, err := call(owner.AccessToken.String(), "apply")
	if err != nil {
		t.Fatal(err)
	}
	var applied controlv1.AppliedProjectConfiguration
	if err := json.Unmarshal(data, &applied); err != nil {
		t.Fatal(err)
	}
	if _, err := call(owner.AccessToken.String(), "apply", "--deployment", "production"); err != nil {
		t.Fatal(err)
	}
	if _, err := call(owner.AccessToken.String(), "apply", "--deployment", "staging"); err != nil {
		t.Fatal(err)
	}
	project, err := loadProjectConfiguration(ctx, cli{ConfigPath: configFile}, state)
	if err != nil {
		t.Fatal(err)
	}
	source, err := project.SourceIdentity(ctx)
	if err != nil {
		t.Fatal(err)
	}
	localSource := project.LocalPublicationIdentity()
	local, err := ownerControl.RealizeLocalProjectService(ctx, localSource.Key, "localdb", controlv1.RealizeLocalProjectServiceRequest{TeamId: team.Id, SourceFingerprint: localSource.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), WorktreeLabel: new(project.Worktree.Label.FullLabel), Configuration: applied.Configuration.Services["localdb"]})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := ownerControl.GetProjectService(ctx, source.Key, "remote", controlv1.GetProjectServiceParams{TeamId: team.Id, SourceFingerprint: source.Fingerprint, Deployment: "production"})
	if err != nil {
		t.Fatal(err)
	}
	assertNoVisit := func() {
		t.Helper()
		for _, path := range []controlv1.ServiceAccessPath{controlv1.ServiceAccessPathConnector, controlv1.ServiceAccessPathPublicEndpoint} {
			services, err := adminControl.ListAvailableServices(ctx, path)
			if err != nil || len(services) != 0 {
				t.Fatalf("service management added %s discovery permission: %+v %v", path, services, err)
			}
		}
	}
	assertNoVisit()
	t.Run("HTTP links and tokens use ordinary exact-service shares", func(t *testing.T) {
		service, err := ownerControl.CreateService(ctx, team.Id, "share-web", "share-web", controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocolHTTP},
			&controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocolHTTP), Public: new(true), Target: "http://app.internal:3000"})
		if err != nil {
			t.Fatal(err)
		}
		for _, command := range []string{"link", "token"} {
			data, err := call(admin.AccessToken.String(), command, "create", service.Id, "--expires-in=1h")
			if err != nil {
				t.Fatal("manager without visitor access could not share the exact service", err)
			}
			var printed struct {
				ShareID    string   `json:"share_id"`
				ServiceID  string   `json:"service_id"`
				ServiceIDs []string `json:"service_ids"`
				EntryURL   string   `json:"entry_url"`
				ShareToken string   `json:"share_token"`
			}
			if err := json.Unmarshal(data, &printed); err != nil || !strings.HasPrefix(printed.ShareID, "shr_") {
				t.Fatal("HTTP share did not return its ordinary share ID", err)
			}
			share, err := adminControl.GetShare(ctx, printed.ShareID)
			if err != nil || share.Scope != "service" || share.PreviewId != nil || share.TeamId != team.Id ||
				!slices.Equal(share.ServiceIds, []string{service.Id}) || share.EntryServiceId != service.Id {
				t.Fatal("HTTP share changed its defining service scope", err)
			}
			if command == "link" && (!slices.Equal(printed.ServiceIDs, []string{service.Id}) ||
				!strings.HasPrefix(printed.EntryURL, "https://"+service.Endpoint.Hostname+"/__tnl/share/"+share.Id+".") || printed.ShareToken != "") ||
				command == "token" && (printed.ServiceID != service.Id || strings.Count(printed.ShareToken, ".") != 2 || printed.EntryURL != "") ||
				bytes.Contains(data, []byte("token_source")) || bytes.Contains(data, []byte(`"secret"`)) {
				t.Fatal("HTTP share output lost its exact address or exposed authority-source fields")
			}
			listed, err := call(admin.AccessToken.String(), "list", service.Id)
			if err != nil || !bytes.Contains(listed, []byte(share.Id)) || bytes.Contains(listed, []byte("token_source")) ||
				bytes.Contains(listed, []byte(`"secret"`)) || printed.ShareToken != "" && bytes.Contains(listed, []byte(printed.ShareToken)) {
				t.Fatal("HTTP share inventory hid the ordinary share or exposed its credential", err)
			}
			httpGrants, err := adminControl.ListServiceHTTPGrants(ctx, service.Id)
			if err != nil || len(httpGrants) != 0 {
				t.Fatal("HTTP link or token created a separate HTTP credential", err)
			}
			assertNoVisit()
			if _, err := call(admin.AccessToken.String(), "revoke", service.Id, share.Id); err != nil {
				t.Fatal("exact-service workflow could not revoke its ordinary share", err)
			}
			revoked, err := adminControl.GetShare(ctx, share.Id)
			if err != nil || revoked.RevokedAt == nil {
				t.Fatal("ordinary service share stayed active after revocation", err)
			}
			assertNoVisit()
		}
	})
	t.Run("same logical key selects only its deployment", func(t *testing.T) {
		staging, err := ownerControl.GetDeployment(ctx, team.Id, source.Key, "staging")
		if err != nil {
			t.Fatal(err)
		}
		if staging.Services["remote"].Id == remote.Id {
			t.Fatal("sibling reused production service")
		}
		data, err := call(admin.AccessToken.String(), "invite", "create", "remote", "--deployment", "staging", "--email=owner@example.test", "--expires-in=1h")
		if err != nil {
			t.Fatal(err)
		}
		var invite controlv1.ServiceInvitation
		if err := json.Unmarshal(data, &invite); err != nil || invite.ServiceId != staging.Services["remote"].Id {
			t.Fatal("share borrowed a sibling", err)
		}
		if _, err := call(admin.AccessToken.String(), "revoke", "remote", invite.Id, "--deployment", "staging"); err != nil {
			t.Fatal(err)
		}
		var output bytes.Buffer
		err = run(ctx, []string{"--config", configFile, "share", "service", "list", "remote", "--server", server.URL, "--access-token", admin.AccessToken.String(), "--team", team.Id, "--state-dir", state}, &output, io.Discard)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidCommand {
			t.Fatal("missing deployment fell back to a remote binding", err)
		}
		assertNoVisit()
	})
	for _, item := range []struct{ key, id string }{{"localdb", local.ServiceId}, {"remote", remote.Id}} {
		t.Run(item.key, func(t *testing.T) {
			before, err := ownerControl.ListServiceGrants(ctx, item.id)
			if err != nil {
				t.Fatal(err)
			}
			for _, selector := range []string{item.id, item.key} {
				deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
				data, err := call(admin.AccessToken.String(), "invite", "create", selector, "--email=owner@example.test", "--expires-at="+deadline.Format(time.RFC3339Nano))
				if err != nil {
					t.Fatalf("manager without a visit grant could not invite using %s: %v", selector, err)
				}
				var invite struct {
					controlv1.ServiceInvitation
					Secret string `json:"secret"`
				}
				if err := json.Unmarshal(data, &invite); err != nil || invite.ServiceId != item.id || !invite.ExpiresAt.Equal(deadline) || invite.Secret == "" {
					t.Fatalf("invitation lost its exact resource or lifetime: %+v %v", invite, err)
				}
				if _, err := call(admin.AccessToken.String(), "list", selector); err != nil {
					t.Fatal("manager could not list exact-service access", err)
				}
				if _, err := call(admin.AccessToken.String(), "revoke", selector, invite.Id); err != nil {
					t.Fatal("manager could not revoke the invitation", err)
				}
			}
			after, err := ownerControl.ListServiceGrants(ctx, item.id)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("selection changed service grants to authorize its own lookup", err)
			}
			assertNoVisit()
		})
	}
	t.Run("complete inventory and revoke beyond first page", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close(ctx)
		for _, query := range []string{
			`INSERT INTO control.visitor_grants(id,service_id,team_id,kind,identity_id,created_by_identity_id,idempotency_key,request_digest,created_at,revoked_at)
			 SELECT 'sgr_'||lpad(n::text,22,'0'),$1,$2,'identity',$3,$3,'cli-page-grant/'||n,sha256(convert_to('grant/'||n,'UTF8')),$4::timestamptz,
			 CASE WHEN n<=120 THEN $4::timestamptz END FROM generate_series(1,205) n`,
			`INSERT INTO control.service_invitations(id,service_id,team_id,normalized_email,token_digest,created_by_identity_id,idempotency_key,request_digest,created_at,expires_at,revoked_at)
			 SELECT 'sivt_'||lpad(n::text,22,'0'),$1,$2,'owner@example.test',sha256(convert_to('token/'||n,'UTF8')),$3,'cli-page-invite/'||n,sha256(convert_to('request/'||n,'UTF8')),$4::timestamptz,$4::timestamptz+interval '1 hour',
			 CASE WHEN n<=120 THEN $4::timestamptz END FROM generate_series(1,205) n`,
		} {
			if _, err := conn.Exec(ctx, query, remote.Id, team.Id, owner.Identity.Identity.ID, now); err != nil {
				t.Fatal(err)
			}
		}
		data, err := call(admin.AccessToken.String(), "list", "remote")
		if err != nil {
			t.Fatal(err)
		}
		var listed struct {
			Grants      []controlv1.ServiceGrant      `json:"grants"`
			Invitations []controlv1.ServiceInvitation `json:"invitations"`
		}
		if err := json.Unmarshal(data, &listed); err != nil || len(listed.Grants) < 205 || len(listed.Invitations) != 207 || bytes.Contains(data, []byte(`"secret"`)) {
			t.Fatal("CLI did not list all secretless access history", err)
		}
		for _, id := range []string{fmt.Sprintf("sgr_%022d", 205), fmt.Sprintf("sivt_%022d", 205)} {
			if _, err := call(admin.AccessToken.String(), "revoke", remote.Id, id); err != nil {
				t.Fatal("CLI could not revoke access beyond the first page", err)
			}
		}
		assertNoVisit()
	})
	t.Run("lost committed response and explicit reissue", func(t *testing.T) {
		deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
		args := []string{"create", remote.Id, "--email=owner@example.test", "--expires-at=" + deadline.Format(time.RFC3339Nano), "--idempotency-key=cli-lost-response"}
		loseInvitationResponse.Store(true)
		if _, firstErr := call(admin.AccessToken.String(), "invite", args...); firstErr == nil {
			t.Fatal("lost response unexpectedly succeeded")
		}
		_, err := call(admin.AccessToken.String(), "invite", args...)
		var problem *clientcontrol.ProblemError
		if !errors.As(err, &problem) || problem.Problem.Code != controlv1.CredentialDeliveryUnavailable || problem.Problem.Details == nil || (*problem.Problem.Details)["resource_id"] != lostInvitationID.Load() {
			t.Fatal("retry lost the original exact-service ID", err)
		}
		recoveredID := lostInvitationID.Load().(string)
		changed := append([]string(nil), args...)
		changed[2] = "--email=other@example.test"
		if _, err := call(admin.AccessToken.String(), "invite", changed...); !errors.Is(err, clientcontrol.ErrStatusConflict) {
			t.Fatal("changed retry did not conflict", err)
		}
		if _, err := call(admin.AccessToken.String(), "revoke", remote.Id, recoveredID); err != nil {
			t.Fatal(err)
		}
		args[len(args)-1] = "--idempotency-key=cli-reissued"
		data, err := call(admin.AccessToken.String(), "invite", args...)
		if err != nil {
			t.Fatal(err)
		}
		var reissued struct {
			controlv1.ServiceInvitation
			Secret string `json:"secret"`
		}
		if err := json.Unmarshal(data, &reissued); err != nil || reissued.Secret == "" || reissued.Id == recoveredID {
			t.Fatal("explicit reissue did not create a deliverable invitation", err)
		}
		assertNoVisit()
	})
	if _, err := ownerAuthority.SetMembershipRole(ctx, team.Id, membership.Id, "member"); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"localdb", "remote", local.ServiceId, remote.Id} {
		want := failure.ServerResourceNotFound
		if selector == "remote" {
			want = failure.ServerDenied
		}
		_, err := call(admin.AccessToken.String(), "list", selector)
		if reason, ok := failure.ReasonOf(err); !ok || reason != want {
			t.Fatalf("demoted manager retained access to %s: %v", selector, err)
		}
	}
	assertNoVisit()
}
