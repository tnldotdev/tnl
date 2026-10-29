package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/zalando/go-keyring"
)

func TestIntegrationServiceShareManagerLookup(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	keyring.MockInit()
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "share_manager_lookup")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
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
	control, err := controlpublic.NewHandler(controlpublic.Config{ControlURL: server.URL, OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, d, d, nil)
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
				var invitation controlv1.ServiceInvitation
				if recorded.Code != http.StatusCreated || json.Unmarshal(recorded.Body.Bytes(), &invitation) != nil || invitation.Secret == nil {
					t.Error("lost-response fixture did not commit an invitation")
				}
				lostInvitationID.Store(invitation.Id)
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
	if err := os.WriteFile(configFile, []byte(`{"version":1,"tnl":{"publisher_groups":{"production":{}},"services":{"remote":{"publisher_group":"production","target":{"type":"address","address":"http://app.internal:3000"}},"localdb":{"target":{"type":"app"}}}}}`), 0600); err != nil {
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
	remote, err := ownerControl.GetProjectService(ctx, source.Key, "remote", controlv1.GetProjectServiceParams{TeamId: team.Id, SourceFingerprint: source.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	assertNoVisit := func() {
		t.Helper()
		services, err := adminControl.ListAvailableServices(ctx)
		if err != nil || len(services) != 0 {
			t.Fatalf("service management added visit permission: %+v %v", services, err)
		}
	}
	assertNoVisit()
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
				var invite controlv1.ServiceInvitation
				if err := json.Unmarshal(data, &invite); err != nil || invite.ServiceId != item.id || !invite.ExpiresAt.Equal(deadline) || invite.Secret == nil {
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
		data, firstErr := call(admin.AccessToken.String(), "invite", args...)
		// net/http may itself retry an idempotent POST on a reused connection.
		if firstErr == nil {
			var recovered controlv1.ServiceInvitation
			if err := json.Unmarshal(data, &recovered); err != nil || recovered.Secret != nil {
				t.Fatal("automatic retry returned a new secret", err)
			}
		}
		data, err := call(admin.AccessToken.String(), "invite", args...)
		if err != nil {
			t.Fatal("lost committed invitation did not recover", err)
		}
		var recovered controlv1.ServiceInvitation
		if err := json.Unmarshal(data, &recovered); err != nil || recovered.Id != lostInvitationID.Load() || recovered.Secret != nil || recovered.ServiceId != remote.Id || !recovered.ExpiresAt.Equal(deadline) {
			t.Fatal("retry lost the original exact-service ID", err)
		}
		changed := append([]string(nil), args...)
		changed[2] = "--email=other@example.test"
		if _, err := call(admin.AccessToken.String(), "invite", changed...); !errors.Is(err, clientcontrol.ErrStatusConflict) {
			t.Fatal("changed retry did not conflict", err)
		}
		if _, err := call(admin.AccessToken.String(), "revoke", remote.Id, recovered.Id); err != nil {
			t.Fatal(err)
		}
		args[len(args)-1] = "--idempotency-key=cli-reissued"
		data, err = call(admin.AccessToken.String(), "invite", args...)
		if err != nil {
			t.Fatal(err)
		}
		var reissued controlv1.ServiceInvitation
		if err := json.Unmarshal(data, &reissued); err != nil || reissued.Secret == nil || reissued.Id == recovered.Id {
			t.Fatal("explicit reissue did not create a deliverable invitation", err)
		}
		assertNoVisit()
	})
	if _, err := ownerAuthority.SetMembershipRole(ctx, team.Id, membership.Id, "member"); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"localdb", "remote", local.ServiceId, remote.Id} {
		if _, err := call(admin.AccessToken.String(), "list", selector); !errors.Is(err, clientcontrol.ErrNotFound) {
			t.Fatalf("demoted manager retained access to %s: %v", selector, err)
		}
	}
	assertNoVisit()
}
