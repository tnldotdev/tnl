package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
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
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	control, err := controlapi.NewHandler(controlapi.Config{ControlURL: server.URL, OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, d, d, nil)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityapi.NewHandler(authorityapi.Config{ControlURL: server.URL, ManagedDomain: "example.test", OIDCIssuer: server.URL + "/oidc", OIDCClientID: "fixture", OIDCClientSecret: "fixture", OIDCScopes: []string{"openid"}}, d)
	if err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, pattern := authority.Handler(r)
		if pattern != "/" {
			authority.ServeHTTP(w, r)
		} else {
			control.ServeHTTP(w, r)
		}
	}))
	original := http.DefaultTransport
	http.DefaultTransport = server.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	ownerAuthority, err := authorityclient.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	adminAuthority, err := authorityclient.New(server.URL, server.Client(), admin.AccessToken)
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
	ownerControl, err := controlclient.New(server.URL, server.Client(), owner.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	adminControl, err := controlclient.New(server.URL, server.Client(), admin.AccessToken)
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
	if err := os.WriteFile(configFile, []byte(`{"version":1,"tnl":{"publishers":{"production":{}},"services":{"remote":{"publisher":"production","target":{"type":"address","address":"http://app.internal:3000"}},"localdb":{"target":{"type":"app"}}}}}`), 0600); err != nil {
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
	local, err := ownerControl.RealizeLocalProjectService(ctx, source.Key, "localdb", controlv1.RealizeLocalProjectServiceRequest{TeamId: team.Id, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey(), WorktreeLabel: new(project.Worktree.Label.FullLabel), Configuration: applied.Configuration.Services["localdb"]})
	if err != nil {
		t.Fatal(err)
	}
	remote, err := ownerControl.GetProjectPrivateService(ctx, source.Key, "remote", controlv1.GetProjectPrivateServiceParams{TeamId: team.Id, SourceFingerprint: source.Fingerprint})
	if err != nil {
		t.Fatal(err)
	}
	assertNoVisit := func() {
		t.Helper()
		services, err := adminControl.ListAvailablePrivateServices(ctx)
		if err != nil || len(services) != 0 {
			t.Fatalf("service management added visit permission: %+v %v", services, err)
		}
	}
	assertNoVisit()
	for _, item := range []struct{ key, id string }{{"localdb", local.ServiceId}, {"remote", remote.Id}} {
		t.Run(item.key, func(t *testing.T) {
			before, err := ownerControl.ListPrivateServiceGrants(ctx, item.id)
			if err != nil {
				t.Fatal(err)
			}
			for _, selector := range []string{item.id, item.key} {
				deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)
				data, err := call(admin.AccessToken.String(), "invite", "create", selector, "--email=owner@example.test", "--expires-at="+deadline.Format(time.RFC3339Nano))
				if err != nil {
					t.Fatalf("manager without a visit grant could not invite using %s: %v", selector, err)
				}
				var invite controlv1.PrivateServiceInvitation
				if err := json.Unmarshal(data, &invite); err != nil || invite.PrivateServiceId != item.id || !invite.ExpiresAt.Equal(deadline) || invite.Secret == nil {
					t.Fatalf("invitation lost its exact resource or lifetime: %+v %v", invite, err)
				}
				if _, err := call(admin.AccessToken.String(), "list", selector); err != nil {
					t.Fatal("manager could not list exact-service access", err)
				}
				if _, err := call(admin.AccessToken.String(), "revoke", selector, invite.Id); err != nil {
					t.Fatal("manager could not revoke the invitation", err)
				}
			}
			after, err := ownerControl.ListPrivateServiceGrants(ctx, item.id)
			if err != nil || !reflect.DeepEqual(before, after) {
				t.Fatal("selection changed service grants to authorize its own lookup", err)
			}
			assertNoVisit()
		})
	}
	if _, err := ownerAuthority.SetMembershipRole(ctx, team.Id, membership.Id, "member"); err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{"localdb", "remote", local.ServiceId, remote.Id} {
		if _, err := call(admin.AccessToken.String(), "list", selector); !errors.Is(err, controlclient.ErrNotFound) {
			t.Fatalf("demoted manager retained access to %s: %v", selector, err)
		}
	}
	assertNoVisit()
}
