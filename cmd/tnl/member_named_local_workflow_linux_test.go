package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// named local publication uses a fresh member, service and exact publisher grant.
// the owner creates only the team/invitation, never saved project intent.
func TestIntegrationCLIMemberFreshNamedLocalPublicationWithoutInventory(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	binary := workflowExecutable(t)
	ownerState := f.state(t, "named-owner")
	f.loginPerson(t, ownerState)
	owner, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: ownerState}, "named member fixture", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	team, err := owner.Authenticated().Authority.CreateTeam(t.Context(), authorityv1.CreateTeamRequest{DisplayName: "member-named-local"}, "named-team")
	if err != nil {
		t.Fatal(err)
	}
	connection, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	// session issuance is setup, not an OIDC-login proof. read the actual
	// configured issuer from the owner's fixture identity without changing it.
	var issuer string
	if err := connection.QueryRow(t.Context(), `SELECT issuer FROM control.identities WHERE id=$1`, owner.Identity().Identity.Id).Scan(&issuer); err != nil {
		t.Fatal(err)
	}
	database, err := controlstate.Open(t.Context(), f.databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now()
	session, err := database.CreateOIDCControlSession(t.Context(), "apps.integration.test", controlstate.OIDCIdentity{
		Issuer: issuer, Subject: "ordinary-named-local-publisher", DisplayName: "ordinary named publisher",
		AssertionDigest: sha256.Sum256([]byte("ordinary-named-local-publisher")), AssertionExpiry: now.Add(time.Hour),
	}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	memberState := f.state(t, "named-member")
	state, err := clientstate.Open(t.Context(), memberState)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	profile, err := state.Server(t.Context(), f.url)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveControlSession(t.Context(), clientstate.ControlSession{
		SessionID: session.SessionID, AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, RefreshExpiresAt: session.RefreshExpiresAt,
	}); err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(f.url, nil, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	control, err := clientcontrol.New(f.url, nil, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	invitation, err := owner.Authenticated().Authority.CreateTeamInvitation(t.Context(), team.Id,
		authorityv1.CreateInvitationRequest{MemberSlug: "implementer", InitialRole: "member", ExpiresAt: now.Add(time.Hour)}, "named-member")
	if err != nil {
		t.Fatal(err)
	}
	member, err := authority.AcceptInvitation(t.Context(), invitation.Secret)
	if err != nil {
		t.Fatal(err)
	}
	assertMember := func() {
		t.Helper()
		identity, err := authority.IdentityContext(t.Context())
		if err != nil || identity.Identity.Administrator {
			t.Fatal("named publisher acquired administration", err)
		}
		for _, current := range identity.Memberships {
			if current.TeamId == team.Id && current.Id == member.Id && current.Role == "member" && current.MemberSlug == "implementer" {
				return
			}
		}
		t.Fatal("named publisher membership changed")
	}
	assertInventoryDenied := func() {
		t.Helper()
		items, err := control.ListServices(t.Context(), team.Id)
		var problem *clientcontrol.ProblemError
		if !errors.As(err, &problem) || problem.Status != 404 || problem.Problem.Code != controlv1.NotFound || len(items) != 0 {
			t.Fatal("named publication opened management inventory", err)
		}
	}
	assertMember()
	assertInventoryDenied()
	if items, err := owner.Authenticated().Control.ListServices(t.Context(), team.Id); err != nil || len(items) != 0 {
		t.Fatal("named member fixture precreated a service", err)
	}
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/member-named" {
			requests.Add(1)
		}
		_, _ = io.WriteString(w, "member named local app")
	}))
	t.Cleanup(target.Close)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(root, "tnl.json")
	data, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{
		"server": f.url, "team": team.Id, "services": map[string]any{"web": map[string]any{}, "unselected": map[string]any{}},
		"deployments": map[string]any{"local": map[string]any{"targets": map[string]any{
			"web": map[string]any{"address": target.URL, "public": true, "http": map[string]any{"access": "anonymous"}},
		}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configuration, data, 0o600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "infrastructure.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	t.Chdir(root)
	project, err := loadProjectConfiguration(t.Context(), cli{ConfigPath: configuration}, memberState)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, _, err := project.Snapshot()
	if err != nil {
		t.Fatal(err)
	}
	ownerCommand := exec.Command(binary, "--no-telemetry", "runtime", "serve", "--directory", root, "--state-dir", memberState, "--snapshot-stdin")
	ownerCommand.Stdin = bytes.NewReader(snapshot)
	ownerProcess := startNamedWorkflowCommand(t, ownerCommand)
	descriptor, err := publisherprotocol.DescriptorPath(memberState, root)
	if err != nil {
		t.Fatal(err)
	}
	ownerProcess.wait(t, 15*time.Second, func(ctx context.Context) (bool, string) {
		endpoint, err := publisherprotocol.ReadEndpoint(descriptor)
		if err == nil {
			err = publisherprotocol.Call(ctx, endpoint, "GET", "/v1/health", nil, nil)
		}
		return err == nil, fmt.Sprint(err)
	})
	process := startNamedWorkflowCommand(t, exec.Command(binary, "--no-telemetry", "--config", configuration,
		"publish", "web", "--foreground", "--output", "ndjson", "--state-dir", memberState))
	var ready publishEvent
	process.wait(t, 30*time.Second, func(context.Context) (bool, string) {
		for _, line := range strings.Split(process.log.String(), "\n") {
			if json.Unmarshal([]byte(line), &ready) == nil && ready.Type == publishEventReady {
				return true, ""
			}
		}
		return false, "waiting for fresh named member publication"
	})
	var id, hostname, run, grantKind, grantService, grantCreator, publisherMember, localCreator string
	var number int64
	var count, applied int
	source := project.LocalPublicationIdentity()
	err = connection.QueryRow(t.Context(), `SELECT l.service_id,s.certificate_hostname,r.id,r.run_number,
		g.kind,g.service_id,g.created_by_identity_id,p.owner_membership_id,l.created_by_identity_id,
		(SELECT count(*) FROM control.local_project_services WHERE team_id=$1),
		(SELECT count(*) FROM control.applied_projects WHERE team_id=$1)
		FROM control.local_project_services l JOIN control.services s ON s.id=l.service_id
		JOIN control.service_runs r ON r.service_id=s.id AND r.closed_at IS NULL
		JOIN control.publisher_grants g ON g.id=r.publisher_grant_id
		JOIN control.publisher_identities p ON p.id=r.publisher_identity_id
		WHERE l.team_id=$1 AND l.project_key=$2 AND l.source_fingerprint=$3 AND l.service='web' AND l.worktree_key=$4`,
		team.Id, source.Key, source.Fingerprint, project.LocalWorktreeKey()).Scan(&id, &hostname, &run, &number,
		&grantKind, &grantService, &grantCreator, &publisherMember, &localCreator, &count, &applied)
	if err != nil || count != 1 || applied != 0 || grantKind != "service" || grantService != id ||
		grantCreator != member.IdentityId || localCreator != member.IdentityId || publisherMember != member.Id ||
		ready.URL != "https://"+hostname || ready.TunnelID == "" || ready.PublishRunNumber <= 0 ||
		!strings.HasSuffix(hostname, "."+member.ManagedLabel+".apps.integration.test") {
		t.Fatal("built named publication lost fresh local/member/exact-grant authority", err)
	}
	process.wait(t, 15*time.Second, func(ctx context.Context) (bool, string) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, ready.URL+"/member-named", nil)
		if err != nil {
			return false, err.Error()
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return false, err.Error()
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
		return err == nil && response.StatusCode == 200 && string(body) == "member named local app" && requests.Load() > 0,
			fmt.Sprintf("visitor status=%d target_requests=%d error=%v", response.StatusCode, requests.Load(), err)
	})
	assertMember()
	assertInventoryDenied()
	process.stop()
	ownerProcess.stop()
	assertMember()
	assertInventoryDenied()
	t.Logf("built named member publication: service_id=%s service_run_id=%s run_number=%d; selected local app only; inventory denied", id, run, number)
}
