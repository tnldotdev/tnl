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
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this qualifies fresh ad-hoc own-namespace publication, not named local
// realization or permission to inventory a team. the member is never promoted,
// and the team owner creates neither the service nor its publisher grant.
func TestIntegrationCLIMemberOwnPublicationWithoutInventory(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	binary := workflowExecutable(t)
	ownerState := f.state(t, "owner")
	f.loginPerson(t, ownerState)
	owner, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: ownerState}, "member publication fixture", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	team, err := owner.Authenticated().Authority.CreateTeam(t.Context(), authorityv1.CreateTeamRequest{DisplayName: "member-publication"}, "member-publication")
	if err != nil {
		t.Fatal(err)
	}
	memberState, memberAuthority, memberControl := memberPublicationPerson(t, f)
	invitation, err := owner.Authenticated().Authority.CreateTeamInvitation(t.Context(), team.Id,
		authorityv1.CreateInvitationRequest{MemberSlug: "implementer", InitialRole: "member", ExpiresAt: time.Now().Add(time.Hour)}, "ordinary-member")
	if err != nil {
		t.Fatal(err)
	}
	member, err := memberAuthority.AcceptInvitation(t.Context(), invitation.Secret)
	if err != nil {
		t.Fatal(err)
	}
	assertMember := func() {
		t.Helper()
		identity, err := memberAuthority.IdentityContext(t.Context())
		if err != nil || identity.Identity.Administrator || identity.Identity.Id != member.IdentityId {
			t.Fatal("ordinary publication identity changed or acquired server administration", err)
		}
		for _, current := range identity.Memberships {
			if current.TeamId == team.Id {
				if current.Id != member.Id || current.Role != "member" || current.MemberSlug != "implementer" {
					t.Fatal("publication changed the ordinary membership")
				}
				return
			}
		}
		t.Fatal("ordinary publication membership disappeared")
	}
	assertMember()
	services, err := owner.Authenticated().Control.ListServices(t.Context(), team.Id)
	if err != nil || len(services) != 0 {
		t.Fatal("fixture precreated a service instead of letting the member publish", err)
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "infrastructure.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	command := func(args ...string) *exec.Cmd {
		argv := append([]string{"--no-config", "--no-telemetry"}, args...)
		argv = append(argv, "--server", f.url, "--state-dir", memberState)
		cmd := exec.CommandContext(t.Context(), binary, argv...)
		cmd.Dir = root
		return cmd
	}
	call := func(args ...string) []byte {
		t.Helper()
		var stdout, stderr bytes.Buffer
		cmd := command(args...)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			t.Fatalf("built member CLI %s: %v\n%s", args[0], err, &stderr)
		}
		return stdout.Bytes()
	}
	assertInventoryDenied := func(serviceID string) {
		t.Helper()
		items, err := memberControl.ListServices(t.Context(), team.Id)
		var problem *clientcontrol.ProblemError
		if !errors.As(err, &problem) || problem.Status != http.StatusNotFound ||
			problem.Problem.Code != controlv1.NotFound || len(items) != 0 {
			t.Fatal("ordinary member acquired broad inventory or lost its concealed-denial contract", err)
		}
		var stdout, stderr bytes.Buffer
		cmd := command("url", "inventory", "--team", team.Id)
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err = cmd.Run()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || stdout.Len() != 0 ||
			!bytes.Contains(stderr.Bytes(), []byte(failure.ServerResourceNotFound)) ||
			serviceID != "" && bytes.Contains(stderr.Bytes(), []byte(serviceID)) {
			t.Fatal("built CLI inventory succeeded or disclosed a service instead of preserving denial", err)
		}
	}
	assertInventoryDenied("")
	const namespace = "implementer.member-publication.apps.integration.test"
	current := call("team", "current", "--team", team.Id)
	if want := team.DisplayName + " (member)\nNew named URL: https://app." + namespace + "\n"; string(current) != want {
		t.Fatalf("built CLI selected a different team or membership: got %q, want %q", current, want)
	}
	var requests atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/g357" {
			requests.Add(1)
		}
		_, _ = io.WriteString(w, "ordinary member application")
	}))
	t.Cleanup(target.Close)
	hostname := "own-app." + namespace
	process := startNamedWorkflowCommand(t, command("publish", target.URL, "--foreground", "--output", "ndjson",
		"--name", "own-app", "--anonymous", "--team", team.Id))
	var ready publishEvent
	process.wait(t, 30*time.Second, func(context.Context) (bool, string) {
		for _, line := range strings.Split(process.log.String(), "\n") {
			var event publishEvent
			if json.Unmarshal([]byte(line), &event) == nil && event.Type == publishEventReady {
				ready = event
				return true, ""
			}
		}
		return false, "waiting for built CLI ready event"
	})
	if ready.SchemaVersion != 1 || ready.TunnelID == "" || ready.PublishRunNumber == 0 || ready.URL != "https://"+hostname {
		t.Fatal("built member publication returned the wrong namespace or lifecycle tuple")
	}
	var status statusResult
	if err := json.Unmarshal(call("status", "--scope", "local", "--output", "json"), &status); err != nil {
		t.Fatal(err)
	}
	if status.SchemaVersion != 1 || status.Scope != "local" || len(status.Projects) != 1 ||
		status.Projects[0].Project != root || status.Projects[0].Local == nil ||
		len(status.Projects[0].Local.Tunnels.Tunnels) != 1 {
		t.Fatal("built CLI status lost the isolated member publication")
	}
	local := status.Projects[0].Local.Tunnels.Tunnels[0]
	if local.ID != ready.TunnelID || local.State != clientstate.TunnelStateReady || local.Server != f.url ||
		local.Hostname != hostname || local.PublicURL != ready.URL || local.Target != target.URL ||
		local.PublishRunNumber != ready.PublishRunNumber || local.ServiceID == "" {
		t.Fatal("built CLI status changed the ready service tuple")
	}
	saved, err := memberControl.GetService(t.Context(), local.ServiceID)
	if err != nil || saved.Id != local.ServiceID || saved.TeamId != team.Id || saved.Protocol != controlv1.ServiceProtocolHTTP ||
		saved.Endpoint == nil || !saved.Endpoint.Public || saved.Endpoint.Hostname != hostname || saved.Endpoint.Port != 443 ||
		!saved.Enabled {
		t.Fatal("member could not read its exact saved service", err)
	}
	// management reads do not select a run or grant connector access. inspect the
	// exact CLI-observed run and its ownership without adding a visitor grant.
	connection, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var runID, membershipID, publisherCreator, grantKind, grantedService, grantCreator string
	err = connection.QueryRow(t.Context(), `SELECT r.id,p.owner_membership_id,p.created_by_identity_id,g.kind,g.service_id,g.created_by_identity_id
		FROM control.service_runs r JOIN control.publisher_identities p ON p.id=r.publisher_identity_id
		JOIN control.publisher_grants g ON g.id=r.publisher_grant_id AND g.publisher_identity_id=p.id
		WHERE r.service_id=$1 AND r.run_number=$2 AND r.team_id=$3 AND r.closed_at IS NULL
			AND r.state='ready' AND r.healthy AND r.serving_until>now() AND r.certificate_expires_at>now()`,
		saved.Id, ready.PublishRunNumber, team.Id).Scan(&runID, &membershipID, &publisherCreator, &grantKind, &grantedService, &grantCreator)
	if err != nil || runID == "" || membershipID != member.Id || publisherCreator != member.IdentityId ||
		grantKind != "service" || grantedService != saved.Id || grantCreator != member.IdentityId {
		t.Fatal("publication did not use the ordinary member's own exact publisher grant", err)
	}
	process.wait(t, 15*time.Second, func(ctx context.Context) (bool, string) {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, ready.URL+"/g357", nil)
		if err != nil {
			return false, err.Error()
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			return false, err.Error()
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 1024))
		return err == nil && response.StatusCode == http.StatusOK && string(body) == "ordinary member application" && requests.Load() > 0,
			fmt.Sprintf("visitor status=%d target_requests=%d error=%v", response.StatusCode, requests.Load(), err)
	})
	assertMember()
	assertInventoryDenied(saved.Id)
	process.stop()
	assertMember()
	t.Logf("built CLI member publication: team_id=%s service_id=%s service_run_id=%s run_number=%d tunnel_id=%s; broad inventory remains denied; scope=ad-hoc own namespace",
		team.Id, saved.Id, runID, ready.PublishRunNumber, ready.TunnelID)
}

// session issuance is fixture setup, not an OIDC-login proof. use the configured
// issuer and a distinct unseeded subject, then admit it only as an ordinary member.
// credentials stay in protected state and never enter subprocess arguments/logs.
func memberPublicationPerson(t *testing.T, f *cliWorkflow) (string, *clientauthority.Client, *clientcontrol.Client) {
	t.Helper()
	database, err := controlstate.Open(t.Context(), f.databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	now := time.Now()
	session, err := database.CreateOIDCControlSession(t.Context(), "apps.integration.test", controlstate.OIDCIdentity{
		Issuer: f.identityIssuer, Subject: "ordinary-publisher", DisplayName: "ordinary publisher",
		AssertionDigest: sha256.Sum256([]byte("g357-ordinary-publisher")), AssertionExpiry: now.Add(time.Hour),
	}, time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	root := f.state(t, "ordinary-member")
	state, err := clientstate.Open(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	profile, err := state.Server(t.Context(), f.url)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.SaveControlSession(t.Context(), clientstate.ControlSession{SessionID: session.SessionID,
		AccessToken: session.AccessToken.String(), RefreshToken: session.RefreshToken.String(),
		AccessExpiresAt: session.AccessExpiresAt, RefreshExpiresAt: session.RefreshExpiresAt}); err != nil {
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
	return root, authority, control
}
