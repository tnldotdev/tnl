package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// use the existing Linux database workflow so the commands share a binary,
// checkout, saved sign-in, and real control/relays/ingress with the psql check.
func testCLIWalkthrough(t *testing.T, f *cliWorkflow, directory string, target *httptest.Server, session *clientteam.Session, query func(*testing.T)) {
	t.Helper()
	ctx := t.Context()
	state := session.Database().Root()
	team, control := session.Identity().PersonalTeamId, session.Authenticated().Control
	ca := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	binary := workflowExecutable(t)
	var shareSecret string
	invoke := func(secretOutput bool, args ...string) []byte {
		t.Helper()
		cmdCtx, cancel := context.WithTimeout(ctx, 45*time.Second)
		defer cancel()
		cmd := exec.CommandContext(cmdCtx, binary, args...)
		cmd.Dir = directory
		cmd.Env = append(slices.DeleteFunc(cmd.Environ(), func(entry string) bool {
			return strings.HasPrefix(entry, "TNL_")
		}), "TNL_STATE_DIR="+state, "TNL_NO_TELEMETRY=true", "SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+filepath.Dir(ca))
		cmd.WaitDelay = 5 * time.Second
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		exit := -1
		if cmd.ProcessState != nil {
			exit = cmd.ProcessState.ExitCode()
		}
		if shareSecret != "" && (strings.Contains(stdout.String(), shareSecret) || strings.Contains(stderr.String(), shareSecret)) {
			t.Fatalf("tnl %s: exit=%d; streams withheld because they exposed the share credential", args[0], exit)
		}
		if secretOutput {
			if err != nil || exit != 0 || stderr.Len() != 0 {
				t.Fatalf("tnl %s: exit=%d; streams withheld because they may contain a share credential", strings.Join(args, " "), exit)
			}
		} else {
			t.Logf("tnl %s: exit=%d, stdout=%q, stderr=%q", strings.Join(args, " "), exit, stdout.Bytes(), stderr.Bytes())
			if err != nil || exit != 0 || stderr.Len() != 0 {
				t.Fatalf("tnl %s: %v", args[0], err)
			}
		}
		return stdout.Bytes()
	}

	// the real owner runs in the fixture process to reuse its trusted DNS and
	// ingress dialer; the user-facing commands below all run the built binary.
	ownerCtx, stopOwner := context.WithCancel(context.WithoutCancel(ctx))
	_, ownerJoined := f.command(t, ownerCtx, stopOwner, []string{"runtime", "serve", "--directory", directory, "--state-dir", state})
	descriptor, err := publisherprotocol.DescriptorPath(state, directory)
	if err != nil {
		t.Fatal(err)
	}
	workflowWait(t, 10*time.Second, func() bool {
		select {
		case <-ownerJoined:
			t.Fatal("walkthrough project owner exited before readiness")
		default:
		}
		endpoint, err := publisherprotocol.ReadEndpoint(descriptor)
		if err != nil {
			return false
		}
		probe, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		return publisherprotocol.Call(probe, endpoint, "GET", "/v1/health", nil, nil) == nil
	})
	t.Cleanup(func() { cleanupBackgroundJobs(t, state) })

	type jobReceipt struct {
		SchemaVersion int    `json:"schema_version"`
		JobID         string `json:"job_id"`
		TunnelID      string `json:"tunnel_id"`
		Mode          string `json:"mode"`
		URL           string `json:"url"`
	}
	publish := func(target string, args ...string) jobReceipt {
		t.Helper()
		var result jobReceipt
		if json.Unmarshal(invoke(false, append([]string{"publish", target, "--bg", "--output", "json"}, args...)...), &result) != nil ||
			result.SchemaVersion != 1 || !validJobID(result.JobID) || !opaqueid.Valid(result.TunnelID, opaqueid.TunnelPrefix) ||
			result.Mode != "background" || !strings.HasPrefix(result.URL, "https://") {
			t.Fatal("publish did not return a background tunnel receipt")
		}
		return result
	}
	accountsJob, apiJob := publish("accounts"), publish("api")
	project, err := loadProjectConfiguration(ctx, cli{ConfigPath: filepath.Join(directory, "tnl.json")}, state)
	if err != nil {
		t.Fatal(err)
	}
	source := project.LocalPublicationIdentity()
	params := controlv1.GetLocalProjectServiceParams{TeamId: team, SourceFingerprint: source.Fingerprint, WorktreeKey: project.LocalWorktreeKey()}
	accounts, err := control.GetLocalProjectService(ctx, source.Key, "accounts", params)
	if err != nil {
		t.Fatal(err)
	}
	api, err := control.GetLocalProjectService(ctx, source.Key, "api", params)
	if err != nil {
		t.Fatal(err)
	}
	previewID, found, err := session.Store().PreviewID(ctx, team, params.WorktreeKey)
	if err != nil || !found {
		t.Fatal("checkout has no saved preview", err)
	}
	preview, err := control.GetPreview(ctx, previewID)
	if err != nil || accounts.ServiceId == api.ServiceId || !slices.Contains(preview.ServiceIds, accounts.ServiceId) || !slices.Contains(preview.ServiceIds, api.ServiceId) {
		t.Fatal("the real preview does not contain both accounts and api", err)
	}
	started := time.Now()
	var ready struct {
		State     string                 `json:"state"`
		CheckedBy string                 `json:"checked_by"`
		Services  []publisherapp.Service `json:"services"`
	}
	if json.Unmarshal(invoke(false, "wait", "accounts", "--timeout", "30s", "--output", "json"), &ready) != nil ||
		ready.State != "ready" || !strings.Contains(ready.CheckedBy, "fresh public-path check") || len(ready.Services) != 1 {
		t.Fatal("wait did not confirm exactly one fresh public-path check")
	}
	checked := ready.Services[0]
	if checked.Name != "accounts" || checked.PublicURL != accountsJob.URL || !checked.Ready || checked.Observation == nil ||
		checked.Observation.CheckedAt.Before(started) || checked.Observation.Readiness.Path != "/accounts-health" || checked.Observation.Status != http.StatusNoContent {
		t.Fatal("wait did not check the running accounts service's configured endpoint")
	}

	if shares, err := control.ListTeamShares(ctx, team); err != nil || len(shares) != 0 {
		t.Fatal("walkthrough must start without shares", err)
	}
	started = time.Now()
	var receipt struct {
		SchemaVersion int       `json:"schema_version"`
		ShareID       string    `json:"share_id"`
		EntryURL      string    `json:"entry_url"`
		ServiceIDs    []string  `json:"service_ids"`
		ExpiresAt     time.Time `json:"expires_at"`
	}
	if json.Unmarshal(invoke(true, "share", "accounts", "--expires-in", "1h", "--output", "json"), &receipt) != nil ||
		receipt.SchemaVersion != 1 || !slices.Equal(receipt.ServiceIDs, []string{accounts.ServiceId}) ||
		receipt.ExpiresAt.Before(started.Add(time.Hour).Truncate(time.Microsecond)) || receipt.ExpiresAt.After(time.Now().Add(time.Hour)) {
		t.Fatal("share did not return one one-hour receipt for accounts")
	}
	credential, ok := strings.CutPrefix(receipt.EntryURL, accountsJob.URL+"/__tnl/share/")
	if !ok || !opaqueid.Valid(receipt.ShareID, opaqueid.SharePrefix) || !serviceShareSecret(credential, receipt.ShareID) {
		t.Fatal("the link did not identify the share from the receipt")
	}
	receipt.EntryURL = "[redacted]"
	redacted, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal("encode redacted share receipt")
	}
	t.Logf("tnl share accounts --expires-in 1h --output json: exit=0, stdout (redacted)=%q, stderr=\"\"", string(redacted)+"\n")

	checkShare := func(revoked bool) {
		t.Helper()
		shares, err := control.ListTeamShares(ctx, team)
		if err != nil || len(shares) != 1 {
			t.Fatal("control did not record exactly one share", err)
		}
		saved := shares[0]
		if saved.Id != receipt.ShareID || saved.Scope != "service" || saved.PreviewId != nil || saved.EntryServiceId != accounts.ServiceId ||
			!slices.Equal(saved.ServiceIds, receipt.ServiceIDs) || !saved.ExpiresAt.Equal(receipt.ExpiresAt) || (saved.RevokedAt != nil) != revoked {
			t.Fatal("saved share does not match the exact receipt and revocation state")
		}
	}
	checkShare(false)
	_, shareSecret, _ = strings.Cut(credential, ".")
	sourceBody, err := json.Marshal(controlv1.VisitorTokenShareSource{Kind: controlv1.VisitorTokenShare, ShareId: receipt.ShareID, Secret: shareSecret})
	if err != nil {
		t.Fatal("encode share source")
	}
	checkPermission := func(id string, wantAccess bool) {
		t.Helper()
		scope := controlv1.VisitorResourceScope{Kind: "service", Id: id}
		permission, err := control.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: scope, Source: sourceBody})
		reason, _ := failure.ReasonOf(err)
		if wantAccess && (err != nil || permission.Resource != scope || permission.VisitorToken == "") ||
			!wantAccess && (reason != failure.ServerDenied || permission.VisitorToken != "") {
			t.Fatalf("unexpected share authorization for %s: wanted access=%t, reason=%s", id, wantAccess, reason)
		}
	}
	checkPermission(accounts.ServiceId, true)
	checkPermission(api.ServiceId, false)

	_, port, err := net.SplitHostPort(target.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	job := publish(port, "--name", "walkthrough", "--anonymous")
	t.Log("tnl connect orders --deployment staging --client psql -- -At -c 'select 1'")
	query(t)

	if stdout := invoke(false, "share", "revoke", receipt.ShareID); string(stdout) != "Revoked share "+receipt.ShareID+"\n" {
		t.Fatal("share revoke did not confirm the receipt ID")
	}
	checkShare(true)
	checkPermission(accounts.ServiceId, false)

	var status jobStatus
	if json.Unmarshal(invoke(false, "status", job.JobID, "--output", "json"), &status) != nil ||
		status.JobID != job.JobID || status.TunnelID != job.TunnelID || status.Address != job.URL || status.State != "ready" {
		t.Fatal("the separate tunnel did not remain ready through the query and revocation")
	}
	visitor := &http.Client{Transport: http.DefaultTransport, Timeout: 2 * time.Second}
	workflowWait(t, 10*time.Second, func() bool {
		response, err := visitor.Get(job.URL)
		if err != nil {
			return false
		}
		defer response.Body.Close()
		body, err := io.ReadAll(response.Body)
		return err == nil && response.StatusCode == http.StatusOK && string(body) == "walkthrough app\n"
	})
	var stopped jobStatus
	if json.Unmarshal(invoke(false, "stop", job.JobID, "--output", "json"), &stopped) != nil ||
		stopped.JobID != job.JobID || (stopped.State != "stopping" && stopped.State != "stopped") {
		t.Fatal("stop did not acknowledge the exact separate tunnel job")
	}
	waitBackgroundJobExit(t, ctx, state, job.JobID)
	var remaining struct {
		Jobs []jobStatus `json:"jobs"`
	}
	if json.Unmarshal(invoke(false, "status", "--bg", "--output", "json"), &remaining) != nil || len(remaining.Jobs) != 2 {
		t.Fatal("background status did not retain the two checkout jobs")
	}
	for _, checkoutJob := range []jobReceipt{accountsJob, apiJob} {
		if !slices.ContainsFunc(remaining.Jobs, func(job jobStatus) bool {
			return job.JobID == checkoutJob.JobID && job.TunnelID == checkoutJob.TunnelID && job.State == "ready"
		}) {
			t.Fatal("stopping the separate tunnel changed a checkout job")
		}
	}
}
