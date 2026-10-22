package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	publisherjob "github.com/tnldotdev/tnl/internal/client/service"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// this invokes the real CLI once for both identities in one process, against
// real control/authority, PostgreSQL, ingress, relays and the managed TLS path.
// the shared workflow fixture supplies local certificate and DNS workers.
func TestIntegrationFixedGroupsCrossTeamIsolation(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	for _, name := range []string{"TNL_GROUP_IDENTITY", "TNL_GROUP_ENROLL_KEY", "TNL_SERVER", "TNL_TEAM", "TNL_ACCESS_TOKEN"} {
		t.Setenv(name, "")
		if err := os.Unsetenv(name); err != nil {
			t.Fatal(err)
		}
	}
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "fixed groups", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	key, err := randomIdempotencyKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := session.Authenticated().Authority.CreateTeam(t.Context(), authorityv1.CreateTeamRequest{DisplayName: "other-team"}, key)
	if err != nil {
		t.Fatal(err)
	}
	teams := []string{session.Identity().PersonalTeamId, other.Id}
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/same/project.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("git fixture: %v %s", err, output)
		}
	}
	writeJSON := func(path string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	configuration := filepath.Join(root, "tnl.json")
	var identities []credentialfile.GroupFile
	var identityPaths, bindingPaths []string
	var applied []controlv1.AppliedProjectConfiguration
	for i, team := range teams {
		token := []string{"team-a-token", "team-b-token"}[i]
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Error("publisher added application authorization")
			}
			_, _ = io.WriteString(w, token)
		}))
		defer target.Close()
		caName := []string{"a.pem", "b.pem"}[i]
		if err := os.WriteFile(filepath.Join(root, caName), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}), 0600); err != nil {
			t.Fatal(err)
		}
		writeJSON(configuration, map[string]any{"version": 1, "tnl": map[string]any{"server": f.url, "team": team, "publishers": map[string]any{"production": map[string]any{}}, "services": map[string]any{
			"api": map[string]any{"publisher": "production", "target": map[string]any{"type": "address", "address": target.URL, "tls": map[string]any{"server_name": "example.com", "ca_file": caName}}, "access": map[string]any{"team": true}},
		}}})
		var result controlv1.AppliedProjectConfiguration
		if err := json.Unmarshal(cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--state-dir", person, "--output", "json"}), &result); err != nil {
			t.Fatal(err)
		}
		applied = append(applied, result)
		path := filepath.Join(t.TempDir(), "identity.json")
		cliCall(t, t.Context(), []string{"--no-config", "publisher", "provision", "--server", f.url, "--team", team, "--group", "production", "--project-key", result.ProjectKey, "--instance", "default", "--output-file", path, "--state-dir", person})
		identity, err := credentialfile.ReadGroup(path)
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
		identityPaths = append(identityPaths, path)
		bindingPath := filepath.Join(t.TempDir(), "binding.json")
		writeJSON(bindingPath, publisherjob.GroupBinding{Version: 1, Scope: publisherjob.ScopeForGroup(identity)})
		bindingPaths = append(bindingPaths, bindingPath)
	}
	if identities[0].Member.ProjectKey != identities[1].Member.ProjectKey || identities[0].Member.GroupName != identities[1].Member.GroupName || identities[0].Instance != identities[1].Instance || identities[0].PrivateKey == identities[1].PrivateKey || identities[0].Member.GroupId == identities[1].Member.GroupId {
		t.Fatal("fixture did not exercise same-name cross-team identities")
	}
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(t.Context())
	state := filepath.Join(t.TempDir(), "worker")
	identityDir := filepath.Join(t.TempDir(), "identity")
	args := []string{"--no-config", "publisher", "serve", "--state-dir", state, "--identity-dir", identityDir}
	for i, path := range identityPaths {
		args = append(args, "--identity-file", path, "--binding-file", bindingPaths[i])
	}
	start := func() (context.CancelFunc, chan error) {
		ctx, cancel := context.WithCancel(t.Context())
		done := make(chan error, 1)
		go func() {
			done <- run(ctx, append([]string{"--no-telemetry"}, args...), io.Discard, workflowLifecycleLog{t: t})
		}()
		t.Cleanup(func() {
			cancel()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				t.Error("fixed group process did not join")
			}
		})
		return cancel, done
	}
	registry, err := publisherjob.Open(t.Context(), publisherjob.OpenOptions{Root: state, StandaloneGroups: true})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	stop, done := start()
	ready := func() {
		t.Helper()
		workflowWait(t, 25*time.Second, func() bool {
			jobs, err := registry.List(t.Context())
			return err == nil && len(jobs) == 2 && jobs[0].Status.State == "ready" && jobs[1].Status.State == "ready"
		})
	}
	ready()
	type runState struct{ id, issuance string }
	current := func(index int) runState {
		t.Helper()
		var state runState
		if err := inspect.QueryRow(t.Context(), `SELECT id,certificate_issuance_id FROM control.private_service_runs WHERE publisher_identity_id=$1 AND private_service_id=$2 AND closed_at IS NULL`, identities[index].Member.PublisherIdentityId, *applied[index].Services[0].ServiceId).Scan(&state.id, &state.issuance); err != nil {
			t.Fatal(err)
		}
		return state
	}
	runs := []runState{current(0), current(1)}
	if runs[0].issuance == runs[1].issuance {
		t.Fatal("teams shared certificate issuance")
	}
	// real visitor connections verify each independent managed certificate and
	// each group's independently assigned target.
	var visitorClients []*http.Client
	var visitorAddresses []string
	var visitorKeys [][]byte
	for i, team := range teams {
		service, err := session.Authenticated().Control.GetPrivateService(t.Context(), *applied[i].Services[0].ServiceId)
		if err != nil {
			t.Fatal(err)
		}
		listener := workflowListen(t)
		address := listener.Addr().String()
		_ = listener.Close()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		ready, _ := f.command(t, ctx, cancel, []string{"--no-config", "connect", "api", "--team", team, "--listen", address, "--server", f.url, "--state-dir", person})
		select {
		case <-ready:
		case <-time.After(25 * time.Second):
			t.Fatal("connector was not ready")
		}
		client := workflowNativeHTTPClient(t, f, service.ManagedTls.Hostname)
		visitorClients = append(visitorClients, client)
		visitorAddresses = append(visitorAddresses, address)
		var visitorKey []byte
		workflowWait(t, 10*time.Second, func() bool {
			response, err := client.Get("https://" + address + "/scoped")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			if response.TLS != nil && len(response.TLS.PeerCertificates) > 0 {
				visitorKey = bytes.Clone(response.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
			}
			return response.StatusCode == 200 && string(body) == []string{"team-a-token", "team-b-token"}[i]
		})
		visitorKeys = append(visitorKeys, visitorKey)
	}
	if len(visitorKeys[0]) == 0 || len(visitorKeys[1]) == 0 || bytes.Equal(visitorKeys[0], visitorKeys[1]) {
		t.Fatal("teams shared a managed TLS key")
	}
	assertVisitor := func(index int, want string) {
		t.Helper()
		workflowWait(t, 10*time.Second, func() bool {
			response, err := visitorClients[index].Get("https://" + visitorAddresses[index] + "/scoped")
			if err != nil {
				return false
			}
			defer response.Body.Close()
			body, _ := io.ReadAll(response.Body)
			return response.StatusCode == 200 && string(body) == want && response.TLS != nil && len(response.TLS.PeerCertificates) > 0 && bytes.Equal(response.TLS.PeerCertificates[0].RawSubjectPublicKeyInfo, visitorKeys[index])
		})
	}
	jobA := publisherjob.JobKey(f.url, "group", identities[0].Member.GroupId+":default")
	if err := registry.Stop(t.Context(), jobA); err != nil {
		t.Fatal(err)
	}
	stopCtx, cancelStop := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancelStop()
	if err := registry.WaitStopped(stopCtx, jobA); err != nil {
		t.Fatal(err)
	}
	if current(1) != runs[1] {
		t.Fatal("stopping A changed B's publish run")
	}
	if err := registry.Start(t.Context(), jobA); err != nil {
		t.Fatal(err)
	}
	ready()
	if current(0).issuance != runs[0].issuance || current(1) != runs[1] {
		t.Fatal("restarting A lost its certificate or restarted B")
	}
	beforeUpdate := current(0)
	replacementTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "updated-team-a")
	}))
	defer replacementTarget.Close()
	if err := os.WriteFile(filepath.Join(root, "a.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: replacementTarget.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	// applying an A-only revision changes A's target while B keeps its exact run.
	var document map[string]any
	data, err := os.ReadFile(configuration)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	tnl := document["tnl"].(map[string]any)
	tnl["team"] = teams[0]
	service := tnl["services"].(map[string]any)["api"].(map[string]any)
	service["target"].(map[string]any)["address"] = replacementTarget.URL
	service["target"].(map[string]any)["tls"].(map[string]any)["ca_file"] = "a.pem"
	writeJSON(configuration, document)
	cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--state-dir", person})
	workflowWait(t, 35*time.Second, func() bool {
		status, err := session.Authenticated().Control.GetProjectConfiguration(t.Context(), teams[0], applied[0].ProjectKey)
		return err == nil && len(status.Members) == 1 && status.Members[0].Healthy && status.Members[0].ObservedRevision > applied[0].Revision
	})
	if current(1) != runs[1] {
		t.Fatal("updating A restarted B")
	}
	if current(0).id == beforeUpdate.id {
		t.Fatal("A target update did not replace its assignment")
	}
	assertVisitor(0, "updated-team-a")
	assertVisitor(1, "team-b-token")
	if err := session.Authenticated().Control.RevokePublisherGroupMember(t.Context(), teams[0], applied[0].ProjectKey, "production", identities[0].Member.PublisherIdentityId); err != nil {
		t.Fatal(err)
	}
	workflowWait(t, 15*time.Second, func() bool {
		jobs, _ := registry.List(t.Context())
		for _, j := range jobs {
			if j.ID == jobA {
				return j.Status.State == "blocked"
			}
		}
		return false
	})
	if current(1) != runs[1] {
		t.Fatal("revoking A restarted B")
	}
	assertVisitor(1, "team-b-token")
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	close(done)
	// a new invocation keeps B's durable issuance; revoked A stays blocked.
	stop, done = start()
	workflowWait(t, 25*time.Second, func() bool {
		jobs, _ := registry.List(t.Context())
		blocked, healthy := false, false
		for _, j := range jobs {
			if j.ID == jobA {
				blocked = j.Status.State == "blocked"
			} else {
				healthy = j.Status.State == "ready"
			}
		}
		return blocked && healthy
	})
	if current(1).issuance != runs[1].issuance {
		t.Fatal("process restart replaced B's certificate files")
	}
	assertVisitor(1, "team-b-token")
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	close(done)
	// alternate paths and instance labels cannot create another owner for a key.
	duplicate := identities[1]
	duplicate.Instance = "other-instance"
	duplicatePath := filepath.Join(t.TempDir(), "duplicate.json")
	if err := credentialfile.WriteGroup(duplicatePath, duplicate); err != nil {
		t.Fatal(err)
	}
	before := f.groupEnrollmentRequests.Load()
	if err := run(t.Context(), []string{"--no-config", "publisher", "serve", "--identity-file", identityPaths[1], "--identity-file", duplicatePath, "--state-dir", state, "--identity-dir", identityDir}, io.Discard, io.Discard); err == nil {
		t.Fatal("duplicate owner accepted")
	}
	if f.groupEnrollmentRequests.Load() != before {
		t.Fatal("fixed-list command attempted enrollment")
	}
	if bytes.Equal([]byte(identities[0].PrivateKey), []byte(identities[1].PrivateKey)) {
		t.Fatal("independent signing keys lost")
	}
	t.Log("one real CLI invocation served same-name groups from different teams; verified visitor bytes, independent signing/certificates, unchanged B run across A stop/start/apply/revoke, durable B issuance after process restart, and duplicate owner rejection")
}
