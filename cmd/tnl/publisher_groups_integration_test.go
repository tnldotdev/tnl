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
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// this invokes the real CLI once for both identities in one process, against
// real control/authority, PostgreSQL, ingress, relays and the managed TLS path.
// the shared workflow fixture supplies local certificate and DNS workers.
func TestIntegrationFixedGroupsCrossTeamIsolation(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	for _, name := range []string{"TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "TNL_ENVIRONMENT_ENROLL_KEY", "TNL_SERVER", "TNL_TEAM", "TNL_ACCESS_TOKEN"} {
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
	var identities []credentialfile.GroupFile
	var identityPaths, bindingPaths []string
	var applied []controlv1.Environment
	for i, team := range teams {
		token := []string{"team-a-token", "team-b-token"}[i]
		target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("Authorization") != "" {
				t.Error("publisher added application authorization")
			}
			_, _ = io.WriteString(w, token)
		}))
		defer target.Close()
		ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw}))
		result := workflowPublisherEnvironment(t, session.Authenticated().Control, team, "same-project", controlv1.EnvironmentTarget{Address: &target.URL, Tls: &controlv1.EnvironmentTargetTLS{Hostname: new("example.com"), CaPem: &ca}, Http: &controlv1.EnvironmentServiceHTTP{Access: &controlv1.ProjectPublicAccess{Mode: new(controlv1.Restricted)}}})
		applied = append(applied, result)
		path := filepath.Join(t.TempDir(), "identity.json")
		cliCall(t, t.Context(), []string{"--no-config", "publisher", "provision", "--server", f.url, "--team", team, "--environment", result.Id, "--services", "api", "--project-key", result.ProjectKey, "--instance", "default", "--output-file", path, "--state-dir", person})
		identity, err := credentialfile.ReadGroup(path)
		if err != nil {
			t.Fatal(err)
		}
		identities = append(identities, identity)
		identityPaths = append(identityPaths, path)
		bindingPath := filepath.Join(t.TempDir(), "binding.json")
		writeJSON(bindingPath, supervisor.GroupBinding{Version: 1, Scope: supervisor.ScopeForGroup(identity)})
		bindingPaths = append(bindingPaths, bindingPath)
	}
	if identities[0].Member.ProjectKey != identities[1].Member.ProjectKey || applied[0].Name != applied[1].Name || identities[0].Instance != identities[1].Instance || identities[0].PrivateKey == identities[1].PrivateKey || identities[0].Member.EnvironmentId == identities[1].Member.EnvironmentId {
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
	registry, err := supervisor.Open(t.Context(), supervisor.OpenOptions{Root: state, StandaloneGroups: true})
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
		if err := inspect.QueryRow(t.Context(), `SELECT id,certificate_issuance_id FROM control.service_runs WHERE publisher_identity_id=$1 AND service_id=$2 AND closed_at IS NULL`, identities[index].Member.PublisherIdentityId, applied[index].Services[0].ServiceId).Scan(&state.id, &state.issuance); err != nil {
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
	visitorJoined := make([]<-chan struct{}, len(teams))
	startVisitor := func(index int) {
		t.Helper()
		ctx, cancel := context.WithCancel(t.Context())
		ready, joined := f.command(t, ctx, cancel, []string{"--no-config", "connect", applied[index].Services[0].ServiceId, "--team", teams[index], "--listen", visitorAddresses[index], "--server", f.url, "--state-dir", person}, connectorstream.ErrServiceConnection, clientcontrol.ErrNotFound)
		visitorJoined[index] = joined
		select {
		case <-ready:
		case <-time.After(25 * time.Second):
			t.Fatal("connector was not ready")
		}
	}
	joinVisitor := func(index int) {
		t.Helper()
		select {
		case <-visitorJoined[index]:
		case <-time.After(10 * time.Second):
			t.Fatal("old connector did not join after publisher termination")
		}
		if connection, err := net.DialTimeout("tcp", visitorAddresses[index], time.Second); err == nil {
			_ = connection.Close()
			t.Fatal("old connector listener survived publisher termination")
		}
	}
	for i := range teams {
		service, err := session.Authenticated().Control.GetService(t.Context(), applied[i].Services[0].ServiceId)
		if err != nil {
			t.Fatal(err)
		}
		listener := workflowListen(t)
		address := listener.Addr().String()
		_ = listener.Close()
		client := workflowNativeHTTPClient(t, f, service.Endpoint.Hostname)
		visitorClients = append(visitorClients, client)
		visitorAddresses = append(visitorAddresses, address)
		startVisitor(i)
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
	jobA := supervisor.JobKey(f.url, "env", identities[0].Member.EnvironmentId+":default")
	if err := registry.Stop(t.Context(), jobA); err != nil {
		t.Fatal(err)
	}
	stopCtx, cancelStop := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancelStop()
	if err := registry.WaitStopped(stopCtx, jobA); err != nil {
		t.Fatal(err)
	}
	joinVisitor(0)
	if current(1) != runs[1] {
		t.Fatal("stopping A changed B's publish run")
	}
	if err := registry.Start(t.Context(), jobA); err != nil {
		t.Fatal(err)
	}
	ready()
	startVisitor(0)
	if current(0).issuance != runs[0].issuance || current(1) != runs[1] {
		t.Fatal("restarting A lost its certificate or restarted B")
	}
	beforeUpdate := current(0)
	replacementTarget := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "updated-team-a")
	}))
	defer replacementTarget.Close()
	// applying an A-only revision changes A's target while B keeps its exact run.
	ca := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: replacementTarget.Certificate().Raw}))
	targets := controlv1.EnvironmentTargets{"api": {Address: &replacementTarget.URL, Tls: &controlv1.EnvironmentTargetTLS{Hostname: new("example.com"), CaPem: &ca}, Http: &controlv1.EnvironmentServiceHTTP{Access: &controlv1.ProjectPublicAccess{Mode: new(controlv1.Restricted)}}}}
	_, err = session.Authenticated().Control.ApplyEnvironment(t.Context(), applied[0].ProjectKey, applied[0].Id, controlv1.ApplyEnvironmentRequest{TeamId: teams[0], ExpectedRevision: applied[0].MutationRevision, DefinitionRevision: applied[0].AppliedDefinitionRevision, Targets: &targets})
	if err != nil {
		t.Fatal(err)
	}
	workflowWait(t, 35*time.Second, func() bool {
		status, err := session.Authenticated().Control.ListEnvironmentPublishers(t.Context(), teams[0], applied[0].ProjectKey, applied[0].Id)
		return err == nil && len(status) == 1 && status[0].Healthy && status[0].ObservedRevision > applied[0].MutationRevision
	})
	if current(1) != runs[1] {
		t.Fatal("updating A restarted B")
	}
	if current(0).id == beforeUpdate.id {
		t.Fatal("A target update did not replace its assignment")
	}
	joinVisitor(0)
	startVisitor(0)
	assertVisitor(0, "updated-team-a")
	assertVisitor(1, "team-b-token")
	if err := session.Authenticated().Control.RevokeEnvironmentPublisher(t.Context(), teams[0], applied[0].ProjectKey, applied[0].Id, identities[0].Member.PublisherIdentityId); err != nil {
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
	joinVisitor(0)
	assertVisitor(1, "team-b-token")
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	close(done)
	joinVisitor(1)
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
	startVisitor(1)
	assertVisitor(1, "team-b-token")
	stop()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	close(done)
	joinVisitor(1)
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
