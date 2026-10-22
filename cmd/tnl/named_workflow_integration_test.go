package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	"github.com/tnldotdev/tnl/internal/publisher/local"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

var cliWorkflowPersonalTeam = flag.Bool("tnl-cli-workflow-personal-team", false, "qualify direct managed-domain local public URL realization")
var cliWorkflowNoGit = flag.Bool("tnl-cli-workflow-no-git", false, "qualify local publication continuity before and after Git initialization")

func runNamedWorkflowProcess(t *testing.T, personal bool, noGit ...bool) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	timeout := 150 * time.Second
	if len(noGit) != 0 && noGit[0] {
		// three git transitions each wait for a full owner shutdown and restart.
		timeout = 4 * time.Minute
	}
	args := []string{"-test.run=^TestIntegrationCLINamedInvocationSelectionAndRealization$", "-test.v", "-test.timeout=" + timeout.String(), "-tnl-test-tier=integration", "-tnl-test-postgres-url=" + flag.Lookup("tnl-test-postgres-url").Value.String(), "-tnl-cli-workflow-child"}
	if personal {
		args = append(args, "-tnl-cli-workflow-personal-team")
	}
	if len(noGit) != 0 && noGit[0] {
		args = append(args, "-tnl-cli-workflow-no-git")
	}
	command := exec.CommandContext(t.Context(), executable, args...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("named CLI workflow: %v\n%s", err, output)
	} else {
		t.Logf("%s", output)
	}
}

func TestIntegrationCLINamedLocalIdentityContinuity(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real CLI state protection is qualified in Linux")
	}
	runNamedWorkflowProcess(t, true, true)
}

func TestIntegrationCLINamedPersonalServiceRealization(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real CLI state protection is qualified in Linux")
	}
	runNamedWorkflowProcess(t, true)
}

// exercise automatic owner startup with a built CLI. server/team overrides and
// a nondefault config must survive the process boundary before and after apply.
func TestIntegrationCLINamedInvocationSelectionAndRealization(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if runtime.GOOS != "linux" {
		t.Skip("real CLI state protection is qualified in Linux")
	}
	if !*cliWorkflowChild {
		runNamedWorkflowProcess(t, false)
		return
	}
	f := newCLIWorkflow(t)
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(t.TempDir(), "tnl")
	build := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", bin, "./cmd/tnl")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build real CLI: %v\n%s", err, output)
	}
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/named/workflow.git"}} {
		if *cliWorkflowNoGit {
			break
		}
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "named CLI workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	team := session.Identity().PersonalTeamId
	if !*cliWorkflowPersonalTeam {
		key, err := randomIdempotencyKey()
		if err != nil {
			t.Fatal(err)
		}
		created, err := session.Authenticated().Authority.CreateTeam(t.Context(), authorityv1.CreateTeamRequest{DisplayName: "named-preview"}, key)
		if err != nil {
			t.Fatal(err)
		}
		team = created.Id
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "selected target") }))
	defer target.Close()
	configuration := filepath.Join(root, "development.json")
	services := map[string]any{
		"api": map[string]any{"target": map[string]any{"type": "address", "address": target.URL}, "access": map[string]any{"team": true}},
		"web": map[string]any{"target": map[string]any{"type": "address", "address": target.URL}, "public_url": map[string]any{}, "access": map[string]any{"team": true}, "http": map[string]any{"readiness": map[string]any{"path": "/health"}}},
	}
	if !*cliWorkflowNoGit {
		services["db"] = map[string]any{"publisher_group": "production", "protocol": "tcp", "target": map[string]any{"type": "address", "address": "127.0.0.1:9"}}
	} else {
		services["sdk"] = map[string]any{"access": map[string]any{"team": true}}
	}
	data, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{
		"server": "https://unselected.example.test", "team": "unselected", "publisher_groups": map[string]any{"production": map[string]any{}},
		"services": services,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(`{"version":1,"tnl":{"services":{"wrong":{}}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	checkSession := exec.CommandContext(t.Context(), bin, "--no-config", "team", "current", "--server", f.url, "--state-dir", person)
	if output, err := checkSession.CombinedOutput(); err != nil {
		t.Fatalf("built CLI session: %v\n%s", err, output)
	}
	t.Chdir(root)
	project, err := loadProjectConfiguration(t.Context(), cli{ConfigPath: configuration}, person)
	if err != nil {
		t.Fatal(err)
	}
	source := project.LocalPublicationIdentity()
	connection, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close(context.Background())
	var endpoint publisherprotocol.Endpoint
	start := func(name string) func() {
		t.Helper()
		var stdout, stderr bytes.Buffer
		command := exec.Command(bin, "--no-telemetry", "--config", configuration, "publish", name, "--foreground", "--output", "ndjson", "--server", f.url, "--team", team, "--state-dir", person)
		command.Stdout, command.Stderr = &stdout, &stderr
		command.WaitDelay = 2 * time.Second
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		joined := make(chan error, 1)
		go func() { joined <- command.Wait() }()
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			_ = command.Process.Signal(os.Interrupt)
			select {
			case err := <-joined:
				if err != nil {
					t.Errorf("named CLI did not stop: %v\n%s\n%s", err, stdout.String(), stderr.String())
				}
			case <-time.After(15 * time.Second):
				_ = command.Process.Kill()
				<-joined
				t.Error("named CLI did not join")
			}
		}
		t.Cleanup(stop)
		workflowWait(t, 30*time.Second, func() bool {
			select {
			case err := <-joined:
				stopped = true
				t.Fatalf("named CLI exited before ready: %v\n%s\n%s", err, stdout.String(), stderr.String())
			default:
			}
			descriptor, err := publisherprotocol.DescriptorPath(person, root)
			if err != nil {
				return false
			}
			endpoint, err = publisherprotocol.ReadEndpoint(descriptor)
			if err != nil {
				return false
			}
			var snapshot publisherapp.Snapshot
			if err := publisherprotocol.Call(t.Context(), endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
				return false
			}
			for _, service := range snapshot.Services {
				if service.Name == name {
					return service.Routable && service.Target == target.URL
				}
			}
			return false
		})
		return stop
	}
	firstAPI, firstWeb := start("api"), start("web")
	if _, err := session.Authenticated().Control.GetProjectConfiguration(t.Context(), team, source.Key); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("local startup implicitly applied production configuration: %v", err)
	}
	assertRealized := func() {
		t.Helper()
		var resources, grants int
		want := 2
		if *cliWorkflowNoGit {
			want = 3
		}
		if err := connection.QueryRow(t.Context(), `SELECT count(*),count(visitor_grant_id) FROM control.local_project_services WHERE team_id=$1 AND project_key=$2 AND worktree_key=$3`, team, source.Key, project.LocalWorktreeKey()).Scan(&resources, &grants); err != nil || resources != want || grants != want {
			t.Fatalf("local public/private team access realization: resources=%d grants=%d err=%v", resources, grants, err)
		}
	}
	if *cliWorkflowNoGit {
		startSDK := func() func() {
			t.Helper()
			selected, err := loadProjectConfiguration(t.Context(), cli{ConfigPath: configuration}, person)
			if err != nil {
				t.Fatal(err)
			}
			selected.Config.Server, selected.Config.Team = &f.url, &team
			snapshot, _, err := selected.Snapshot()
			if err != nil {
				t.Fatal(err)
			}
			command := exec.CommandContext(t.Context(), bin, "runtime", "endpoint", "--directory", root, "--state-dir", person, "--service", "sdk", "--snapshot-stdin")
			command.Stdin = bytes.NewReader(snapshot)
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("built app endpoint: %v\n%s", err, &stderr)
			}
			var app publisherprotocol.Endpoint
			if err := json.Unmarshal(stdout.Bytes(), &app); err != nil {
				t.Fatal(err)
			}
			owner := "0123456789abcdef0123456789abcdef"
			var assignment publisherprotocol.Assignment
			if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/prepare", publisherprotocol.Prepare{Version: 1, Directory: root, Service: "sdk", Framework: "node", Owner: owner, PID: os.Getpid()}, &assignment); err != nil {
				t.Fatal(err)
			}
			registration := publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: owner, Target: target.URL}
			if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/register", registration, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			go func() {
				defer close(done)
				ticker := time.NewTicker(3 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						_ = publisherprotocol.Call(ctx, app, "POST", "/v1/renew", registration, nil)
					}
				}
			}()
			stopped := false
			stop := func() {
				if stopped {
					return
				}
				stopped = true
				cancel()
				<-done
				_ = publisherprotocol.Call(context.Background(), app, "POST", "/v1/unregister", registration, nil)
			}
			t.Cleanup(stop)
			workflowWait(t, 20*time.Second, func() bool {
				var snapshot publisherapp.Snapshot
				names := []string{"sdk"}
				if err := publisherprotocol.Call(t.Context(), endpoint, "POST", "/v1/check", publisherprotocol.Check{Services: &names}, &snapshot); err != nil {
					return false
				}
				for _, service := range snapshot.Services {
					if service.Name == "sdk" {
						return service.Registered && service.Routable && service.Ready
					}
				}
				return false
			})
			return stop
		}
		firstSDK := startSDK()
		assertRealized()
		var originalIDs string
		readIDs := func() string {
			var ids string
			if err := connection.QueryRow(t.Context(), `SELECT string_agg(COALESCE(service_id, public_url_id), ',' ORDER BY service) FROM control.local_project_services WHERE team_id=$1 AND project_key=$2`, team, source.Key).Scan(&ids); err != nil {
				t.Fatal(err)
			}
			return ids
		}
		originalIDs = readIDs()
		transitionsStarted := time.Now()
		for phase := range 3 {
			t.Logf("git transition %d: stopping the current owner after %s", phase+1, time.Since(transitionsStarted).Round(time.Millisecond))
			firstAPI()
			firstWeb()
			firstSDK()
			workflowWait(t, 15*time.Second, func() bool { return !local.Available(t.Context(), endpoint) })
			t.Logf("git transition %d: owner stopped after %s", phase+1, time.Since(transitionsStarted).Round(time.Millisecond))
			args := []string{"init", "--quiet", root}
			if phase == 1 {
				args = []string{"-C", root, "remote", "add", "origin", "https://example.test/first.git"}
			}
			if phase == 2 {
				args = []string{"-C", root, "remote", "set-url", "origin", "https://elsewhere.test/second.git"}
			}
			if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
				t.Fatalf("Git transition: %v %s", err, output)
			}
			firstAPI, firstWeb = start("api"), start("web")
			firstSDK = startSDK()
			assertRealized()
			if ids := readIDs(); ids != originalIDs {
				t.Fatalf("Git transition replaced local services: %s != %s", ids, originalIDs)
			}
			t.Logf("git transition %d: the same services are ready after %s", phase+1, time.Since(transitionsStarted).Round(time.Millisecond))
		}
		firstAPI()
		firstWeb()
		firstSDK()
		t.Log("built CLI reused the same service and public URL before Git, after git init without origin, and across origin changes")
		return
	}
	assertRealized()
	cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--server", f.url, "--team", team, "--state-dir", person, "--output", "json"})
	assertRealized()
	firstAPI()
	firstWeb()
	secondAPI, secondWeb := start("api"), start("web")
	assertRealized()
	secondAPI()
	secondWeb()
	t.Log("built CLI preserved --config/--server/--team through automatic owner startup; local public/private team grants survived startup-before-apply and restart-after-apply without implicit production apply")
}
