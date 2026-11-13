//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/filelock"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
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
	args := []string{"-test.run=^TestIntegrationCLINamedInvocationSelectionAndRealization$", "-test.v", "-test.timeout=150s", "-tnl-test-tier=integration", "-tnl-test-postgres-url=" + flag.Lookup("tnl-test-postgres-url").Value.String(), "-tnl-cli-binary=" + *cliWorkflowBinary, "-tnl-cli-workflow-child"}
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
	runNamedWorkflowProcess(t, true, true)
}

func TestIntegrationCLINamedPersonalServiceRealization(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	runNamedWorkflowProcess(t, true)
}

// exercise automatic owner startup with a built CLI. server/team overrides and
// a nondefault config must survive the process boundary before and after apply.
func TestIntegrationCLINamedInvocationSelectionAndRealization(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if !*cliWorkflowChild {
		runNamedWorkflowProcess(t, false)
		return
	}
	f := newCLIWorkflow(t)
	bin := workflowExecutable(t)
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
	t.Cleanup(target.Close)
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
	descriptor, err := publisherprotocol.DescriptorPath(person, root)
	if err != nil {
		t.Fatal(err)
	}
	selectedSnapshot := func() []byte {
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
		return snapshot
	}
	var owner *namedWorkflowProcess
	startOwner := func() func() {
		t.Helper()
		command := exec.Command(bin, "--no-telemetry", "runtime", "serve", "--directory", root, "--state-dir", person, "--snapshot-stdin")
		command.Stdin = bytes.NewReader(selectedSnapshot())
		process := startNamedWorkflowCommand(t, command)
		process.wait(t, 15*time.Second, func(ctx context.Context) (bool, string) {
			current, err := publisherprotocol.ReadEndpoint(descriptor)
			if err == nil {
				err = publisherprotocol.Call(ctx, current, "GET", "/v1/health", nil, nil)
			}
			return err == nil, fmt.Sprint(err)
		})
		owner = process
		return func() {
			process.stop()
			// process exit, not failed health, proves cleanup released ownership.
			if _, err := os.Stat(descriptor); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("joined owner retained its descriptor: %v", err)
			}
			lock, err := filelock.Acquire(descriptor+".lock", filelock.Nonblocking, os.Geteuid())
			if err != nil {
				t.Fatalf("joined owner retained its ownership lock: %v", err)
			}
			if err := lock.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	start := func(name string) func() {
		t.Helper()
		command := exec.Command(bin, "--no-telemetry", "--config", configuration, "publish", name, "--foreground", "--output", "ndjson", "--server", f.url, "--team", team, "--state-dir", person)
		process := startNamedWorkflowCommand(t, command)
		process.wait(t, 30*time.Second, func(ctx context.Context) (bool, string) {
			var err error
			endpoint, err = publisherprotocol.ReadEndpoint(descriptor)
			if err != nil {
				return false, err.Error()
			}
			var snapshot publisherapp.Snapshot
			if err := publisherprotocol.Call(ctx, endpoint, "GET", "/v1/status", nil, &snapshot); err != nil {
				return false, err.Error()
			}
			for _, service := range snapshot.Services {
				if service.Name == name {
					return service.Routable && service.Target == target.URL, fmt.Sprintf("%s: registered=%t routable=%t stage=%q failure=%q target=%q", name, service.Registered, service.Routable, service.ProvisioningStage, service.Failure, service.Target)
				}
			}
			return false, "selected service is absent from owner status"
		})
		return process.stop
	}
	// runtime endpoint/publish can leave their automatically started owner alive
	// after the launcher exits. keep infrastructure and state until it is reaped.
	joinNamedWorkflowOwners(t)
	var stopOwner func()
	if *cliWorkflowNoGit {
		stopOwner = startOwner()
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
			startup, finishStartup := context.WithTimeout(t.Context(), 30*time.Second)
			defer finishStartup()
			command := exec.CommandContext(startup, bin, "runtime", "endpoint", "--directory", root, "--state-dir", person, "--service", "sdk", "--snapshot-stdin")
			command.Stdin = bytes.NewReader(selectedSnapshot())
			var stdout, stderr bytes.Buffer
			command.Stdout, command.Stderr = &stdout, &stderr
			if err := command.Run(); err != nil {
				t.Fatalf("built app endpoint: %v\n%s", err, &stderr)
			}
			var app publisherprotocol.Endpoint
			if err := json.Unmarshal(stdout.Bytes(), &app); err != nil {
				t.Fatal(err)
			}
			appOwner := "0123456789abcdef0123456789abcdef"
			var assignment publisherprotocol.Assignment
			if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/prepare", publisherprotocol.Prepare{Version: 1, Directory: root, Service: "sdk", Framework: "node", Owner: appOwner, PID: os.Getpid()}, &assignment); err != nil {
				t.Fatal(err)
			}
			registration := publisherprotocol.Registration{Version: 1, RegistrationID: assignment.RegistrationID, Owner: appOwner, Target: target.URL}
			if err := publisherprotocol.Call(t.Context(), app, "POST", "/v1/register", registration, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			done := make(chan struct{})
			var renewalErr error
			go func() {
				defer close(done)
				ticker := time.NewTicker(3 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-ctx.Done():
						return
					case <-ticker.C:
						if err := publisherprotocol.Call(ctx, app, "POST", "/v1/renew", registration, nil); err != nil {
							if ctx.Err() == nil {
								renewalErr = err
							}
							return
						}
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
				if renewalErr != nil {
					t.Errorf("app registration renewal failed: %v", renewalErr)
				}
				cleanup, finish := context.WithTimeout(context.Background(), 10*time.Second)
				defer finish()
				if err := publisherprotocol.Call(cleanup, app, "POST", "/v1/unregister", registration, nil); err != nil {
					t.Errorf("app registration did not stop: %v", err)
				}
			}
			t.Cleanup(stop)
			owner.wait(t, 20*time.Second, func(ctx context.Context) (bool, string) {
				select {
				case <-done:
					t.Fatalf("app registration renewal stopped before ready: %v", renewalErr)
				default:
				}
				var snapshot publisherapp.Snapshot
				names := []string{"sdk"}
				if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/check", publisherprotocol.Check{Services: &names}, &snapshot); err != nil {
					return false, err.Error()
				}
				for _, service := range snapshot.Services {
					if service.Name == "sdk" {
						return service.Registered && service.Routable && service.Ready, fmt.Sprintf("sdk: registered=%t routable=%t ready=%t stage=%q failure=%q", service.Registered, service.Routable, service.Ready, service.ProvisioningStage, service.Failure)
					}
				}
				return false, "app service is absent from owner status"
			})
			return stop
		}
		firstSDK := startSDK()
		assertRealized()
		readIDs := func() string {
			var ids string
			if err := connection.QueryRow(t.Context(), `SELECT string_agg(COALESCE(service_id, public_url_id)||':'||visitor_grant_id, ',' ORDER BY service) FROM control.local_project_services WHERE team_id=$1 AND project_key=$2`, team, source.Key).Scan(&ids); err != nil {
				t.Fatal(err)
			}
			return ids
		}
		originalIDs := readIDs()
		firstAPI()
		firstWeb()
		firstSDK()
		stopOwner()
		// project and invocation tests cover each intermediate Git state without
		// publications. this smoke crosses the real process boundary only once.
		for _, args := range [][]string{
			{"init", "--quiet", root},
			{"-C", root, "remote", "add", "origin", "https://example.test/first.git"},
			{"-C", root, "remote", "set-url", "origin", "https://elsewhere.test/second.git"},
		} {
			if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
				t.Fatalf("Git transition: %v %s", err, output)
			}
		}
		stopOwner = startOwner()
		secondAPI, secondWeb, secondSDK := start("api"), start("web"), startSDK()
		assertRealized()
		if ids := readIDs(); ids != originalIDs {
			t.Fatalf("owner restart replaced local resources or grants: %s != %s", ids, originalIDs)
		}
		secondAPI()
		secondWeb()
		secondSDK()
		stopOwner()
		t.Log("one joined owner restart preserved public, private, and app services and their team grants from a non-Git directory to a Git checkout with a changed origin")
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
