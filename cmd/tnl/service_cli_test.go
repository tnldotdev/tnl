package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func TestSystemServiceCommandWiring(t *testing.T) {
	for _, command := range []string{"install", "start", "remove", "serve", "register"} {
		t.Run(command, func(t *testing.T) {
			var root cli
			parser := commandForTest(&root, io.Discard)
			args := []string{"service", command}
			if command == "start" || command == "remove" {
				args = append(args, testExactJobID)
			}
			args = append(args, "--system-state-dir", "/private/system-publisher")
			parsed, err := parser(args)
			if err != nil {
				t.Fatal(err)
			}
			want := "service " + command
			if command == "start" || command == "remove" {
				want += " <job-id>"
			}
			if commandID(parsed) != want {
				t.Fatalf("parent dispatch path: %s, want %s", commandID(parsed), want)
			}
			if command == "start" && root.Service.Start.Job != testExactJobID || command == "remove" && root.Service.Remove.Job != testExactJobID {
				t.Fatal("job selection was lost")
			}
			if command == "serve" {
				path, err := root.Service.Serve.root()
				if err != nil || path != "/private/system-publisher" {
					t.Fatalf("unit's state path was lost: %s %v", path, err)
				}
			}
		})
	}
}

func TestUserAndSystemServiceScopesAndInactiveDiagnostic(t *testing.T) {
	user, err := (systemStateFlags{}).options()
	if err != nil {
		t.Fatal(err)
	}
	system, err := (systemStateFlags{System: true}).options()
	if err != nil {
		t.Fatal(err)
	}
	if !user.User || system.User || user.Root == system.Root || user.Root == "" {
		t.Fatalf("service scopes were mixed: user=%+v system=%+v", user, system)
	}
	err = requireInstalledService(t.Context(), installedjobs.ServiceOptions{Root: t.TempDir(), User: true}, installedjobs.ExecutorFunc(func(context.Context, installedjobs.Command) error {
		t.Fatal("uninstalled service reached the manager")
		return nil
	}))
	if reason, ok := failure.Of(err); !ok || reason.Reason() != failure.ServiceNotInstalled || !errors.Is(err, installedjobs.ErrServiceNotLoaded) {
		t.Fatalf("uninstalled service had no authored next step: %v", err)
	}
}

func TestInstalledServiceArgumentsSelectMatchingStateOwner(t *testing.T) {
	for _, mode := range []struct {
		arg    string
		system bool
	}{{"--user", false}, {"--system", true}} {
		var root cli
		parser := commandForTest(&root, io.Discard)
		if _, err := parser([]string{"service", "serve", "--system-state-dir", "/private/tnl-service", mode.arg}); err != nil {
			t.Fatal(err)
		}
		options, err := root.Service.Serve.options()
		if err != nil || options.User == mode.system || options.Root != "/private/tnl-service" {
			t.Fatalf("%s selected the wrong state owner: %+v", mode.arg, root.Service.Serve)
		}
	}
}

func TestUserHomeFailureNeverFallsBackToSystemState(t *testing.T) {
	previous := serviceUserRoot
	serviceUserRoot = func(string) (string, error) { return "", errors.New("home unavailable") }
	t.Cleanup(func() { serviceUserRoot = previous })
	flags := systemStateFlags{}
	state := filepath.Join(t.TempDir(), "missing-state")
	if _, err := flags.root(); err == nil {
		t.Fatal("missing home silently selected a default state root")
	}
	if _, err := flags.options(); err == nil {
		t.Fatal("missing home silently selected a service scope")
	}
	err := runServiceInstall(t.Context(), serviceInstallCommand{}, io.Discard, installedjobs.ExecutorFunc(func(context.Context, installedjobs.Command) error {
		t.Fatal("user-home failure reached the service manager")
		return nil
	}))
	if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.ClientStateUnavailable {
		t.Fatalf("missing home has no typed failure: %v", err)
	}
	for name, run := range map[string]func() error{
		"start": func() error {
			return runServiceStart(t.Context(), serviceJobCommand{Job: testExactJobID}, io.Discard, nil)
		},
		"stop": func() error {
			return runStopJob(t.Context(), stopCommand{JobID: testExactJobID, StateDir: state}, io.Discard)
		},
		"remove": func() error { return runServiceRemove(t.Context(), serviceJobCommand{Job: testExactJobID}, io.Discard) },
		"list":   func() error { return runJobStatus(t.Context(), jobStatusOptions{StateDir: state}, io.Discard) },
		"show": func() error {
			return runJobStatus(t.Context(), jobStatusOptions{StateDir: state, JobID: testExactJobID}, io.Discard)
		},
		"serve": func() error { return runServiceServe(t.Context(), serviceServeCommand{}) },
		"publish install": func() error {
			return runEnrolledBackgroundPublish(t.Context(), publishCommand{}, enrolledPublishSelection{PublisherCredentialFile: filepath.Join(t.TempDir(), "missing")}, backgroundPublishFlags{}, io.Discard, strings.NewReader(""), nil)
		},
	} {
		if err := run(); err == nil {
			t.Fatalf("%s accepted an unavailable user home", name)
		} else if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.ClientStateUnavailable {
			t.Fatalf("%s selected another state root: %v", name, err)
		}
	}
	system, err := (systemStateFlags{System: true}).options()
	if err != nil || system.User || system.Root == "" {
		t.Fatalf("system state incorrectly depends on a user home: %+v %v", system, err)
	}
}

func TestSystemSupervisorRejectsConnectorRunner(t *testing.T) {
	runner := testServiceRunner(func(context.Context) error { t.Fatal("system service ran a user connector"); return nil })
	err := runServiceServeWithUserJobs(t.Context(), serviceServeCommand{systemStateFlags: systemStateFlags{System: true}}, []installedjobs.UserJobRunner{runner})
	if !errors.Is(err, installedjobs.ErrScope) {
		t.Fatalf("system supervisor accepted a user connector: %v", err)
	}
}

func TestUserSupervisorCanAttachConnectorRunner(t *testing.T) {
	root, err := os.MkdirTemp("/tmp", "tnl-user-supervisor-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	started, joined := make(chan struct{}), make(chan struct{})
	runner := testServiceRunner(func(ctx context.Context) error {
		close(started)
		<-ctx.Done()
		close(joined)
		return nil
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runServiceServeWithUserJobs(ctx, serviceServeCommand{systemStateFlags: systemStateFlags{SystemStateDir: filepath.Join(root, "state"), User: true}}, []installedjobs.UserJobRunner{runner})
	}()
	select {
	case <-started:
	case err := <-done:
		t.Fatalf("user runner never started: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("user runner never started")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("user supervisor did not join its runner")
	}
	select {
	case <-joined:
	default:
		t.Fatal("user connector worker was not joined")
	}
}

type testServiceRunner func(context.Context) error

func (f testServiceRunner) Serve(ctx context.Context, _ func() time.Time, _ context.Context) error {
	return f(ctx)
}

func TestSystemServiceNativeStateOutput(t *testing.T) {
	job := installedjobs.Job{Kind: installedjobs.KindService, ID: testExactJobID, Name: "orders", Server: "https://control.example", PublisherIdentityID: "pub_selected", ServiceID: "svc_selected", Target: "private-target-secret", Protocol: "postgres", Trust: &targettrust.Snapshot{PEM: []byte("trust-secret")}, Enabled: true, Status: installedjobs.Status{State: "ready", RunNumber: 42, Address: "orders.example:25443"}}
	for _, mode := range []statusOutputMode{statusOutputHuman, statusOutputJSON} {
		var output bytes.Buffer
		if err := writeJobList(&output, mode, []jobStatus{installedJobStatus(job, true)}); err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{"orders", testExactJobID, "ready", "orders.example:25443"} {
			if !strings.Contains(output.String(), expected) {
				t.Fatalf("publication field missing: %s", expected)
			}
		}
		for _, hidden := range []string{"secret", "pub_selected", "service run", "run_number"} {
			if strings.Contains(output.String(), hidden) {
				t.Fatalf("unexpected field %q in list: %s", hidden, output.String())
			}
		}
	}
}

func TestSystemServiceHTTPAndConnectorUseServiceIdentity(t *testing.T) {
	for _, kind := range []installedjobs.Kind{installedjobs.KindService, installedjobs.KindConnector} {
		t.Run(string(kind), func(t *testing.T) {
			job := installedjobs.Job{Kind: kind, ID: testExactJobID, Name: "web", ServiceID: "svc_web", Protocol: "http", Enabled: true,
				Server: "https://control.example", PublisherIdentityID: "pub_web", Target: "127.0.0.1:23080",
				Status: installedjobs.Status{State: installedjobs.JobReady, RunNumber: 3, Address: "https://web.example"}}
			var output bytes.Buffer
			if err := writeSelectedJobStatus(&output, statusOutputHuman, installedJobStatus(job, false)); err != nil {
				t.Fatal(err)
			}
			for _, expected := range []string{"service ID", "svc_web", "http"} {
				if !strings.Contains(output.String(), expected) {
					t.Fatal("installed HTTP job lost its service identity", output.String())
				}
			}
			if strings.Contains(output.String(), "public URL") || strings.Contains(output.String(), "publish run") {
				t.Fatal("installed HTTP job rendered a retired resource family", output.String())
			}
			if kind == installedjobs.KindConnector {
				if !strings.Contains(output.String(), "127.0.0.1:23080") || strings.Contains(output.String(), "https://web.example") {
					t.Fatal("connector listener was replaced by a public endpoint", output.String())
				}
			} else if !strings.Contains(output.String(), "https://web.example") || strings.Contains(output.String(), job.Target) {
				t.Fatal("publisher output lost its address or disclosed its target", output.String())
			}
		})
	}
}
