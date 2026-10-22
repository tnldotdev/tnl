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

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestSystemServiceCommandWiring(t *testing.T) {
	for _, command := range []string{"install", "start", "stop", "remove", "list", "serve"} {
		t.Run(command, func(t *testing.T) {
			var root struct {
				Service serviceCommand `cmd:""`
			}
			parser, err := kong.New(&root, kong.Name("tnl"), kong.Writers(io.Discard, io.Discard))
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"service", command}
			if command == "start" || command == "stop" || command == "remove" {
				args = append(args, "database")
			}
			args = append(args, "--system-state-dir", "/private/system-publisher")
			parsed, err := parser.Parse(args)
			if err != nil {
				t.Fatal(err)
			}
			want := "service " + command
			if command == "start" || command == "stop" || command == "remove" {
				want += " <job>"
			}
			if parsed.Command() != want {
				t.Fatalf("parent dispatch path: %s, want %s", parsed.Command(), want)
			}
			if command == "start" && root.Service.Start.Job != "database" || command == "stop" && root.Service.Stop.Job != "database" {
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
	err = requireInstalledService(t.Context(), supervisor.ServiceOptions{Root: t.TempDir(), User: true}, supervisor.ExecutorFunc(func(context.Context, supervisor.Command) error {
		t.Fatal("uninstalled service reached the manager")
		return nil
	}))
	if reason, ok := failure.Of(err); !ok || reason.Reason() != failure.ServiceNotInstalled || !errors.Is(err, supervisor.ErrServiceNotLoaded) {
		t.Fatalf("uninstalled service had no authored next step: %v", err)
	}
}

func TestInstalledServiceArgumentsSelectMatchingStateOwner(t *testing.T) {
	for _, mode := range []struct {
		arg    string
		system bool
	}{{"--user", false}, {"--system", true}} {
		var root struct {
			Service serviceCommand `cmd:""`
		}
		parser, err := kong.New(&root, kong.Name("tnl"), kong.Writers(io.Discard, io.Discard))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parser.Parse([]string{"service", "serve", "--system-state-dir", "/private/tnl-service", mode.arg}); err != nil {
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
	if _, err := flags.root(); err == nil {
		t.Fatal("missing home silently selected a default state root")
	}
	if _, err := flags.options(); err == nil {
		t.Fatal("missing home silently selected a service scope")
	}
	err := runServiceInstall(t.Context(), serviceInstallCommand{}, io.Discard, supervisor.ExecutorFunc(func(context.Context, supervisor.Command) error {
		t.Fatal("user-home failure reached the service manager")
		return nil
	}))
	if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.ClientStateUnavailable {
		t.Fatalf("missing home has no typed failure: %v", err)
	}
	for name, run := range map[string]func() error{
		"start":  func() error { return runServiceStart(t.Context(), serviceJobCommand{Job: "one"}, io.Discard, nil) },
		"stop":   func() error { return runServiceStop(t.Context(), serviceJobCommand{Job: "one"}, io.Discard) },
		"remove": func() error { return runServiceRemove(t.Context(), serviceJobCommand{Job: "one"}, io.Discard) },
		"list":   func() error { return runServiceList(t.Context(), serviceListCommand{}, io.Discard) },
		"serve":  func() error { return runServiceServe(t.Context(), serviceServeCommand{}) },
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
	err := runServiceServeWithUserJobs(t.Context(), serviceServeCommand{systemStateFlags: systemStateFlags{System: true}}, []supervisor.UserJobRunner{runner})
	if !errors.Is(err, supervisor.ErrScope) {
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
		done <- runServiceServeWithUserJobs(ctx, serviceServeCommand{systemStateFlags: systemStateFlags{SystemStateDir: filepath.Join(root, "state"), User: true}}, []supervisor.UserJobRunner{runner})
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

func (f testServiceRunner) Serve(ctx context.Context) error { return f(ctx) }

func TestSystemServiceNativeStateOutput(t *testing.T) {
	job := supervisor.Job{ID: "url-012345", Name: "orders", Server: "https://control.example", PublisherIdentityID: "pub_selected", PublicURLID: "url_selected", Target: "private-target-secret", Protocol: "postgres", TargetCAPEM: []byte("trust-secret"), Enabled: true, Status: supervisor.Status{State: "ready", RunNumber: 42}}
	var output bytes.Buffer
	if err := renderSystemJobs(&output, "tnl service list", []supervisor.Job{job}, ""); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"orders", "url-012345", "postgres", "ready", "42", "url_selected", "pub_selected"} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("publication field missing: %s", expected)
		}
	}
	if strings.Contains(output.String(), "secret") {
		t.Fatal("private state escaped the renderer")
	}
	for _, line := range strings.Split(output.String(), "\n") {
		if len(line) > 72 {
			t.Fatalf("frame wider than 72 columns: %q", line)
		}
		for _, c := range line {
			if c > 127 || c == 27 {
				t.Fatal("non-ASCII output")
			}
		}
	}
}
