package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alecthomas/kong"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestGroupIdentityInputConsumesInjectedSecretWithoutFallback(t *testing.T) {
	value := testPublisherGroupIdentity(t)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteGroup(path, value); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		name, secret, path string
		valid              bool
	}{
		{name: "valid injection", secret: string(encoded), valid: true},
		{name: "empty supplied secret"},
		{name: "invalid supplied secret", secret: "must-not-appear-in-errors"},
		{name: "ambiguous sources", secret: string(encoded), path: path},
	} {
		t.Run(input.name, func(t *testing.T) {
			t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", input.secret)
			loaded, supplied, err := publisherGroupIdentityInput(input.path)
			if !supplied || (err == nil) != input.valid || input.valid && loaded != value {
				t.Fatal("identity input did not fail closed or changed the credential", err)
			}
			if _, exists := os.LookupEnv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); exists {
				t.Fatal("injected key remains available to child processes")
			}
		})
	}
	t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "")
	if err := os.Unsetenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	loaded, supplied, err := publisherGroupIdentityInput(path)
	if err != nil || !supplied || loaded != value {
		t.Fatal("mounted file did not use the same contract", err)
	}
	if _, supplied, err := publisherGroupIdentityInput(""); err != nil || supplied {
		t.Fatal("absent identity incorrectly selected import", err)
	}
	if _, supplied, err := publisherGroupIdentityInput(path + ".missing"); !supplied || !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("missing explicit file fell back to enrollment", err)
	}
}

func testPublisherGroupIdentity(t *testing.T) credentialfile.GroupFile {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	value, err := credentialfile.NewGroup("https://control.example", "replica-1", controlv1.EnvironmentPublisher{TeamId: id(opaqueid.TeamPrefix), ProjectKey: "shop", EnvironmentId: id(opaqueid.EnvironmentPrefix), PublisherIdentityId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix)}, private)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestGroupIdentityCLIRejectsInvalidInputBeforeStateOrEnrollment(t *testing.T) {
	value := testPublisherGroupIdentity(t)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteGroup(path, value); err != nil {
		t.Fatal(err)
	}
	for _, input := range []struct {
		name   string
		secret *string
		args   []string
	}{
		{name: "empty injection", secret: new("")},
		{name: "invalid injection", secret: new("must-not-appear-in-errors")},
		{name: "missing mounted identity", args: []string{"--identity-file", path + ".missing"}},
		{name: "ambiguous sources", secret: new(string(encoded)), args: []string{"--identity-file", path}},
		{name: "enrollment flag with file", args: []string{"--identity-file", path, "--enroll-key", "must-not-be-redeemed"}},
		{name: "enrollment flag with injection", secret: new(string(encoded)), args: []string{"--enroll-key", "must-not-be-redeemed"}},
		{name: "another control", args: []string{"--identity-file", path, "--server", "https://another.example"}},
		{name: "another project", args: []string{"--identity-file", path, "--project-key", "another"}},
		{name: "another instance", args: []string{"--identity-file", path, "--instance", "another"}},
	} {
		t.Run(input.name, func(t *testing.T) {
			t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "")
			if err := os.Unsetenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TNL_ENVIRONMENT_ENROLL_KEY", "")
			if input.secret != nil {
				t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", *input.secret)
			}
			state := filepath.Join(t.TempDir(), "state")
			args := append([]string{"--no-config", "--no-telemetry", "publisher", "serve", "--environment", value.Member.EnvironmentId, "--instance", "replica-1", "--state-dir", state}, input.args...)
			var output, diagnostics bytes.Buffer
			if err := run(t.Context(), args, &output, &diagnostics); err == nil {
				t.Fatal("invalid identity selected enrollment or saved person state")
			} else {
				writeCommandError(&diagnostics, err)
			}
			if _, err := os.Lstat(state); !os.IsNotExist(err) {
				t.Fatalf("invalid identity opened local state: %v", err)
			}
			if _, exists := os.LookupEnv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); exists {
				t.Fatal("injected key remains available to child processes")
			}
			for _, secret := range []string{value.PrivateKey, "must-not-appear-in-errors", "must-not-be-redeemed"} {
				if strings.Contains(output.String()+diagnostics.String(), secret) {
					t.Fatal("identity or enrollment secret appeared in CLI output")
				}
			}
		})
	}
	t.Run("enrollment environment with identity", func(t *testing.T) {
		t.Setenv("TNL_ENVIRONMENT_ENROLL_KEY", "must-not-be-redeemed")
		t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", string(encoded))
		state := filepath.Join(t.TempDir(), "state")
		if err := run(t.Context(), []string{"--no-config", "publisher", "serve", "--environment", value.Member.EnvironmentId, "--instance", "replica-1", "--state-dir", state}, io.Discard, io.Discard); err == nil {
			t.Fatal("identity accepted enrollment from environment")
		}
		if _, err := os.Lstat(state); !os.IsNotExist(err) {
			t.Fatal("conflicting credentials opened client state")
		}
	})
}

func TestGroupIdentityBindsControlBeforeProjectDefaults(t *testing.T) {
	t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "")
	if err := os.Unsetenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	value := testPublisherGroupIdentity(t)
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteGroup(path, value); err != nil {
		t.Fatal(err)
	}
	projectServer, team := "https://unrelated.example", "unrelated-team"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &projectServer, Team: &team}}}
	for _, selected := range []string{"", value.ControlURL + "/"} {
		var flags cli
		flags.Publisher.Serve = publisherServeCommand{IdentityFile: []string{path}, Environment: value.Member.EnvironmentId, Instance: "replica-1", ProjectKey: "shop", scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: selected}}}
		if err := preparePublisherGroupIdentity(&flags.Publisher.Serve); err != nil {
			t.Fatal(err)
		}
		if err := applyProjectCommandContext("publisher serve", project, &flags); err != nil {
			t.Fatal(err)
		}
		if flags.Publisher.Serve.ServerURL != value.ControlURL || flags.Publisher.Serve.ProjectTeam != "" {
			t.Fatal("project defaults redirected the imported identity")
		}
	}
}

func TestGroupIdentityDefaultInstanceStillRequiresAnExactMatch(t *testing.T) {
	t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "")
	if err := os.Unsetenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_ENVIRONMENT_ENROLL_KEY", "")
	value := testPublisherGroupIdentity(t)
	for _, instance := range []string{"replica-1", "default"} {
		value.Instance = instance
		path := filepath.Join(t.TempDir(), "identity.json")
		if err := credentialfile.WriteGroup(path, value); err != nil {
			t.Fatal(err)
		}
		for _, explicit := range []bool{false, true} {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"publisher", "serve", "--environment", value.Member.EnvironmentId, "--identity-file", path}
			if explicit {
				args = append(args, "--instance", "default")
			}
			if _, err := parser.Parse(args); err != nil {
				t.Fatal(err)
			}
			if err := preparePublisherGroupIdentity(&flags.Publisher.Serve); (err == nil) != (instance == "default") {
				t.Fatal("default instance bypassed the credential's exact replica binding")
			}
		}
	}
}

func TestGroupIdentityProvisionRejectsMixedAndIncompleteScopes(t *testing.T) {
	for _, flags := range []publisherProvisionCommand{
		{Environment: "production", Instance: "replica-1", Namespace: true},
		{Environment: "production", Instance: "replica-1", URL: "url_selected"},
		{Environment: "production", Instance: "replica-1", ServiceID: "svc_selected"},
		{Environment: "production", Instance: "replica-1", Domain: "example.test"},
		{Environment: "production"},
		{Environment: "local", Instance: "replica-1"},
		{ProjectKey: "shop", Namespace: true},
		{Instance: "replica-1", Namespace: true},
	} {
		flags.OutputFile = filepath.Join(t.TempDir(), "identity.json")
		err := runPublisherProvision(t.Context(), flags, projectConfiguration{}, io.Discard, io.Discard)
		if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags {
			t.Fatalf("invalid provision scope reached local or remote enrollment: %v", err)
		}
	}
}

func TestGroupIdentityInstallPreflightBeforeProjectOrIdentityState(t *testing.T) {
	state, service := filepath.Join(t.TempDir(), "state"), filepath.Join(t.TempDir(), "supervisor")
	t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "not-valid-json")
	err := run(t.Context(), []string{"publisher", "serve", "--environment", testPublisherGroupIdentity(t).Member.EnvironmentId, "--install", "--state-dir", state, "--system-state-dir", service}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServiceNotInstalled {
		t.Fatalf("install did not preflight before identity processing: %v", err)
	}
	for _, path := range []string{state, service} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("install preflight created local state")
		}
	}
}

func TestGroupIdentityFlagsAppearInGeneratedHelp(t *testing.T) {
	for command, wanted := range map[string][]string{
		"provision": {"--environment", "--services", "--project-key", "--instance", "--output-file"},
		"serve":     {"--identity-file", "TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "--instance", "--enroll-key"},
	} {
		t.Run(command, func(t *testing.T) {
			var flags cli
			var output bytes.Buffer
			parser, err := kong.New(&flags, kong.Name("tnl"), kong.Writers(&output, io.Discard), kong.Exit(func(int) {}))
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"publisher", command, "--help"}
			if command == "provision" {
				args = append(args, "--output-file", filepath.Join(t.TempDir(), "identity.json"))
			} else {
				args = append(args, "--environment", testPublisherGroupIdentity(t).Member.EnvironmentId)
			}
			if _, err := parser.Parse(args); err != nil {
				t.Fatal(err)
			}
			for _, want := range wanted {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("generated help is missing %s", want)
				}
			}
		})
	}
}

func TestEnvironmentPublisherServeRequiresExplicitBootstrapWithoutPersonFallback(t *testing.T) {
	t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "")
	if err := os.Unsetenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	value := testPublisherGroupIdentity(t)
	state := filepath.Join(t.TempDir(), "state")
	err := runPublisherServe(t.Context(), publisherServeCommand{
		Environment: value.Member.EnvironmentId, ProjectKey: value.Member.ProjectKey, Instance: value.Instance,
		scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: value.ControlURL, StateDir: state}},
	}, projectConfiguration{}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags {
		t.Fatal("new replica attempted implicit human-session enrollment", err)
	}
	database, err := clientstate.Open(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	profile, err := database.Server(t.Context(), value.ControlURL)
	if err != nil {
		t.Fatal(err)
	}
	selection := credentialfile.GroupSelection(value.Member.ProjectKey, value.Member.EnvironmentId, value.Instance)
	if _, found, err := profile.PendingPublisherEnrollmentForSelection(t.Context(), "project", selection); err != nil || found {
		t.Fatal("missing bootstrap created a pending signing identity", err)
	}
	if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
		t.Fatal("publisher serve opened a person session", err)
	}
}

func TestEnvironmentPublisherIdentityRejectsAnotherEnvironmentBeforeState(t *testing.T) {
	t.Setenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY", "")
	if err := os.Unsetenv("TNL_ENVIRONMENT_PUBLISHER_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	value := testPublisherGroupIdentity(t)
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteGroup(path, value); err != nil {
		t.Fatal(err)
	}
	other := testPublisherGroupIdentity(t)
	flags := publisherServeCommand{Environment: other.Member.EnvironmentId, ProjectKey: value.Member.ProjectKey, Instance: value.Instance, IdentityFile: []string{path}}
	if err := preparePublisherGroupIdentity(&flags); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("friendly names or another environment selected this signing key", err)
	}
	if flags.identity != nil {
		t.Fatal("foreign environment retained portable signing authority")
	}
}
