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
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDeploymentIdentityInputConsumesInjectedSecretWithoutFallback(t *testing.T) {
	value := testDeploymentIdentity(t)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteDeployment(path, value); err != nil {
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
			t.Setenv("TNL_DEPLOYMENT_IDENTITY", input.secret)
			loaded, supplied, err := deploymentPublisherIdentityInput(input.path)
			if !supplied || (err == nil) != input.valid || input.valid && loaded != value {
				t.Fatal("identity input did not fail closed or changed the credential", err)
			}
			if _, exists := os.LookupEnv("TNL_DEPLOYMENT_IDENTITY"); exists {
				t.Fatal("injected key remains available to child processes")
			}
		})
	}
	t.Setenv("TNL_DEPLOYMENT_IDENTITY", "")
	if err := os.Unsetenv("TNL_DEPLOYMENT_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	loaded, supplied, err := deploymentPublisherIdentityInput(path)
	if err != nil || !supplied || loaded != value {
		t.Fatal("mounted file did not use the same contract", err)
	}
	if _, supplied, err := deploymentPublisherIdentityInput(""); err != nil || supplied {
		t.Fatal("absent identity incorrectly selected import", err)
	}
	if _, supplied, err := deploymentPublisherIdentityInput(path + ".missing"); !supplied || !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("missing explicit file fell back to enrollment", err)
	}
}

func testDeploymentIdentity(t *testing.T) credentialfile.DeploymentFile {
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
	value, err := credentialfile.NewDeployment("https://control.example", "replica-1", controlv1.DeploymentPublisherIdentity{TeamId: "team", ProjectKey: "shop", DeploymentName: "production", DeploymentId: id("dpl_"), PublisherIdentityId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix)}, private)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDeploymentIdentityCLIRejectsInvalidInputBeforeStateOrEnrollment(t *testing.T) {
	value := testDeploymentIdentity(t)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteDeployment(path, value); err != nil {
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
			t.Setenv("TNL_DEPLOYMENT_IDENTITY", "")
			if err := os.Unsetenv("TNL_DEPLOYMENT_IDENTITY"); err != nil {
				t.Fatal(err)
			}
			t.Setenv("TNL_DEPLOYMENT_ENROLL_KEY", "")
			if input.secret != nil {
				t.Setenv("TNL_DEPLOYMENT_IDENTITY", *input.secret)
			}
			state := filepath.Join(t.TempDir(), "state")
			args := append([]string{"--no-config", "--no-telemetry", "publisher", "serve", "--deployment", "production", "--instance", "replica-1", "--state-dir", state}, input.args...)
			var output, diagnostics bytes.Buffer
			if err := run(t.Context(), args, &output, &diagnostics); err == nil {
				t.Fatal("invalid identity selected enrollment or saved person state")
			} else {
				writeCommandError(&diagnostics, err)
			}
			if _, err := os.Lstat(state); !os.IsNotExist(err) {
				t.Fatalf("invalid identity opened local state: %v", err)
			}
			if _, exists := os.LookupEnv("TNL_DEPLOYMENT_IDENTITY"); exists {
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
		t.Setenv("TNL_DEPLOYMENT_ENROLL_KEY", "must-not-be-redeemed")
		t.Setenv("TNL_DEPLOYMENT_IDENTITY", string(encoded))
		state := filepath.Join(t.TempDir(), "state")
		if err := run(t.Context(), []string{"--no-config", "publisher", "serve", "--deployment", "production", "--instance", "replica-1", "--state-dir", state}, io.Discard, io.Discard); err == nil {
			t.Fatal("identity accepted enrollment from environment")
		}
		if _, err := os.Lstat(state); !os.IsNotExist(err) {
			t.Fatal("conflicting credentials opened client state")
		}
	})
}

func TestDeploymentIdentityBindsControlBeforeProjectDefaults(t *testing.T) {
	t.Setenv("TNL_DEPLOYMENT_IDENTITY", "")
	if err := os.Unsetenv("TNL_DEPLOYMENT_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	value := testDeploymentIdentity(t)
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteDeployment(path, value); err != nil {
		t.Fatal(err)
	}
	projectServer, team := "https://unrelated.example", "unrelated-team"
	project := projectConfiguration{Project: clientproject.Project{Config: config.TNL{Server: &projectServer, Team: &team}}}
	for _, selected := range []string{"", value.ControlURL + "/"} {
		var flags cli
		flags.Publisher.Serve = publisherServeCommand{IdentityFile: []string{path}, Deployment: "production", Instance: "replica-1", ProjectKey: "shop", scopedTeamFlags: scopedTeamFlags{remoteFlags: remoteFlags{ServerURL: selected}}}
		if err := prepareDeploymentIdentity(&flags.Publisher.Serve); err != nil {
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

func TestDeploymentIdentityDefaultInstanceStillRequiresAnExactMatch(t *testing.T) {
	t.Setenv("TNL_DEPLOYMENT_IDENTITY", "")
	if err := os.Unsetenv("TNL_DEPLOYMENT_IDENTITY"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_DEPLOYMENT_ENROLL_KEY", "")
	value := testDeploymentIdentity(t)
	for _, instance := range []string{"replica-1", "default"} {
		value.Instance = instance
		path := filepath.Join(t.TempDir(), "identity.json")
		if err := credentialfile.WriteDeployment(path, value); err != nil {
			t.Fatal(err)
		}
		for _, explicit := range []bool{false, true} {
			var flags cli
			parser, err := kong.New(&flags)
			if err != nil {
				t.Fatal(err)
			}
			args := []string{"publisher", "serve", "--deployment", "production", "--identity-file", path}
			if explicit {
				args = append(args, "--instance", "default")
			}
			if _, err := parser.Parse(args); err != nil {
				t.Fatal(err)
			}
			if err := prepareDeploymentIdentity(&flags.Publisher.Serve); (err == nil) != (instance == "default") {
				t.Fatal("default instance bypassed the credential's exact replica binding")
			}
		}
	}
}

func TestDeploymentIdentityProvisionRejectsMixedAndIncompleteScopes(t *testing.T) {
	for _, flags := range []publisherProvisionCommand{
		{Deployment: "production", Instance: "replica-1", Namespace: true},
		{Deployment: "production", Instance: "replica-1", URL: "url_selected"},
		{Deployment: "production", Instance: "replica-1", ServiceID: "svc_selected"},
		{Deployment: "production", Instance: "replica-1", Domain: "example.test"},
		{Deployment: "production"},
		{Deployment: "local", Instance: "replica-1"},
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

func TestDeploymentIdentityInstallPreflightBeforeProjectOrIdentityState(t *testing.T) {
	state, service := filepath.Join(t.TempDir(), "state"), filepath.Join(t.TempDir(), "supervisor")
	t.Setenv("TNL_DEPLOYMENT_IDENTITY", "not-valid-json")
	err := run(t.Context(), []string{"publisher", "serve", "--deployment", "production", "--install", "--state-dir", state, "--system-state-dir", service}, io.Discard, io.Discard)
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServiceNotInstalled {
		t.Fatalf("install did not preflight before identity processing: %v", err)
	}
	for _, path := range []string{state, service} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatal("install preflight created local state")
		}
	}
}

func TestDeploymentIdentityFlagsAppearInGeneratedHelp(t *testing.T) {
	for command, wanted := range map[string][]string{
		"provision": {"--deployment", "--project-key", "--instance", "--output-file"},
		"serve":     {"--identity-file", "TNL_DEPLOYMENT_IDENTITY", "--instance", "--enroll-key"},
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
				args = append(args, "--deployment", "production")
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
