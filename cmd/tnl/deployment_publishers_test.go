package main

import (
	"errors"
	"io"
	"path/filepath"
	"testing"

	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
)

func TestFixedDeploymentsRejectDuplicateOwnershipBeforeStateOrControl(t *testing.T) {
	value := testDeploymentIdentity(t)
	write := func(value credentialfile.DeploymentFile) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "identity.json")
		if err := credentialfile.WriteDeployment(path, value); err != nil {
			t.Fatal(err)
		}
		return path
	}
	first := write(value)
	for _, kind := range []string{"same-file", "another-instance", "same-replica"} {
		t.Run(kind, func(t *testing.T) {
			duplicate := value
			switch kind {
			case "another-instance":
				duplicate.Instance = "another"
			case "same-replica":
				other := testDeploymentIdentity(t)
				duplicate.PrivateKey = other.PrivateKey
				duplicate.Member.PublisherIdentityId = other.Member.PublisherIdentityId
				duplicate.Member.KeyId = other.Member.KeyId
			}
			second := write(duplicate)
			flags := publisherServeCommand{IdentityFile: []string{first, second}, StateDir: "/does/not/exist/state", IdentityDir: "/does/not/exist/identity"}
			if _, err := readFixedDeploymentRuntime(flags); !errors.Is(err, installedjobs.ErrJobExists) {
				t.Fatal("duplicate ownership was not rejected locally", err)
			}
			if err := run(t.Context(), []string{"--no-telemetry", "--no-config", "publisher", "serve", "--identity-file", first, "--identity-file", second, "--state-dir", flags.StateDir, "--identity-dir", flags.IdentityDir}, io.Discard, io.Discard); !errors.Is(err, installedjobs.ErrJobExists) {
				t.Fatal("repeatable CLI input did not reject duplicate ownership before opening state", err)
			}
		})
	}
}

func TestFixedDeploymentsUseIdentityBindingWithoutSingleDeploymentOverrides(t *testing.T) {
	value := testDeploymentIdentity(t)
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteDeployment(path, value); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_DEPLOYMENT_PROVIDER", "malformed-ambient-provenance")
	flags := publisherServeCommand{IdentityFile: []string{path}, StateDir: "/state", IdentityDir: "/identity"}
	inputs, err := readFixedDeploymentRuntime(flags)
	if err != nil || len(inputs) != 1 {
		t.Fatal("identity-bound command required --deployment or ambient provenance", err)
	}
	if inputs[0].job.DeploymentInstance != value.Instance || inputs[0].job.Server != value.ControlURL || inputs[0].runner.Deployment != nil {
		t.Fatal("fixed deployment did not retain exact identity scope")
	}
	for _, modify := range []func(*publisherServeCommand){func(f *publisherServeCommand) { f.Deployment = "production" }, func(f *publisherServeCommand) { f.Team = "another" }, func(f *publisherServeCommand) { f.EnrollmentKey = "secret" }, func(f *publisherServeCommand) { f.Detach = true }} {
		invalid := flags
		modify(&invalid)
		if err := validateFixedDeploymentRuntime(invalid); err == nil {
			t.Fatal("fixed list accepted a single-deployment override")
		}
	}
}
