package main

import (
	"errors"
	"io"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
)

func TestFixedGroupsRejectDuplicateOwnershipBeforeStateOrControl(t *testing.T) {
	value := testPublisherGroupIdentity(t)
	write := func(value credentialfile.GroupFile) string {
		t.Helper()
		path := filepath.Join(t.TempDir(), "identity.json")
		if err := credentialfile.WriteGroup(path, value); err != nil {
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
				other := testPublisherGroupIdentity(t)
				duplicate.PrivateKey = other.PrivateKey
				duplicate.Member.PublisherIdentityId = other.Member.PublisherIdentityId
				duplicate.Member.KeyId = other.Member.KeyId
			}
			second := write(duplicate)
			flags := publisherServeCommand{IdentityFile: []string{first, second}, StateDir: "/does/not/exist/state", IdentityDir: "/does/not/exist/identity"}
			if _, err := readFixedPublisherGroups(flags); !errors.Is(err, supervisor.ErrJobExists) {
				t.Fatal("duplicate ownership was not rejected locally", err)
			}
			if err := run(t.Context(), []string{"--no-telemetry", "--no-config", "publisher", "serve", "--identity-file", first, "--identity-file", second, "--state-dir", flags.StateDir, "--identity-dir", flags.IdentityDir}, io.Discard, io.Discard); !errors.Is(err, supervisor.ErrJobExists) {
				t.Fatal("repeatable CLI input did not reject duplicate ownership before opening state", err)
			}
		})
	}
}

func TestFixedGroupsUseIdentityBindingWithoutSingleGroupOverrides(t *testing.T) {
	value := testPublisherGroupIdentity(t)
	path := filepath.Join(t.TempDir(), "identity.json")
	if err := credentialfile.WriteGroup(path, value); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_DEPLOYMENT_PROVIDER", "malformed-ambient-provenance")
	flags := publisherServeCommand{IdentityFile: []string{path}, StateDir: "/state", IdentityDir: "/identity"}
	inputs, err := readFixedPublisherGroups(flags)
	if err != nil || len(inputs) != 1 {
		t.Fatal("identity-bound command required --group or ambient provenance", err)
	}
	if inputs[0].job.GroupInstance != value.Instance || inputs[0].job.Server != value.ControlURL || inputs[0].runner.Deployment != nil {
		t.Fatal("fixed group did not retain exact identity scope")
	}
	for _, modify := range []func(*publisherServeCommand){func(f *publisherServeCommand) { f.Group = "production" }, func(f *publisherServeCommand) { f.Team = "another" }, func(f *publisherServeCommand) { f.EnrollmentKey = "secret" }, func(f *publisherServeCommand) { f.Detach = true }} {
		invalid := flags
		modify(&invalid)
		if err := validateFixedPublisherGroups(invalid); err == nil {
			t.Fatal("fixed list accepted a single-group override")
		}
	}
}
