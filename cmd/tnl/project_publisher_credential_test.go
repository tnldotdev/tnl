package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProjectPublisherCredentialCreationKeepsOneOwnerSecretPrivate(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	project := t.TempDir()
	configuration := []byte(`{"version":1,"tnl":{"publisher":{"type":"url","url":"https://publisher.example.test","owner_credential_file":".tnl/owner-token"}}}`)
	if err := os.WriteFile(filepath.Join(project, "tnl.json"), configuration, 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	state := filepath.Join(t.TempDir(), "state")
	var stdout, stderr bytes.Buffer
	args := []string{"project", "publisher", "credential", "create", "--state-dir", state, "--output", "raw"}
	if err := run(t.Context(), args, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	credential := strings.TrimSpace(stdout.String())
	if len(credential) != 43 || stderr.Len() != 0 {
		t.Fatalf("owner credential output = %q, %q", stdout.String(), stderr.String())
	}
	path := filepath.Join(project, ".tnl", "owner-token")
	if saved, err := readPublisherOwnerCredential(project, path); err != nil || saved != credential {
		t.Fatalf("private owner credential = %q, %v", saved, err)
	}
	stdout.Reset()
	if err := run(t.Context(), args, &stdout, &stderr); err == nil || stdout.Len() != 0 {
		t.Fatalf("credential overwrite = %v, stdout=%q", err, stdout.String())
	}
}

func TestProjectPublisherCredentialUsesThePrivateDefaultPath(t *testing.T) {
	t.Setenv("TNL_CONFIG", "")
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), []byte(`{"version":1,"tnl":{"publisher":{"type":"url","url":"https://publisher.example.test"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	state := filepath.Join(t.TempDir(), "state")
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"project", "publisher", "credential", "create", "--state-dir", state}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	credential, err := readPublisherOwnerCredential(root, ".tnl/publisher-owner")
	if err != nil || len(credential) != 43 || strings.Contains(stdout.String(), credential) {
		t.Fatalf("private default credential = %v, human output = %q", err, stdout.String())
	}
}
