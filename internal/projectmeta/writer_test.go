package projectmeta

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/filelock"
)

func TestRenderProducesSortedLiteralPublicShape(t *testing.T) {
	metadata := Metadata{
		Version: Version, Namespace: "ecstatic-penguin.tnl.dev",
		Services: map[string]Service{
			"web": {
				Namespace: "ecstatic-penguin.tnl.dev", Hostname: "web-tnl-bb4eff.ecstatic-penguin.tnl.dev",
				URL: "https://web-tnl-bb4eff.ecstatic-penguin.tnl.dev",
			},
			"api": {
				Namespace: "ecstatic-penguin.tnl.dev", Hostname: "api-tnl-bb4eff.ecstatic-penguin.tnl.dev",
				URL: "https://api-tnl-bb4eff.ecstatic-penguin.tnl.dev",
			},
		},
		ServiceDirectories: map[string]string{"web": "apps/web", "api": "apps/api"},
	}
	jsonData, declarations, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	text := string(declarations)
	api, web := strings.Index(text, "readonly api:"), strings.Index(text, "readonly web:")
	if api < 0 || web < 0 || api >= web ||
		!strings.Contains(text, "interface TnlProjectMetadata") ||
		!strings.Contains(text, `readonly namespace: "ecstatic-penguin.tnl.dev"`) ||
		!strings.Contains(text, `readonly hostname: "api-tnl-bb4eff.ecstatic-penguin.tnl.dev"`) ||
		!strings.Contains(text, `readonly url: "https://api-tnl-bb4eff.ecstatic-penguin.tnl.dev"`) ||
		strings.Contains(text, "TnlProjectRegistry") || strings.Contains(text, "serviceDirectories") ||
		strings.Contains(text, "readonly project:") {
		t.Fatalf("declarations =\n%s", declarations)
	}
	golden, err := os.ReadFile(filepath.Join("testdata", "project.d.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(declarations, golden) {
		t.Fatalf("declarations do not match golden:\n%s", declarations)
	}
	if bytes.Count(jsonData, []byte(`"namespace": "ecstatic-penguin.tnl.dev"`)) != 3 {
		t.Fatalf("JSON does not expose the project and service namespaces:\n%s", jsonData)
	}
	public := metadata.Public(true)
	if !public.Dev || public.Services["api"].Namespace != "ecstatic-penguin.tnl.dev" {
		t.Fatalf("public metadata = %#v", public)
	}
	for _, forbidden := range []string{"target", "accessToken", "tunnelID", "teamID", "projectRoot"} {
		if bytes.Contains(jsonData, []byte(forbidden)) || bytes.Contains(declarations, []byte(forbidden)) {
			t.Fatalf("generated metadata contains %q", forbidden)
		}
	}
}

func TestTypeScriptPropertyNameQuotesHyphenatedServices(t *testing.T) {
	if got := typeScriptPropertyName("worker-ui"); got != `"worker-ui"` {
		t.Fatalf("hyphenated property name = %q", got)
	}
	if got := typeScriptPropertyName("api"); got != "api" {
		t.Fatalf("simple property name = %q", got)
	}
}

func TestWriteRejectsInvalidMetadataWithoutChangingFiles(t *testing.T) {
	root := t.TempDir()
	metadata := Metadata{
		Version: Version, Namespace: "ecstatic-penguin.tnl.dev",
		Services: map[string]Service{
			"api": {
				Namespace: "ecstatic-penguin.tnl.dev", Hostname: "api.ecstatic-penguin.tnl.dev",
				URL: "https://api.ecstatic-penguin.tnl.dev",
			},
		},
		ServiceDirectories: map[string]string{"api": "."},
	}
	if err := Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(root, DirectoryName, JSONName)
	before, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	declarationsPath := filepath.Join(root, DirectoryName, DeclarationsName)
	declarationsBefore, err := os.ReadFile(declarationsPath)
	if err != nil {
		t.Fatal(err)
	}
	invalid := metadata
	invalid.Namespace = "INVALID"
	if err := Write(t.Context(), root, invalid); err == nil {
		t.Fatal("invalid metadata was written")
	}
	after, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed write changed existing metadata")
	}
	declarationsAfter, err := os.ReadFile(declarationsPath)
	if err != nil || !bytes.Equal(declarationsBefore, declarationsAfter) {
		t.Fatalf("invalid input changed declarations: %v", err)
	}
}

func TestStagedWriteRollbackReportsRestoreFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "project.d.ts")
	if err := os.WriteFile(path, []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write, err := stageWrite(path, []byte("replacement\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer write.cleanup()
	if err := write.commit(); err != nil {
		t.Fatal(err)
	}
	// force a filesystem failure after commit, rather than invalid input
	// rejected before any write. restoring cannot overwrite a directory.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	err = write.restore()
	var pathErr *os.PathError
	if !errors.As(err, &pathErr) || !strings.Contains(err.Error(), "restore generated project metadata") {
		t.Fatalf("rollback failure = %v", err)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "project.d.ts" {
		t.Fatalf("rollback leaked staged files: %v", entries)
	}
}

func TestWriteReplacesBothGeneratedFiles(t *testing.T) {
	root := t.TempDir()
	metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{}, ServiceDirectories: map[string]string{}}
	if err := Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	metadata.Services["api"] = Service{Namespace: "member.example", Hostname: "api.member.example", URL: "https://api.member.example"}
	metadata.ServiceDirectories["api"] = "."
	if err := Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	jsonData, declarations, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string][]byte{JSONName: jsonData, DeclarationsName: declarations} {
		got, err := os.ReadFile(filepath.Join(root, DirectoryName, name))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("%s = %s, %v", name, got, err)
		}
	}
}

func TestWriteLockWaitHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, DirectoryName)
	if err := prepareDirectory(directory); err != nil {
		t.Fatal(err)
	}
	lock, err := filelock.Acquire(filepath.Join(directory, "project.lock"), filelock.Blocking, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	metadata := Metadata{
		Version: Version, Namespace: "member.example",
		Services: map[string]Service{}, ServiceDirectories: map[string]string{},
	}
	if err := Write(ctx, root, metadata); !errors.Is(err, context.Canceled) {
		t.Fatalf("write = %v", err)
	}
}

func TestRenderRejectsOversizedMetadata(t *testing.T) {
	metadata := Metadata{
		Version: Version, Namespace: "member.example",
		Services: map[string]Service{
			"api": {
				Namespace: "member.example", Hostname: "api.member.example", URL: "https://api.member.example",
			},
		},
		ServiceDirectories: map[string]string{"api": strings.Repeat("a", MaxFileBytes)},
	}
	if _, _, err := Render(metadata); err == nil || !strings.Contains(err.Error(), "exceeds 65536 bytes") {
		t.Fatalf("oversized metadata error = %v", err)
	}
}

func TestRenderBroadensNamespaceWhenServicesDiffer(t *testing.T) {
	metadata := Metadata{
		Version: Version, Namespace: "member.example",
		Services: map[string]Service{
			"api": {
				Namespace: "member.other.example", Hostname: "api.member.other.example",
				URL: "https://api.member.other.example",
			},
		},
		ServiceDirectories: map[string]string{"api": "."},
	}
	_, declarations, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	text := string(declarations)
	if !strings.Contains(text, "interface TnlProjectMetadata") ||
		!strings.Contains(text, "  interface TnlProjectMetadata {\n    readonly namespace: string;") ||
		!strings.Contains(text, `readonly namespace: "member.other.example"`) ||
		strings.Contains(text, "readonly project:") {
		t.Fatalf("declarations =\n%s", declarations)
	}
}

func TestStagedWriteRestoresPreviousFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "project.d.ts")
	if err := os.WriteFile(path, []byte("previous\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	write, err := stageWrite(path, []byte("replacement\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer write.cleanup()
	if err := write.commit(); err != nil {
		t.Fatal(err)
	}
	if err := write.restore(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "previous\n" {
		t.Fatalf("restored file = %q", data)
	}
}
