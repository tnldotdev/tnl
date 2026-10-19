package projectmeta

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/filelock"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestRenderProducesSortedLiteralPublicShape(t *testing.T) {
	metadata := Metadata{
		Version: Version, Namespace: "ecstatic-penguin.tnl.dev",
		Worktree: &Worktree{Label: projectconfig.WorktreeLabel{Project: "tnl", ID: "bb4eff", FullLabel: "tnl-bb4eff"}},
		Services: map[string]Service{
			"web": {
				Protocol:  "http",
				Namespace: "ecstatic-penguin.tnl.dev", Hostname: "web-tnl-bb4eff.ecstatic-penguin.tnl.dev",
				URL: "https://web-tnl-bb4eff.ecstatic-penguin.tnl.dev",
			},
			"api": {
				Protocol:  "http",
				Namespace: "ecstatic-penguin.tnl.dev", Hostname: "api-tnl-bb4eff.ecstatic-penguin.tnl.dev",
				URL: "https://api-tnl-bb4eff.ecstatic-penguin.tnl.dev",
			},
		},
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
		strings.Contains(text, "readonly root:") || strings.Contains(text, "readonly checkout:") {
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

func TestRenderWorktreeLabelLiteralComponents(t *testing.T) {
	metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{},
		Worktree: &Worktree{Label: projectconfig.WorktreeLabel{Project: "shop", Checkout: "perf", ID: "k7n2p9", FullLabel: "shop-perf-k7n2p9"}}}
	_, declarations, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	for _, literal := range []string{`readonly project: "shop"`, `readonly checkout: "perf"`, `readonly id: "k7n2p9"`, `readonly fullLabel: "shop-perf-k7n2p9"`} {
		if !bytes.Contains(declarations, []byte(literal)) {
			t.Fatalf("declaration missing %s", literal)
		}
	}
	metadata.Worktree.Label.FullLabel = "different-k7n2p9"
	if _, _, err := Render(metadata); err == nil {
		t.Fatal("inconsistent label components were written")
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

func TestRenderIncludesMountedServicePathsWithoutLocalTargets(t *testing.T) {
	metadata := Metadata{
		Version: Version, Namespace: "member.example.test",
		Services: map[string]Service{
			"web": {Protocol: "http", Namespace: "member.example.test", Hostname: "web.member.example.test", URL: "https://web.member.example.test",
				Paths: map[string]Path{"/api": {Service: "api", URL: "https://web.member.example.test/api", StripPrefix: true}}},
			"api": {Protocol: "http", Namespace: "member.example.test", Hostname: "api.member.example.test", URL: "https://api.member.example.test"},
		},
	}
	jsonData, declarations, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(jsonData, []byte(`"stripPrefix": true`)) ||
		!bytes.Contains(declarations, []byte(`readonly "/api": { readonly service: "api"; readonly url: "https://web.member.example.test/api"; readonly stripPrefix: true; };`)) ||
		bytes.Contains(jsonData, []byte("127.0.0.1")) {
		t.Fatalf("mount metadata = %s\n%s", jsonData, declarations)
	}
	invalid := metadata
	web := metadata.Services["web"]
	web.Paths = map[string]Path{"/api": {Service: "Invalid", URL: web.URL + "/api", StripPrefix: true}}
	invalid.Services = map[string]Service{"web": web}
	if err := invalid.Validate(); err == nil {
		t.Fatal("an invalid mounted service name was accepted")
	}
}

func TestWriteRejectsInvalidMetadataWithoutChangingFiles(t *testing.T) {
	root := t.TempDir()
	metadata := Metadata{
		Version: Version, Namespace: "ecstatic-penguin.tnl.dev",
		Services: map[string]Service{
			"api": {
				Protocol:  "http",
				Namespace: "ecstatic-penguin.tnl.dev", Hostname: "api.ecstatic-penguin.tnl.dev",
				URL: "https://api.ecstatic-penguin.tnl.dev",
			},
		},
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
	metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{}}
	if err := Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	metadata.Services["api"] = Service{Protocol: "http", Namespace: "member.example", Hostname: "api.member.example", URL: "https://api.member.example"}
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

func TestWriteKeepsAllOutputLocal(t *testing.T) {
	root := t.TempDir()
	metadata := Metadata{Version: Version, Services: map[string]Service{}}
	if err := Write(t.Context(), root, metadata); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(root, ".tnl"))
	if err != nil || len(entries) != 1 || entries[0].Name() != "local" {
		t.Fatalf("parent entries = %v, %v", entries, err)
	}
	local := filepath.Join(root, ".tnl", "local")
	entries, err = os.ReadDir(local)
	if err != nil || len(entries) != 3 {
		t.Fatalf("local entries = %v, %v", entries, err)
	}
	for _, name := range []string{JSONName, DeclarationsName, "project.lock"} {
		if info, err := os.Lstat(filepath.Join(local, name)); err != nil || !info.Mode().IsRegular() {
			t.Fatalf("local %s = %v, %v", name, info, err)
		}
	}
	write, err := stageWrite(filepath.Join(local, JSONName), []byte("changed\n"))
	if err != nil {
		t.Fatal(err)
	}
	defer write.cleanup()
	if filepath.Dir(write.temporary) != local || !strings.HasPrefix(filepath.Base(write.temporary), ".project-") {
		t.Fatalf("temporary file escaped local: %s", write.temporary)
	}
}

func TestWriteRejectsUnsafeParentChildAndOutput(t *testing.T) {
	for _, path := range []string{".tnl", ".tnl/local", ".tnl/local/project.json", ".tnl/local/project.d.ts", ".tnl/local/project.lock"} {
		t.Run(path, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			link := filepath.Join(root, path)
			if err := os.MkdirAll(filepath.Dir(link), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, link); err != nil {
				t.Fatal(err)
			}
			if err := Write(t.Context(), root, Metadata{Version: Version, Services: map[string]Service{}}); err == nil {
				t.Fatal("accepted symlink")
			}
			if entries, err := os.ReadDir(outside); err != nil || len(entries) != 0 {
				t.Fatalf("wrote outside project: %v, %v", entries, err)
			}
		})
	}
	for _, path := range []string{".tnl", ".tnl/local"} {
		t.Run("file/"+path, func(t *testing.T) {
			root := t.TempDir()
			file := filepath.Join(root, path)
			if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(file, []byte("preserve"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := Write(t.Context(), root, Metadata{Version: Version, Services: map[string]Service{}}); err == nil {
				t.Fatal("accepted non-directory")
			}
			if data, err := os.ReadFile(file); err != nil || string(data) != "preserve" {
				t.Fatalf("changed existing file: %q, %v", data, err)
			}
		})
	}
}

func TestWriteRequiresExistingAbsoluteProjectRoot(t *testing.T) {
	root := t.TempDir()
	for _, invalid := range []string{"", ".", "relative", filepath.Join(root, "missing")} {
		if err := Write(t.Context(), invalid, Metadata{Version: Version, Services: map[string]Service{}}); err == nil {
			t.Fatalf("accepted root %q", invalid)
		}
	}
	if entries, err := os.ReadDir(root); err != nil || len(entries) != 0 {
		t.Fatalf("created missing root: %v, %v", entries, err)
	}
}

func TestWriteLockWaitHonorsCancellation(t *testing.T) {
	root := t.TempDir()
	directory := filepath.Join(root, DirectoryName)
	if err := prepareDirectory(filepath.Dir(directory)); err != nil {
		t.Fatal(err)
	}
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
		Services: map[string]Service{},
	}
	if err := Write(ctx, root, metadata); !errors.Is(err, context.Canceled) {
		t.Fatalf("write = %v", err)
	}
}

func TestRenderRejectsOversizedMetadata(t *testing.T) {
	metadata := Metadata{Version: Version, Namespace: "member.example", Services: map[string]Service{}}
	for index := range 8 {
		name := fmt.Sprintf("app%d", index)
		url := "https://" + name + ".member.example"
		service := Service{Protocol: "http", Namespace: "member.example", Hostname: name + ".member.example", URL: url, Paths: map[string]Path{}}
		for pathIndex := range 32 {
			prefix := fmt.Sprintf("/p%d-%s", pathIndex, strings.Repeat("x", 230))
			service.Paths[prefix] = Path{Service: "app0", URL: url + prefix}
			if index == 0 {
				service.Paths[prefix] = Path{Service: "app1", URL: url + prefix}
			}
		}
		metadata.Services[name] = service
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
				Protocol:  "http",
				Namespace: "member.other.example", Hostname: "api.member.other.example",
				URL: "https://api.member.other.example",
			},
		},
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
