package projectmeta

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRenderProducesSortedLiteralPublicShape(t *testing.T) {
	metadata := Metadata{
		Version: Version, MemberNamespace: "busy-toast.tnl.dev",
		Services: map[string]Service{
			"web": {
				MemberNamespace: "busy-toast.tnl.dev", Hostname: "web-tnl-bb4eff.busy-toast.tnl.dev",
				URL: "https://web-tnl-bb4eff.busy-toast.tnl.dev",
			},
			"api": {
				MemberNamespace: "busy-toast.tnl.dev", Hostname: "api-tnl-bb4eff.busy-toast.tnl.dev",
				URL: "https://api-tnl-bb4eff.busy-toast.tnl.dev",
			},
		},
		ServiceDirectories: map[string]string{"web": "apps/web", "api": "apps/api"},
	}
	jsonData, declarations, err := Render(metadata)
	if err != nil {
		t.Fatal(err)
	}
	text := string(declarations)
	if strings.Index(text, `readonly "api"`) > strings.Index(text, `readonly "web"`) ||
		!strings.Contains(text, "interface TnlProjectMetadata") ||
		!strings.Contains(text, `readonly memberNamespace: "busy-toast.tnl.dev"`) ||
		!strings.Contains(text, `readonly hostname: "api-tnl-bb4eff.busy-toast.tnl.dev"`) ||
		!strings.Contains(text, `readonly url: "https://api-tnl-bb4eff.busy-toast.tnl.dev"`) ||
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
	if bytes.Count(jsonData, []byte(`"memberNamespace": "busy-toast.tnl.dev"`)) != 3 {
		t.Fatalf("JSON does not expose the project and service member namespaces:\n%s", jsonData)
	}
	public := metadata.Public(true)
	if !public.RunningUnderTnlDev || public.Services["api"].MemberNamespace != "busy-toast.tnl.dev" {
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

func TestWriteAtomicallyReplacesGeneratedFiles(t *testing.T) {
	root := t.TempDir()
	metadata := Metadata{
		Version: Version, MemberNamespace: "busy-toast.tnl.dev",
		Services: map[string]Service{
			"api": {
				MemberNamespace: "busy-toast.tnl.dev", Hostname: "api.busy-toast.tnl.dev",
				URL: "https://api.busy-toast.tnl.dev",
			},
		},
		ServiceDirectories: map[string]string{"api": "."},
	}
	if err := Write(root, metadata); err != nil {
		t.Fatal(err)
	}
	jsonPath := filepath.Join(root, DirectoryName, JSONName)
	before, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	invalid := metadata
	invalid.MemberNamespace = "INVALID"
	if err := Write(root, invalid); err == nil {
		t.Fatal("invalid metadata was written")
	}
	after, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("failed write changed existing metadata")
	}
}

func TestRenderRejectsOversizedMetadata(t *testing.T) {
	metadata := Metadata{
		Version: Version, MemberNamespace: "member.example",
		Services: map[string]Service{
			"api": {
				MemberNamespace: "member.example", Hostname: "api.member.example", URL: "https://api.member.example",
			},
		},
		ServiceDirectories: map[string]string{"api": strings.Repeat("a", MaxFileBytes)},
	}
	if _, _, err := Render(metadata); err == nil || !strings.Contains(err.Error(), "exceeds 65536 bytes") {
		t.Fatalf("oversized metadata error = %v", err)
	}
}

func TestRenderBroadensMemberNamespaceWhenServicesDiffer(t *testing.T) {
	metadata := Metadata{
		Version: Version, MemberNamespace: "member.example",
		Services: map[string]Service{
			"api": {
				MemberNamespace: "member.other.example", Hostname: "api.member.other.example",
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
		!strings.Contains(text, "  interface TnlProjectMetadata {\n    readonly memberNamespace: string;") ||
		!strings.Contains(text, `readonly memberNamespace: "member.other.example"`) ||
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
