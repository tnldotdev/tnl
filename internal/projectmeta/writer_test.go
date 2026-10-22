package projectmeta

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestRuntimeWriterOwnsOnlyJSON(t *testing.T) {
	root := t.TempDir()
	m := Metadata{Version: Version, Services: map[string]Service{}}
	if err := Write(t.Context(), root, m); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, DirectoryName, JSONName)
	before, _ := os.ReadFile(path)
	info, _ := os.Stat(path)
	if err := Write(t.Context(), root, m); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if info.ModTime() != after.ModTime() {
		t.Fatal("identical write changed file")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 2 {
		t.Fatalf("runtime writer created unexpected files: %v", entries)
	}
	m.Namespace = "INVALID"
	if err := Write(t.Context(), root, m); err == nil {
		t.Fatal("accepted invalid metadata")
	}
	data, _ := os.ReadFile(path)
	if !bytes.Equal(before, data) {
		t.Fatal("invalid write changed runtime JSON")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(Write(ctx, root, m), context.Canceled) {
		t.Fatal("lost cancellation")
	}
}

func TestRuntimeWriterRejectsOversizedMetadataAndInvalidRoots(t *testing.T) {
	root := t.TempDir()
	metadata := Metadata{Version: Version, Services: map[string]Service{}}
	for _, invalid := range []string{"", ".", "relative", filepath.Join(root, "missing")} {
		if err := Write(t.Context(), invalid, metadata); err == nil {
			t.Fatal("accepted invalid root", invalid)
		}
	}
	metadata.Namespace = "member.example"
	for _, name := range []string{"api", "web", "worker", "admin", "app", "console", "preview", "other"} {
		service, err := NewService(metadata.Namespace, name+".member.example", "http", nil)
		if err != nil {
			t.Fatal(err)
		}
		service.Paths = map[string]Path{}
		for index := range 32 {
			prefix := "/" + strings.Repeat("x", 230) + string(rune('a'+index/26)) + string(rune('a'+index%26))
			target := "api"
			if name == "api" {
				target = "web"
			}
			service.Paths[prefix] = Path{Service: target, URL: service.URL + prefix}
		}
		metadata.Services[name] = service
	}
	if _, err := Render(metadata); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatal("accepted oversized runtime metadata", err)
	}
}

func TestRuntimeWriterRejectsUnsafePaths(t *testing.T) {
	for _, name := range []string{".tnl", DirectoryName, DirectoryName + "/project.json", DirectoryName + "/project.lock"} {
		t.Run(name, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(outside, path); err != nil {
				t.Fatal(err)
			}
			if err := Write(t.Context(), root, Metadata{Version: Version, Services: map[string]Service{}}); err == nil {
				t.Fatal("accepted symlink")
			}
			entries, _ := os.ReadDir(outside)
			if len(entries) != 0 {
				t.Fatal("wrote through symlink")
			}
		})
	}
}

func TestPortableDeclarationsNeverUseRuntimeValues(t *testing.T) {
	protocol := "postgres"
	configuration := config.TNL{Services: config.Services{"database": {Protocol: &protocol}}}
	for _, root := range []string{"/checkout/one", "/another/checkout"} {
		data, err := Declarations(configuration, root+"/tnl.config.ts", root+"/.tnl/generated")
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `typeof import("../../tnl.config.js").default`) || strings.Contains(string(data), root) || strings.Contains(string(data), "postgres") {
			t.Fatalf("snapshot declarations: %s", data)
		}
	}
	data, err := Declarations(configuration, "/project/tnl.yml", "/project/.tnl/generated")
	if err != nil || !strings.Contains(string(data), `"database"`) || !strings.Contains(string(data), `"postgres"`) {
		t.Fatalf("static declarations: %s %v", data, err)
	}
}
