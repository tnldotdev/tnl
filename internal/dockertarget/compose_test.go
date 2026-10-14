package dockertarget

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposePortUsesExplicitWorktreeCoordinates(t *testing.T) {
	root := t.TempDir()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "compose.yaml"), []byte("services: {}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	command := filepath.Join(bin, "docker")
	if err := os.WriteFile(command, []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$COMPOSE_ARGS\"\nprintf '%s\\n' \"$COMPOSE_BINDING\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	args := filepath.Join(root, "args")
	t.Setenv("COMPOSE_ARGS", args)
	t.Setenv("COMPOSE_BINDING", "0.0.0.0:49152")
	address, err := ComposePort(t.Context(), root, "compose.yaml", "my_worktree", "db", 5432)
	if err != nil || address != "127.0.0.1:49152" {
		t.Fatalf("binding = %q, %v", address, err)
	}
	data, err := os.ReadFile(args)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	want := "compose\n--project-directory\n" + canonical + "\n--file\n" + filepath.Join(canonical, "compose.yaml") + "\n--project-name\nmy_worktree\nport\n--protocol\ntcp\ndb\n5432\n"
	if string(data) != want {
		t.Fatalf("docker arguments = %q, want %q", data, want)
	}
	for _, invalid := range []string{"", "192.0.2.2:3456", "0.0.0.0:12\n0.0.0.0:13", strings.Repeat("x", 257)} {
		t.Setenv("COMPOSE_BINDING", invalid)
		if _, err := ComposePort(context.Background(), root, "compose.yaml", "my_worktree", "db", 5432); err == nil {
			t.Fatalf("accepted binding %q", invalid)
		}
	}
	if err := os.Symlink(filepath.Join(bin, "docker"), filepath.Join(root, "outside.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, err := ComposePort(t.Context(), root, "outside.yaml", "my_worktree", "db", 5432); err == nil {
		t.Fatal("accepted Compose file outside worktree")
	}
}
