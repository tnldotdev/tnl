package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
)

func TestComposeObservationsUseSelectedOwnerWithoutExportingItsCredential(t *testing.T) {
	bin := t.TempDir()
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\"\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	root := t.TempDir()
	project := projectConfiguration{Project: projectconfig.Project{Root: root,
		Worktree: projectconfig.Worktree{Label: projectconfig.WorktreeLabel{FullLabel: "shop-feature-12345678"}},
		Config:   config.TNL{Publisher: &config.AppPublisher{Type: "compose", Service: "publisher", ProjectRoot: "/workspace", Port: 8765}},
	}}
	var output bytes.Buffer
	if err := composeOwnerCommand(t.Context(), project, &output, composeWaitArgs(waitCommand{Service: []string{"web"}, Timeout: 1200000000, Output: "json"})...); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, part := range []string{"--project-directory\n" + root + "\n", "--project-name\nshop-feature-12345678\n", "-T\n", "TNL_PUBLISHER_INTERNAL=1\n", "--workdir\n/workspace\n", "publisher\ntnl\nwait\n--output\njson\n--timeout\n1.2s\n--service\nweb\n"} {
		if !strings.Contains(text, part) {
			t.Fatalf("Compose observation omitted %q: %s", part, text)
		}
	}
	if strings.Contains(text, "credential") || strings.Contains(text, "token") {
		t.Fatalf("Compose command carried a credential: %s", text)
	}
}
