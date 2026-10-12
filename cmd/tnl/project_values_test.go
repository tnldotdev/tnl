package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestProjectLabelReadsWorktreeWithoutEvaluatingConfig(t *testing.T) {
	root := t.TempDir()
	state := filepath.Join(t.TempDir(), "state")
	marker := filepath.Join(root, "evaluated")
	source := `import { writeFileSync } from "node:fs";
writeFileSync("evaluated", "yes");
export default {};`
	if err := os.WriteFile(filepath.Join(root, "tnl.config.ts"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(root)
	var stdout, stderr bytes.Buffer
	if err := run(t.Context(), []string{"project", "label", "--state-dir", state, "--output", "raw"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	label := strings.TrimSuffix(stdout.String(), "\n")
	if label == "" || stdout.String() != label+"\n" || stderr.Len() != 0 {
		t.Fatalf("raw label = %q; stderr = %q", stdout.String(), stderr.String())
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("project config was evaluated: %v", err)
	}
	stdout.Reset()
	if err := run(t.Context(), []string{"project", "label", "--state-dir", state, "--output", "json"}, &stdout, &stderr); err != nil {
		t.Fatal(err)
	}
	var result struct {
		SchemaVersion int    `json:"schema_version"`
		Label         string `json:"label"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.SchemaVersion != 1 || result.Label != label {
		t.Fatalf("JSON label = %q: %+v, %v", stdout.String(), result, err)
	}
	stdout.Reset()
	if err := run(t.Context(), []string{"project", "label", "--state-dir", state}, &stdout, &stderr); err != nil || !strings.Contains(stdout.String(), "tnl project label") || !strings.Contains(stdout.String(), label) {
		t.Fatalf("human label = %q, %v", stdout.String(), err)
	}
}

func TestSavedURLShowValueModesNeverExposePrivateTarget(t *testing.T) {
	port := 15432
	saved := controlv1.PublicURL{
		Id: "url_0123456789abcdefghijkl", CanonicalHostname: "orders.member.example",
		ServiceProtocol: controlv1.Postgres, PublicPort: &port, Target: "db.internal:5432",
		LifecycleState: controlv1.Enabled, PublicUrlScope: controlv1.Member,
	}
	address := "orders.member.example:15432"
	for _, mode := range []scalarOutputMode{scalarOutputHuman, scalarOutputJSON, scalarOutputRaw} {
		var output bytes.Buffer
		if err := writeURLShow(mode, saved, address, &output); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(output.String(), saved.Target) {
			t.Fatalf("%s showed private target: %s", mode, output.String())
		}
		switch mode {
		case scalarOutputRaw:
			if output.String() != address+"\n" {
				t.Fatalf("raw address = %q", output.String())
			}
		case scalarOutputJSON:
			var result struct {
				PublicURL     string `json:"public_url"`
				SchemaVersion int    `json:"schema_version"`
			}
			if err := json.Unmarshal(output.Bytes(), &result); err != nil || result.PublicURL != address || result.SchemaVersion != 1 {
				t.Fatalf("JSON address = %q, %+v, %v", output.String(), result, err)
			}
		case scalarOutputHuman:
			if !strings.Contains(output.String(), "tnl url show") || !strings.Contains(output.String(), address) {
				t.Fatalf("human address = %q", output.String())
			}
		}
	}
}
