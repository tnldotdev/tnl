package cli_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func TestIntegrationCLIHelpJSONOffline(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	dir := t.TempDir()
	config := filepath.Join(dir, "tnl.config.ts")
	if err := os.WriteFile(config, []byte(`throw new Error("help evaluated the project")`), 0600); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocked, nil, 0600); err != nil {
		t.Fatal(err)
	}
	const secret = "never-print-this-fixture-secret"
	offline := []string{
		"TNL_STATE_DIR=" + filepath.Join(blocked, "state"),
		"TNL_SERVER=https://127.0.0.1:1", "TNL_ACCESS_TOKEN=" + secret,
		"TNL_NO_TELEMETRY=false", "TNL_CONFIG=" + config,
	}
	read := func(extraEnv []string, args ...string) string {
		t.Helper()
		got := runBuiltCLI(t, dir, slices.Concat(offline, extraEnv), args...)
		if got.exit != 0 || got.stderr != "" || strings.Contains(got.stdout, secret) || strings.Contains(got.stdout, dir) {
			t.Fatalf("%v: %+v", args, got)
		}
		return got.stdout
	}

	indexText := read(nil, "help", "--output=json")
	publishText := read(nil, "help", "publish", "--output=json")
	for _, env := range [][]string{
		{"AI_AGENT=tool@1", "TNL_OUTPUT=human"},
		{"AI_AGENT= ", "COPILOT_GITHUB_TOKEN=" + secret, "TNL_OUTPUT=machine"},
	} {
		for _, audience := range []string{"human", "agent"} {
			if got := read(env, "help", "--audience", audience, "--output", "json"); got != indexText {
				t.Fatal("index changed with audience")
			}
			if got := read(env, "help", "publish", "--audience", audience, "--output", "json"); got != publishText {
				t.Fatal("reference changed with audience")
			}
		}
	}
	if got := read([]string{"TNL_OUTPUT=machine"}, "help", "publish"); got != publishText {
		t.Fatal("machine preference did not select JSON")
	}

	var index struct {
		SchemaVersion int    `json:"schema_version"`
		Kind          string `json:"kind"`
		Commands      []struct {
			Path    []string `json:"path"`
			Summary string   `json:"summary"`
		} `json:"commands"`
	}
	if err := json.Unmarshal([]byte(indexText), &index); err != nil || index.SchemaVersion != 1 || index.Kind != "index" {
		t.Fatalf("index: %v\n%s", err, indexText)
	}
	var paths []string
	for _, cmd := range index.Commands {
		path := strings.Join(cmd.Path, " ")
		if path == "" || cmd.Summary == "" || slices.Contains(paths, path) {
			t.Fatalf("bad index item: %+v", cmd)
		}
		paths = append(paths, path)
	}
	if !slices.IsSorted(paths) {
		t.Fatalf("unexpected command order: %v", paths)
	}
	for _, path := range []string{"help", "publish", "agent-guide", "connect start", "share service invite create", "completion zsh"} {
		if !slices.Contains(paths, path) {
			t.Errorf("index omitted %s", path)
		}
	}
	for _, hidden := range []string{"runtime", "runtime connections", "service serve", "connect kube-credential", "__complete"} {
		if slices.Contains(paths, hidden) {
			t.Errorf("index included hidden command %s", hidden)
		}
	}

	type input struct {
		Name       string   `json:"name"`
		Type       string   `json:"type"`
		Scope      string   `json:"scope"`
		Choices    []string `json:"choices"`
		Default    string   `json:"default"`
		AliasFor   string   `json:"alias_for"`
		Required   bool     `json:"required"`
		Repeatable bool     `json:"repeatable"`
	}
	type example struct {
		Argv []string `json:"argv"`
	}
	type result struct {
		Mode   string   `json:"mode"`
		Format string   `json:"format"`
		Stdout string   `json:"stdout"`
		Ends   string   `json:"ends"`
		Proves string   `json:"proves"`
		Fields []string `json:"fields"`
		Events []string `json:"events"`
	}
	type reference struct {
		SchemaVersion int       `json:"schema_version"`
		Kind          string    `json:"kind"`
		Path          []string  `json:"path"`
		Default       string    `json:"default_command"`
		ChildArgs     bool      `json:"child_args"`
		Arguments     []input   `json:"arguments"`
		Flags         []input   `json:"flags"`
		Examples      []example `json:"examples"`
		Results       []result  `json:"results"`
	}
	decode := func(text string, path ...string) reference {
		t.Helper()
		var ref reference
		if err := json.Unmarshal([]byte(text), &ref); err != nil || ref.SchemaVersion != 1 || ref.Kind != "command" || !slices.Equal(ref.Path, path) {
			t.Fatalf("reference: %v\n%s", err, text)
		}
		return ref
	}
	publish := decode(publishText, "publish")
	seen := make(map[string]input)
	for _, flag := range publish.Flags {
		seen[flag.Name] = flag
	}
	if seen["background"].AliasFor != "bg" || seen["config"].Scope != "inherited" || seen["config"].Type != "path" ||
		seen["output"].Default != "human" || !slices.Equal(seen["output"].Choices, []string{"human", "json", "ndjson"}) {
		t.Fatalf("publish flags: %+v", seen)
	}
	if len(publish.Examples) == 0 || !slices.Equal(publish.Examples[0].Argv, []string{"tnl", "publish", "3000"}) {
		t.Fatalf("publish examples: %+v", publish.Examples)
	}
	if !slices.ContainsFunc(publish.Results, func(r result) bool {
		return r.Mode == "background" && r.Format == "json" &&
			r.Stdout != "" && r.Ends != "" && r.Proves != "" &&
			slices.Contains(r.Fields, "url") && slices.Contains(r.Fields, "job_id")
	}) || !slices.ContainsFunc(publish.Results, func(r result) bool {
		return r.Format == "ndjson" && slices.Contains(r.Events, "ready")
	}) {
		t.Fatalf("publish results: %+v", publish.Results)
	}
	wait := decode(read(nil, "help", "wait", "--output=json"), "wait")
	if len(wait.Arguments) != 1 || wait.Arguments[0].Name != "service" || !wait.Arguments[0].Repeatable || wait.Arguments[0].Required {
		t.Fatalf("wait arguments: %+v", wait.Arguments)
	}
	connect := decode(read(nil, "help", "connect", "--output=json"), "connect")
	wantChildArgv := []string{"tnl", "connect", "orders", "--deployment", "staging", "--client", "psql", "--", "-At", "-c", "select 1"}
	if connect.Default != "start" || !connect.ChildArgs || len(connect.Arguments) != 1 || !connect.Arguments[0].Required ||
		!slices.ContainsFunc(connect.Examples, func(e example) bool { return slices.Equal(e.Argv, wantChildArgv) }) {
		t.Fatalf("connect shorthand reference: %+v", connect)
	}
	available := decode(read(nil, "help", "connect", "available", "--output=json"), "connect", "available")
	if available.ChildArgs || slices.ContainsFunc(available.Flags, func(f input) bool { return f.Name == "listen" }) {
		t.Fatalf("connect available inherited shorthand-only syntax: %+v", available)
	}
	if _, err := os.Stat(filepath.Join(dir, "unused-state")); !os.IsNotExist(err) {
		t.Fatalf("help touched client state: %v", err)
	}
}

func TestIntegrationCLIHelpJSONDoesNotExposeHiddenTopics(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	dir := t.TempDir()
	for _, topic := range []string{"runtime connections read", "connect kube-credential", "service serve", "share service invte"} {
		args := append([]string{"help", "--output=json"}, strings.Fields(topic)...)
		got := runBuiltCLI(t, dir, nil, args...)
		var problem struct {
			Type, Code string
		}
		if got.exit != 1 || got.stdout != "" || json.Unmarshal([]byte(got.stderr), &problem) != nil ||
			problem.Type != "error" || problem.Code != "TNL_CLIENT_INVALID_COMMAND" {
			t.Fatalf("%s: %+v", topic, got)
		}
		if strings.Contains(got.stderr, "runtime") || strings.Contains(got.stderr, "kube-credential") || strings.Contains(got.stderr, "service serve") {
			t.Fatalf("JSON help disclosed a hidden command: %+v", got)
		}
	}
	got := runBuiltCLI(t, dir, []string{"TNL_OUTPUT=machine"}, "help", "runtime", "connections", "read", "--output", "human")
	if got.exit != 0 || got.stderr != "" || !strings.Contains(got.stdout, "--handle") {
		t.Fatalf("exact hidden text help changed: %+v", got)
	}
}
