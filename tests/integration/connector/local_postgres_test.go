package connector_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/testutil"
)

func installSDKNativePackage(t *testing.T, root, binary string) {
	t.Helper()
	manifest, err := os.ReadFile("../../../packages/ts/package.json")
	if err != nil {
		t.Fatal(err)
	}
	var sdk struct{ Version string }
	if err := json.Unmarshal(manifest, &sdk); err != nil {
		t.Fatal(err)
	}
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	packageName := fmt.Sprintf("tnl-%s-%s", runtime.GOOS, arch)
	packageDir := filepath.Join(root, "node_modules", "@tnldotdev", packageName)
	if err := os.MkdirAll(filepath.Join(packageDir, "bin"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(packageDir, "package.json"), []byte(fmt.Sprintf(`{"name":"@tnldotdev/%s","version":%q}`, packageName, sdk.Version)), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(binary, filepath.Join(packageDir, "bin", "tnl")); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresLocalDeployment(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *connectionCLIBinary == "" {
		t.Fatal("the connections Task must supply -tnl-cli-binary")
	}
	database, err := url.Parse(testutil.NewDisposablePostgresDatabaseURL(t, "local_sdk"))
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	installSDKNativePackage(t, root, *connectionCLIBinary)
	configuration, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{
		"services":    map[string]any{"db": map[string]any{"protocol": "postgres"}},
		"deployments": map[string]any{"local": map[string]any{"targets": map[string]any{"db": map[string]any{"address": database.Host}}}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), configuration, 0600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(root, "absent-client-state")
	var environment []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "TNL_") && !strings.HasPrefix(value, "OTEL_") {
			environment = append(environment, value)
		}
	}
	environment = append(environment, "TNL_STATE_DIR="+state, "TNL_SERVER=https://unreachable.invalid", "NODE_PATH="+filepath.Join(root, "node_modules"))
	generate := exec.CommandContext(t.Context(), *connectionCLIBinary, "generate")
	generate.Dir, generate.Env = root, environment
	if output, err := generate.CombinedOutput(); err != nil {
		t.Fatalf("generate offline service facts: %v\n%s", err, output)
	}
	native := exec.CommandContext(t.Context(), *connectionCLIBinary, "runtime", "connections", "local", "--directory", root, "--service", "db", "--protocol", "postgres")
	native.Dir, native.Env = root, environment
	if output, err := native.CombinedOutput(); err != nil {
		t.Fatalf("resolve local database settings: %v\n%s", err, output)
	}
	fixture, err := filepath.Abs("../../../packages/ts/test/fixtures/local-deployment.ts")
	if err != nil {
		t.Fatal(err)
	}
	password, _ := database.User.Password()
	input, err := json.Marshal(map[string]string{"directory": root, "user": database.User.Username(), "password": password, "database": strings.TrimPrefix(database.Path, "/")})
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "node", fixture)
	command.Env, command.Stdin = environment, bytes.NewReader(input)
	if output, err := command.CombinedOutput(); err != nil || string(output) != "local PostgreSQL query passed\n" {
		t.Fatalf("local deployment SDK: %v\n%s", err, output)
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Fatal("local SDK opened client state", err)
	}
}
