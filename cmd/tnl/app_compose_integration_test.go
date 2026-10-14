package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

var composeFixture = flag.String("tnl-compose-fixture", "", "compose app integration fixture role")

// the same test binary runs in the disposable Compose publisher and app
// containers so the test exercises the actual scoped TCP implementation.
func TestComposeFixture(t *testing.T) {
	if *composeFixture == "" {
		t.Skip("requires -tnl-compose-fixture")
	}
	if *composeFixture == "publisher" {
		handler := http.NewServeMux()
		handler.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
		handler.HandleFunc("POST /v1/prepare", func(w http.ResponseWriter, r *http.Request) {
			if localPublisherService(r.Context()) == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		})
		server, _, err := startRuntimeTCPCompose("/state/publisher", handler, "0.0.0.0:8765", "publisher",
			map[string]string{"web": "/run/web/app.web.endpoint.json", "api": "/run/api/app.api.endpoint.json"}, "web", "api")
		if err != nil {
			t.Fatal(err)
		}
		defer server.Close()
		select {} // docker compose owns the lifetime of this publisher process.
	}
	service := *composeFixture
	if service != "web" && service != "api" {
		t.Fatal("unknown app fixture")
	}
	for _, path := range []string{"/state/publisher.endpoint.json", "/run/" + map[string]string{"web": "api", "api": "web"}[service]} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("app can see an owner or sibling volume at %s: %v", path, err)
		}
	}
	data, err := os.ReadFile("/run/" + service + "/app." + service + ".endpoint.json")
	if err != nil {
		t.Fatal(err)
	}
	var endpoint localPublisherEndpoint
	if err := json.Unmarshal(data, &endpoint); err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{DisableKeepAlives: true, Proxy: nil}}
	for _, check := range []struct {
		method, path string
		status       int
	}{
		{http.MethodGet, "/v1/status", http.StatusOK},
		{http.MethodPost, "/v1/prepare", http.StatusNoContent},
		{http.MethodGet, "/v1/events", http.StatusUnauthorized},
		{http.MethodPost, "/v1/ad-hoc/register", http.StatusUnauthorized},
	} {
		request, err := http.NewRequestWithContext(t.Context(), check.method, endpoint.URL+check.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != check.status {
			t.Fatalf("%s %s: got %d, want %d", check.method, check.path, response.StatusCode, check.status)
		}
	}
}

func TestIntegrationComposeAppEndpoints(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	root := t.TempDir()
	for _, name := range []string{"state", "web", "api"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	binary := filepath.Join(root, "tnl.test")
	build := exec.CommandContext(t.Context(), "go", "test", "-c", "-o", binary, ".")
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build Linux test binary: %v\n%s", err, output)
	}
	image := "mirror.gcr.io/library/golang:1.27.2-bookworm@sha256:5cf287a799e6b94384bad13d16b14904c531f51ba65792237e122ce42b392f61"
	user := fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid())
	type service struct {
		Image   string   `json:"image"`
		User    string   `json:"user"`
		Command []string `json:"command"`
		Volumes []string `json:"volumes"`
	}
	volume := func(name string) string { return filepath.Join(root, name) + ":/run/" + name }
	base := service{Image: image, User: user, Volumes: []string{binary + ":/test/tnl.test:ro"}}
	publisher := base
	publisher.Command = []string{"/test/tnl.test", "-test.run=^TestComposeFixture$", "-tnl-compose-fixture=publisher"}
	publisher.Volumes = append(append([]string{}, base.Volumes...), filepath.Join(root, "state")+":/state", volume("web"), volume("api"))
	services := map[string]service{"publisher": publisher}
	for _, name := range []string{"web", "api"} {
		app := base
		app.Command = []string{"sleep", "3600"}
		app.Volumes = append(append([]string{}, base.Volumes...), volume(name)+":ro")
		services[name] = app
	}
	composeFile := filepath.Join(root, "compose.json")
	data, err := json.Marshal(map[string]any{"services": services})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(composeFile, data, 0600); err != nil {
		t.Fatal(err)
	}
	project := fmt.Sprintf("tnlcompose%d", time.Now().UnixNano())
	compose := func(ctx context.Context, args ...string) ([]byte, error) {
		command := exec.CommandContext(ctx, "docker", append([]string{"compose", "-p", project, "-f", composeFile}, args...)...)
		return command.CombinedOutput()
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if output, err := compose(ctx, "down", "-v", "--remove-orphans"); err != nil {
			t.Errorf("remove disposable Compose project: %v\n%s", err, output)
		}
	})
	if output, err := compose(t.Context(), "up", "-d", "publisher", "web", "api"); err != nil {
		t.Fatalf("start disposable Compose project: %v\n%s", err, output)
	}
	read := func(name string) localPublisherEndpoint {
		t.Helper()
		path := filepath.Join(root, name, "app."+name+".endpoint.json")
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(path)
			var endpoint localPublisherEndpoint
			if err == nil && json.Unmarshal(data, &endpoint) == nil && endpoint.Credential != "" {
				return endpoint
			}
			time.Sleep(100 * time.Millisecond)
		}
		if output, err := compose(t.Context(), "logs", "publisher"); err == nil {
			t.Logf("publisher logs:\n%s", output)
		}
		t.Fatalf("Compose app %s did not receive an endpoint", name)
		return localPublisherEndpoint{}
	}
	first := read("web")
	for _, name := range []string{"web", "api"} {
		if output, err := compose(t.Context(), "exec", "-T", name, "/test/tnl.test", "-test.run=^TestComposeFixture$", "-tnl-compose-fixture="+name); err != nil {
			t.Fatalf("app %s could not use its scoped endpoint: %v\n%s", name, err, output)
		}
	}
	if output, err := compose(t.Context(), "restart", "publisher"); err != nil {
		t.Fatalf("replace publisher: %v\n%s", err, output)
	}
	deadline := time.Now().Add(30 * time.Second)
	var second localPublisherEndpoint
	for time.Now().Before(deadline) {
		second = read("web")
		if second.Credential != first.Credential {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if second.Credential == first.Credential {
		t.Fatal("publisher replacement reused the old app credential")
	}
	if output, err := compose(t.Context(), "exec", "-T", "web", "/test/tnl.test", "-test.run=^TestComposeFixture$", "-tnl-compose-fixture=web"); err != nil {
		t.Fatalf("app did not recover after publisher replacement: %v\n%s", err, output)
	}
}
