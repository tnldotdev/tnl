package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalPublisherTCPRequiresCredentialOnPrivateOperations(t *testing.T) {
	key := filepath.Join(t.TempDir(), "publisher")
	handler := http.NewServeMux()
	handler.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler.HandleFunc("POST /v1/prepare", func(w http.ResponseWriter, r *http.Request) {
		if localPublisherService(r.Context()) != "api" {
			t.Error("app credential did not carry its service scope")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler.HandleFunc("POST /v1/ad-hoc/register", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler.HandleFunc("POST /v1/observe", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server, _, err := startRuntimeTCP(key, handler, "api")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil || endpoint.Credential == "" || !strings.HasPrefix(endpoint.URL, "http://127.0.0.1:") {
		t.Fatalf("invalid loopback endpoint: %+v, %v", endpoint, err)
	}
	info, err := os.Stat(runtimeTCPEndpointPath(key))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("endpoint descriptor mode = %v, %v", info, err)
	}
	data, err := os.ReadFile(runtimeAppTCPEndpointPath(key, "api"))
	if err != nil {
		t.Fatal(err)
	}
	var app localPublisherEndpoint
	if err := json.Unmarshal(data, &app); err != nil || app.Credential == "" || app.Credential == endpoint.Credential || app.URL != endpoint.URL {
		t.Fatalf("invalid scoped descriptor: %+v, %v", app, err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, test := range []struct {
		method, path, token, origin, host string
		status                            int
	}{
		{path: "/v1/health", status: http.StatusNoContent},
		{path: "/v1/health", host: "evil.example", status: http.StatusUnauthorized},
		{path: "/v1/status", status: http.StatusUnauthorized},
		{path: "/v1/status", token: "wrong", status: http.StatusUnauthorized},
		{path: "/v1/status", token: endpoint.Credential, origin: "https://other.example", status: http.StatusUnauthorized},
		{path: "/v1/status", token: endpoint.Credential, status: http.StatusNoContent},
		{path: "/v1/status", token: app.Credential, status: http.StatusNoContent},
		{method: http.MethodPost, path: "/v1/prepare", token: endpoint.Credential, status: http.StatusUnauthorized},
		{method: http.MethodPost, path: "/v1/prepare", token: app.Credential, status: http.StatusNoContent},
		{method: http.MethodPost, path: "/v1/ad-hoc/register", token: app.Credential, status: http.StatusUnauthorized},
		{method: http.MethodPost, path: "/v1/ad-hoc/register", token: endpoint.Credential, status: http.StatusNoContent},
		{method: http.MethodPost, path: "/v1/observe", token: app.Credential, status: http.StatusUnauthorized},
		{method: http.MethodPost, path: "/v1/observe", token: endpoint.Credential, status: http.StatusNoContent},
		{method: http.MethodPost, path: "/v1/register", token: endpoint.Credential, status: http.StatusUnauthorized},
	} {
		method := test.method
		if method == "" {
			method = http.MethodGet
		}
		request, err := http.NewRequestWithContext(t.Context(), method, endpoint.URL+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.token != "" {
			request.Header.Set("Authorization", "Bearer "+test.token)
		}
		if test.origin != "" {
			request.Header.Set("Origin", test.origin)
		}
		if test.host != "" {
			request.Host = test.host
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil {
			t.Fatalf("read local publisher response: %v, close: %v", readErr, closeErr)
		}
		if response.StatusCode != test.status {
			t.Fatalf("%s %s with credential=%t and origin=%t: status %d, want %d", method, test.path, test.token != "", test.origin != "", response.StatusCode, test.status)
		}
	}
	if err := stopRuntimeTCP(context.Background(), server, key, "api"); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{runtimeTCPEndpointPath(key), runtimeAppTCPEndpointPath(key, "api")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("endpoint %s survived shutdown: %v", path, err)
		}
	}
}

func TestLocalPublisherIssuesLiveAppCredentialWithoutGrantingOwnerAccess(t *testing.T) {
	key := filepath.Join(t.TempDir(), "publisher")
	server, _, err := startRuntimeTCP(key, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/prepare" && localPublisherService(r.Context()) == "web" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}), "api")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	owner, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	request := func(method, route, token string) int {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), method, owner.URL+route, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer "+token)
		response, err := (&http.Client{Timeout: time.Second, Transport: &http.Transport{DisableKeepAlives: true}}).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if status := request(http.MethodPost, "/v1/scopes/app/web", owner.Credential); status != http.StatusNoContent {
		t.Fatalf("issue web credential: %d", status)
	}
	data, err := os.ReadFile(runtimeAppTCPEndpointPath(key, "web"))
	if err != nil {
		t.Fatal(err)
	}
	var web localPublisherEndpoint
	if err := json.Unmarshal(data, &web); err != nil || web.Credential == owner.Credential {
		t.Fatalf("web credential: %+v, %v", web, err)
	}
	if status := request(http.MethodPost, "/v1/prepare", web.Credential); status != http.StatusNoContent {
		t.Fatalf("web prepare: %d", status)
	}
	if status := request(http.MethodPost, "/v1/scopes/app/api", web.Credential); status != http.StatusUnauthorized {
		t.Fatalf("web issued another credential: %d", status)
	}
	if status := request(http.MethodGet, "/v1/status", web.Credential); status != http.StatusForbidden {
		t.Fatalf("web status handler: %d", status)
	}
	if status := request(http.MethodPost, "/v1/scopes/app/web", owner.Credential); status != http.StatusNoContent {
		t.Fatalf("reissue web credential: %d", status)
	}
	data, err = os.ReadFile(runtimeAppTCPEndpointPath(key, "web"))
	var again localPublisherEndpoint
	if err != nil || json.Unmarshal(data, &again) != nil || again.Credential != web.Credential {
		t.Fatalf("credential changed while owner was running: %+v, %v", again, err)
	}
	if err := stopRuntimeTCP(context.Background(), server, key, "api", "web"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(runtimeAppTCPEndpointPath(key, "web")); !os.IsNotExist(err) {
		t.Fatalf("web descriptor survived owner shutdown: %v", err)
	}
}

func TestLocalPublisherRuntimeKeyUsesPrivateClientState(t *testing.T) {
	state := filepath.Join(t.TempDir(), "client-state")
	key, err := runtimeKey("/project", state)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(state)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(key) != filepath.Join(canonical, "run") {
		t.Fatalf("runtime key = %q, want state run directory", key)
	}
	if info, err := os.Lstat(filepath.Dir(key)); err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Fatalf("run directory = %v, %v", info, err)
	}
	if err := os.Remove(filepath.Dir(key)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(t.TempDir(), filepath.Dir(key)); err != nil {
		t.Fatal(err)
	}
	if _, err := runtimeKey("/project", state); err == nil {
		t.Fatal("accepted a symlink as the private runtime directory")
	}
}

func TestComposePublisherKeepsOwnerAndAppDescriptorsApart(t *testing.T) {
	ownerState := t.TempDir()
	appVolume := t.TempDir()
	key := filepath.Join(ownerState, "publisher")
	appPath := filepath.Join(appVolume, "app.web.endpoint.json")
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/status" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	server, _, err := startRuntimeTCPCompose(key, handler, "0.0.0.0:0", "publisher", map[string]string{"web": appPath}, "web")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	owner, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(appPath)
	if err != nil {
		t.Fatal(err)
	}
	var app localPublisherEndpoint
	if err := json.Unmarshal(data, &app); err != nil || app.Credential == owner.Credential ||
		!strings.HasPrefix(app.URL, "http://publisher:") || !strings.HasPrefix(owner.URL, "http://127.0.0.1:") {
		t.Fatalf("Compose endpoints = %+v, %+v, %v", owner, app, err)
	}
	if _, err := os.Stat(filepath.Join(appVolume, filepath.Base(runtimeTCPEndpointPath(key)))); !os.IsNotExist(err) {
		t.Fatalf("owner credential appeared in app volume: %v", err)
	}
	request := func(host, token string) int {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, owner.URL+"/v1/status", nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Host = host
		r.Header.Set("Authorization", "Bearer "+token)
		response, err := (&http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: time.Second}).Do(r)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		return response.StatusCode
	}
	if request(strings.TrimPrefix(app.URL, "http://"), app.Credential) != http.StatusOK ||
		request(strings.TrimPrefix(owner.URL, "http://"), app.Credential) != http.StatusUnauthorized ||
		request(strings.TrimPrefix(app.URL, "http://"), owner.Credential) != http.StatusUnauthorized {
		t.Fatal("Compose endpoint authorities crossed scopes")
	}
	if err := stopRuntimeTCP(t.Context(), server, key); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(appPath); !os.IsNotExist(err) {
		t.Fatalf("app descriptor survived replacement: %v", err)
	}
	replacement, _, err := startRuntimeTCPCompose(key, handler, "0.0.0.0:0", "publisher", map[string]string{"web": appPath}, "web")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	data, err = os.ReadFile(appPath)
	var newApp localPublisherEndpoint
	if err != nil || json.Unmarshal(data, &newApp) != nil || newApp.Credential == app.Credential {
		t.Fatalf("replacement app credential was reused: %+v, %v", newApp, err)
	}
	newOwner, err := readRuntimeTCPEndpoint(key)
	if err != nil || newOwner.Credential == owner.Credential {
		t.Fatalf("replacement owner credential was reused: %v", err)
	}
	if err := stopRuntimeTCP(t.Context(), replacement, key); err != nil {
		t.Fatal(err)
	}
}
