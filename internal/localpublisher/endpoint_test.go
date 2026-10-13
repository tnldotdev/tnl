package localpublisher

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientruntime"
	"github.com/tnldotdev/tnl/internal/config"
)

func TestLocalPublisherTCPRequiresCredentialOnPrivateOperations(t *testing.T) {
	key := filepath.Join(t.TempDir(), "publisher")
	handler := http.NewServeMux()
	handler.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server, _, err := startRuntimeTCP(key, handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stopRuntimeTCP(context.Background(), server, key); err != nil {
			t.Error(err)
		}
	})
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil || endpoint.Credential == "" || !strings.HasPrefix(endpoint.URL, "http://127.0.0.1:") {
		t.Fatalf("invalid loopback endpoint: %+v, %v", endpoint, err)
	}
	info, err := os.Stat(runtimeTCPEndpointPath(key))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("endpoint descriptor mode = %v, %v", info, err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, test := range []struct {
		path, token, origin string
		status              int
	}{
		{path: "/v1/health", status: http.StatusNoContent},
		{path: "/v1/status", status: http.StatusUnauthorized},
		{path: "/v1/status", token: "wrong", status: http.StatusUnauthorized},
		{path: "/v1/status", token: endpoint.Credential, origin: "https://other.example", status: http.StatusUnauthorized},
		{path: "/v1/status", token: endpoint.Credential, status: http.StatusNoContent},
	} {
		request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, endpoint.URL+test.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		if test.token != "" {
			request.Header.Set("Authorization", "Bearer "+test.token)
		}
		if test.origin != "" {
			request.Header.Set("Origin", test.origin)
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
			t.Fatalf("GET %s with credential=%t and origin=%t: status %d, want %d", test.path, test.token != "", test.origin != "", response.StatusCode, test.status)
		}
	}
}

func TestLocalPublisherRemovesEveryScopedCredentialOnShutdown(t *testing.T) {
	key := filepath.Join(t.TempDir(), "publisher")
	handler := http.NewServeMux()
	handler.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server, _, err := startRuntimeTCP(key, handler, clientruntime.Service{Name: "web"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	endpoint, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint.URL+"/v1/scopes/app/new", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "Bearer "+endpoint.Credential)
	response, err := (&http.Client{Timeout: time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		t.Fatalf("new scoped credential status = %d", response.StatusCode)
	}
	for _, path := range []string{runtimeTCPEndpointPath(key), runtimeAdHocEndpointPath(key), runtimeAppEndpointPath(key, "web"), runtimeAppEndpointPath(key, "new")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
	if err := stopRuntimeTCP(context.Background(), server, key); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{runtimeTCPEndpointPath(key), runtimeAdHocEndpointPath(key), runtimeAppEndpointPath(key, "web"), runtimeAppEndpointPath(key, "new")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("stale credential descriptor %s: %v", path, err)
		}
	}
}

func TestContainerAppEndpointUsesOnlyTheScopedCredentialAndPrivateComposeOrigin(t *testing.T) {
	port := 3781
	publisher := config.ProjectPublisher{Type: "docker", DockerSelection: config.DockerSelection{
		Compose: &config.ComposeSelection{File: "compose.yaml", Project: "shop-k7n2p9", Service: "publisher"}, ContainerPort: &port,
	}}
	owner, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	app, err := publisherCredential()
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := containerAppEndpoint(publisher, localPublisherEndpoint{Version: 1, URL: "http://127.0.0.1:49153", Credential: app})
	if err != nil || endpoint.URL != "http://publisher:3781" || endpoint.Credential != app || endpoint.Credential == owner {
		t.Fatalf("exported Compose app endpoint = %+v, %v", endpoint, err)
	}
	publisher.Compose = nil
	if _, err := containerAppEndpoint(publisher, endpoint); err == nil {
		t.Fatal("allowed an app endpoint without a Compose publisher service")
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

func TestComposePublisherWritesOnlyServiceCredentialsToSeparateVolumes(t *testing.T) {
	state := filepath.Join(t.TempDir(), "state")
	key, err := runtimeKey("/project", state)
	if err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(t.TempDir(), "app-volumes")
	if err := os.Mkdir(appDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{"web", "api"} {
		if err := os.Mkdir(filepath.Join(appDir, service), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("TNL_PUBLISHER_APP_ENDPOINT_DIR", appDir)
	port := 3781
	publisher := &config.ProjectPublisher{Type: "docker", DockerSelection: config.DockerSelection{
		Compose: &config.ComposeSelection{File: "compose.yaml", Project: "shop-k7n2p9", Service: "publisher"}, ContainerPort: &port,
	}}
	server, _, err := startRuntimeTCPWithProjectOptions(key, http.NewServeMux(), "127.0.0.1:0", "", publisher,
		clientruntime.Service{Name: "web"}, clientruntime.Service{Name: "api"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = stopRuntimeTCP(context.Background(), server, key) })
	owner, err := readRuntimeTCPEndpoint(key)
	if err != nil {
		t.Fatal(err)
	}
	credentials := map[string]string{}
	for _, service := range []string{"web", "api"} {
		path := runtimeAppEndpointPath(key, service)
		if path != filepath.Join(appDir, service, "publisher.endpoint.json") {
			t.Fatalf("app endpoint outside its volume: %s", path)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var app localPublisherEndpoint
		err = json.Unmarshal(data, &app)
		if err != nil || app.URL != "http://publisher:3781" || app.Credential == owner.Credential {
			t.Fatalf("app scope %q was not isolated: %v", service, err)
		}
		credentials[service] = app.Credential
	}
	if credentials["web"] == credentials["api"] {
		t.Fatal("sibling apps shared the same publisher credential")
	}
	if entries, err := os.ReadDir(appDir); err != nil || len(entries) != 2 {
		t.Fatalf("app credential mounts = %d, %v", len(entries), err)
	}
}

func TestLocalPublisherPartialStartupRemovesDescriptorsAndReleasesListener(t *testing.T) {
	key := filepath.Join(t.TempDir(), "publisher")
	blocked := runtimeAppEndpointPath(key, "web")
	if err := os.Mkdir(blocked, 0700); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	server, done, err := startRuntimeTCPWithOptions(key, http.NewServeMux(), address, "", clientruntime.Service{Name: "web"})
	if err == nil || server != nil || done != nil {
		t.Fatalf("partial startup = %v, %v, %v", server, done, err)
	}
	for _, path := range []string{runtimeAdHocEndpointPath(key), runtimeTCPEndpointPath(key)} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("partial startup left descriptor %s: %v", path, err)
		}
	}
	if info, err := os.Stat(blocked); err != nil || !info.IsDir() {
		t.Fatalf("startup removed the conflicting path: %v", err)
	}
	rebound, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("partial startup retained its listener: %v", err)
	}
	if err := rebound.Close(); err != nil {
		t.Fatal(err)
	}
}
