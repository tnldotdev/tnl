package main

import (
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLocalPublisherTCPRequiresCredentialOnPrivateOperations(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "publisher.sock")
	handler := http.NewServeMux()
	handler.HandleFunc("GET /v1/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	handler.HandleFunc("GET /v1/status", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	server, _, err := startRuntimeTCP(socket, handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := stopRuntimeTCP(context.Background(), server, socket); err != nil {
			t.Error(err)
		}
	})
	endpoint, err := readRuntimeTCPEndpoint(socket)
	if err != nil || endpoint.Credential == "" || !strings.HasPrefix(endpoint.URL, "http://127.0.0.1:") {
		t.Fatalf("invalid loopback endpoint: %+v, %v", endpoint, err)
	}
	info, err := os.Stat(runtimeTCPEndpointPath(socket))
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
