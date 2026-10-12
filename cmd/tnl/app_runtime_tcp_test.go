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

	"github.com/tnldotdev/tnl/internal/clientruntime"
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
