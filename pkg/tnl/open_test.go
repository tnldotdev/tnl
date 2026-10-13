package tnl

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

func TestOpenUsesLocalPublisherAndRetainsInvocationThroughClose(t *testing.T) {
	credential := strings.Repeat("A", 43)
	var mu sync.Mutex
	var registered privateprotocol.AdHocRegister
	statusReads, unregistered := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			http.Error(w, "local publisher credential required", http.StatusUnauthorized)
			return
		}
		write := func(value any) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(value)
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/status":
			write(map[string]any{"version": 1})
		case "POST /v1/ad-hoc/register":
			mu.Lock()
			defer mu.Unlock()
			if err := json.NewDecoder(r.Body).Decode(&registered); err != nil {
				t.Error(err)
			}
			write(privateprotocol.AdHocStatus{Version: 1, RegistrationID: registered.RegistrationID, State: privateprotocol.AdHocStarting})
		case "POST /v1/ad-hoc/status":
			mu.Lock()
			defer mu.Unlock()
			statusReads++
			status := privateprotocol.AdHocStatus{Version: 1, RegistrationID: registered.RegistrationID,
				State: privateprotocol.AdHocPublishing}
			if statusReads > 1 {
				status.State, status.PublicURLID = privateprotocol.AdHocRoutable, "url_allocated"
				status.PublicURL = "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test"
				status.PublishRunNumber = 1
			}
			write(status)
		case "POST /v1/ad-hoc/renew":
			w.WriteHeader(http.StatusNoContent)
		case "POST /v1/ad-hoc/unregister":
			mu.Lock()
			unregistered++
			mu.Unlock()
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Errorf("unexpected local publisher request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "ad-hoc.endpoint.json")
	descriptor, err := json.Marshal(map[string]any{"version": 1, "url": server.URL, "credential": credential})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, descriptor, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), Options{PublisherEndpointFile: path, Limits: Limits{HTTP: WorkLimits{Total: 1}}})
	if err != nil || tunnel.URL() != "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test" {
		t.Fatalf("ad-hoc URL = %v, %v", tunnel, err)
	}
	mu.Lock()
	target, id, owner, requests := registered.Target, registered.RegistrationID, registered.Owner, statusReads
	mu.Unlock()
	if requests < 2 || !strings.HasPrefix(id, "ivk_") || owner == "" || !strings.HasPrefix(target, "http://127.0.0.1:") {
		t.Fatalf("native registration = %+v, status reads = %d", registered, requests)
	}
	response, err := (&http.Client{Timeout: time.Second}).Get(target)
	if err != nil || response.StatusCode != http.StatusNoContent {
		t.Fatalf("local listener = %v, %v", response, err)
	}
	response.Body.Close()
	cancel()
	if err := tunnel.Wait(); err != nil && err != context.Canceled {
		t.Fatal(err)
	}
	mu.Lock()
	removed := unregistered
	mu.Unlock()
	if removed != 1 {
		t.Fatalf("local publication unregistrations = %d, want one", removed)
	}
}
