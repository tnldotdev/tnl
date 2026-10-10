package tnl

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestOpenWaitsForRoutabilityAndCleansUpOnCancellation(t *testing.T) {
	credential, _, _, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	var allocations, publishRuns, deletions, reads atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential.String() {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "POST /v1/ephemeral-public-urls":
			allocations.Add(1)
			var body controlv1.AllocateEphemeralPublicURLRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "invalid allocation", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(controlv1.PublicURL{Id: "url_allocated", TeamId: "team_1", DomainId: "domain_1",
				CanonicalHostname: "eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test", Target: body.Target,
				Ephemeral: true, Purpose: controlv1.App, LifecycleState: controlv1.Enabled,
				PublicUrlScope: controlv1.Shared, PolicyRevision: 1})
		case "POST /v1/public-urls/url_allocated/publish-runs":
			publishRuns.Add(1)
			<-r.Context().Done()
		case "DELETE /v1/ephemeral-public-urls/url_allocated":
			deletions.Add(1)
			w.WriteHeader(http.StatusNoContent)
		default:
			reads.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	state := t.TempDir()
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	tunnel, err := Open(ctx, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), Options{Credential: credential.String(), ServerURL: server.URL, HTTPClient: server.Client(), StateDir: state})
	if tunnel != nil || !errors.Is(err, context.DeadlineExceeded) || allocations.Load() != 1 || publishRuns.Load() < 1 ||
		deletions.Load() != 1 || reads.Load() != 0 {
		t.Fatalf("Open returned before ready or failed cleanup: tunnel=%v error=%v allocations=%d runs=%d deletes=%d unexpected=%d",
			tunnel, err, allocations.Load(), publishRuns.Load(), deletions.Load(), reads.Load())
	}
}
