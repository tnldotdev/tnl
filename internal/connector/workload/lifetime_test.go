package workload

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestMaintainRetainsExistingExpiryAndCancellation(t *testing.T) {
	for _, canceled := range []bool{false, true} {
		s := sessionFixture(controlv1.WorkloadOIDC)
		s.LeaseExpiresAt = time.Now().Add(20 * time.Millisecond)
		client := &Client{session: s}
		ctx, cancel := context.WithCancelCause(t.Context())
		if canceled {
			cancel(context.Canceled)
		}
		err := client.Maintain(ctx)
		cancel(context.Canceled)
		want := ErrSessionExpired
		if canceled {
			want = context.Canceled
		}
		if !errors.Is(err, want) {
			t.Fatalf("maintain = %v, want %v", err, want)
		}
	}
}

func TestMaintainUsesSharedClientRenewal(t *testing.T) {
	original := sessionFixture(controlv1.WorkloadOIDC)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		s := cloneSession(original)
		if r.URL.Path != "/v1/workload-sessions/exchange" {
			s.RenewalSequence = 1
		}
		_ = json.NewEncoder(w).Encode(s)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), original.TeamId, original.ProjectKey, "source", original.Workload, "assertion", nil); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- client.Maintain(ctx) }()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		s, err := client.Session()
		if err != nil {
			t.Fatal(err)
		}
		if s.RenewalSequence == 1 {
			break
		}
		select {
		case <-ctx.Done():
			t.Fatal("shared renewal was not installed")
		case <-ticker.C:
		}
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
