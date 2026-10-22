package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	publishergroup "github.com/tnldotdev/tnl/internal/publisher/group"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestInstalledGroupRecoveryChecksControlPlansAgainstEntireOlderSnapshot(t *testing.T) {
	job, _, key := kindFixture(t, KindGroup)
	planA := controlv1.CertificatePlan{CacheKey: "old.example", Scope: "old.example", Identifiers: []string{"old.example"}, ChallengeMethod: controlv1.Dns01}
	planB := controlv1.CertificatePlan{CacheKey: "current.example", Scope: "current.example", Identifiers: []string{"current.example"}, ChallengeMethod: controlv1.Dns01}
	assignments := controlv1.PublisherGroupAssignments{Member: *job.GroupMember, CertificateStatePlans: []controlv1.CertificatePlan{planA, planB}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/publisher-groups/lease":
			_ = json.NewEncoder(w).Encode(controlv1.PublisherGroupLease{AccessToken: "fixture", ExpiresAt: time.Now().Add(time.Minute)})
		case "/v1/publisher-groups/assignments":
			_ = json.NewEncoder(w).Encode(assignments)
		default:
			t.Error("unexpected recovery request", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	job.Server = server.URL
	registry := testRegistry(t)
	profile, err := registry.Profile(t.Context(), job.Server)
	if err != nil {
		t.Fatal(err)
	}
	client, err := publishergroup.NewClient(job.Server, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	cacheA, err := profile.CertificatesForPublisher(job.GroupMember.TeamId, job.PublisherIdentityID, planA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cacheA.Pending(t.Context(), "old.example"); err != nil {
		t.Fatal(err)
	}
	// the entire restored local snapshot predates B, including its local index.
	served := false
	serve := func(context.Context) error { served = true; return nil }
	err = WithCertificateState(t.Context(), job, profile, key, client, serve)
	if !errors.Is(err, clientstate.ErrPublisherStateConflict) || served {
		t.Fatal("old complete snapshot hid a newer control plan", err)
	}
	if typed, ok := failure.Of(err); !ok || typed.Reason() != failure.PublisherCertificateStateMissing {
		t.Fatal("lost recovery diagnostic", err)
	}
	cacheB, err := profile.CertificatesForPublisher(job.GroupMember.TeamId, job.PublisherIdentityID, planB)
	if err != nil {
		t.Fatal(err)
	}
	// explicit restoration supplies the exact missing plan; setup itself never
	// calls Pending or creates a replacement key while checking recovery.
	if _, err := cacheB.Pending(t.Context(), "current.example"); err != nil {
		t.Fatal(err)
	}
	if err := WithCertificateState(t.Context(), job, profile, key, client, serve); err != nil || !served {
		t.Fatal("complete restore was not usable", err)
	}
	served = false
	assignments.CertificateStatePlans = nil
	if err := WithCertificateState(t.Context(), job, profile, key, client, serve); err == nil || served {
		t.Fatal("missing required plan inventory was accepted")
	}
}
