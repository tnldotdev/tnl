package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	projectconfig "github.com/tnldotdev/tnl/internal/client/project"
	projectmeta "github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/config"
	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	workloadclient "github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func connectionBackendFixture(t *testing.T, handle func(http.ResponseWriter, *http.Request, authorityv1.WorkloadSession)) *nativeConnectionBackend {
	t.Helper()
	id := "wls_" + strings.Repeat("s", 22)
	team := "tm_" + strings.Repeat("t", 22)
	ids := []string{"psvc_" + strings.Repeat("a", 22), "psvc_" + strings.Repeat("b", 22)}
	now := time.Now()
	session := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: team, ProjectKey: "project", Workload: "worker", Provider: controlv1.WorkloadVercel, Binding: strings.Repeat("a", 64), Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, ServiceIds: ids, ExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(90 * time.Second), RenewAfter: now.Add(30 * time.Second)}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/workload-sessions/exchange":
			_ = json.NewEncoder(w).Encode(session)
		default:
			handle(w, r, session)
		}
	}))
	t.Cleanup(server.Close)
	client, err := workloadclient.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), team, "project", strings.Repeat("a", 64), "worker", "assertion", []string{"api", "db"}); err != nil {
		t.Fatal(err)
	}
	b := &nativeConnectionBackend{scope: connectionruntime.Context{Services: []string{"api", "db"}}, nativeConnectionSession: nativeConnectionSession{workload: client, deadline: session.ExpiresAt}, prepared: map[string]*preparedConnection{}, services: map[string]controlv1.PrivateService{}, metadata: projectmeta.PublicMetadata{Services: map[string]projectmeta.Service{}}, project: projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: config.Services{"api": {Protocol: new("http")}, "db": {Protocol: new("postgres")}}}}}}
	for i, name := range []string{"api", "db"} {
		protocol := []controlv1.PrivateServiceProtocol{"http", "postgres"}[i]
		b.services[name] = controlv1.PrivateService{Id: ids[i], Protocol: protocol, Enabled: true, ManagedTls: &controlv1.ManagedServiceTLS{Hostname: name + ".example.test", Port: 15443 + i}}
	}
	b.prepared["api"] = &preparedConnection{service: b.services["api"], ready: true, sessionID: id, connection: connectionruntime.Connection{Schema: 1, Protocol: "http", Host: "127.0.0.1", Port: 15443}}
	return b
}

func TestConnectionBackendPreparedReadSurvivesStalledSibling(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, session authorityv1.WorkloadSession) {
		if strings.HasSuffix(r.URL.Path, "/authorization") {
			_, _ = io.Copy(io.Discard, r.Body)
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
			}
			w.WriteHeader(503)
			return
		}
		w.WriteHeader(204)
	})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := b.Connect(ctx, "db"); done <- err }()
	<-entered
	read := make(chan error, 1)
	go func() { _, err := b.Prepared("api"); read <- err }()
	select {
	case err := <-read:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second):
		t.Error("prepared HTTP service blocked behind stalled database authorization")
		defer func() { <-read }()
	}
	close(release)
	<-done
}

func TestConnectionApprovedMetadataRefreshRetainsExactServiceScope(t *testing.T) {
	var endpoint controlv1.ManagedServiceTLS
	var replacementID string
	b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, session authorityv1.WorkloadSession) {
		if r.URL.Path != "/v1/workload/services" {
			t.Error("unexpected metadata work", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		id := session.ServiceIds[0]
		if replacementID != "" {
			id = replacementID
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": id, "service": "api", "protocol": "http", "managed_tls": endpoint}}})
	})
	approved := b.services["api"]
	endpoint = *approved.ManagedTls
	endpoint.Hostname, endpoint.Port = "updated.example.test", 25443
	fresh, err := b.refreshService(t.Context(), "api", approved, b.workload)
	if err != nil || fresh.Id != approved.Id || fresh.ManagedTls.Hostname != endpoint.Hostname || b.PublicRuntime().Services["api"].Hostname != endpoint.Hostname {
		t.Fatal("approved endpoint stayed stale", err)
	}
	if _, err := b.Prepared("api"); !errors.Is(err, connectionruntime.ErrUnprepared) {
		t.Fatal("new metadata was paired with an old transport", err)
	}
	replacementID = "psvc_" + strings.Repeat("c", 22)
	if _, err := b.refreshService(t.Context(), "api", fresh, b.workload); err == nil {
		t.Fatal("metadata refresh broadened the session's service IDs")
	}
}

func TestConnectionCleanupRevokesSessionWhileFailedReleasesUseOneBudget(t *testing.T) {
	entered, revoked := make(chan struct{}), make(chan struct{})
	var once sync.Once
	b := connectionBackendFixture(t, func(w http.ResponseWriter, r *http.Request, session authorityv1.WorkloadSession) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.URL.Path == "/v1/workload-sessions/"+session.Id {
			close(revoked)
			w.WriteHeader(204)
			return
		}
		once.Do(func() { close(entered) })
		<-r.Context().Done()
	})
	b.lifetime, b.cancel = context.WithCancel(t.Context())
	for range 3 {
		b.workers.Go(func() {
			<-b.lifetime.Done()
			// use the production workload HTTP release, including a second failed
			// release that must inherit the same exhausted caller budget.
			for _, id := range []string{"pcs_" + strings.Repeat("a", 22), "pcs_" + strings.Repeat("b", 22)} {
				err := b.workload.ReleaseIngressAssignment(b.cleanup(), id)
				b.mu.Lock()
				b.cleanupErr = errors.Join(b.cleanupErr, err)
				b.mu.Unlock()
			}
		})
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- b.Close(ctx) }()
	for _, barrier := range []<-chan struct{}{entered, revoked} {
		select {
		case <-barrier:
		case <-time.After(time.Second):
			cancel()
			<-done
			t.Fatal("release cleanup blocked session revocation")
		}
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal("incomplete cleanup was reported clean", err)
		}
	case <-time.After(time.Second):
		t.Fatal("failed releases outlived the shared cleanup budget")
	}
	b.workers.Wait()
}

func TestConnectionCloseHonorsCallerBudget(t *testing.T) {
	b := &nativeConnectionBackend{}
	blocked := make(chan struct{})
	b.workers.Go(func() { <-blocked })
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	done := make(chan error, 1)
	go func() { done <- b.Close(ctx) }()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Error("cleanup did not report incomplete join", err)
		}
	case <-time.After(time.Second):
		t.Error("Close ignored its caller budget")
	}
	close(blocked)
}
