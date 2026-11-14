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

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/meta"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func connectionBackendFixture(t *testing.T, handle func(http.ResponseWriter, *http.Request, authorityv1.WorkloadSession)) *connectorConnectionBackend {
	t.Helper()
	id := "wls_" + strings.Repeat("s", 22)
	team := "tm_" + strings.Repeat("t", 22)
	ids := []string{"svc_" + strings.Repeat("a", 22), "svc_" + strings.Repeat("b", 22)}
	now := time.Now()
	session := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: team, ProjectKey: "project", Workload: "worker", Provider: controlv1.WorkloadVercel, Binding: strings.Repeat("a", 64), Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, ServiceIds: ids, ExpiresAt: new(now.Add(time.Hour)), LeaseExpiresAt: now.Add(90 * time.Second), RenewAfter: now.Add(30 * time.Second)}
	session.IdentityExpiresAt = now.Add(2 * time.Hour)
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
	client, err := workload.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), team, "project", strings.Repeat("a", 64), "worker", "assertion", []string{"api", "db"}); err != nil {
		t.Fatal(err)
	}
	b := &connectorConnectionBackend{scope: connectorruntime.Context{Services: []string{"api", "db"}}, connectorConnectionSession: connectorConnectionSession{workload: client, deadline: workload.SessionDeadline(session)}, listeners: map[string]*ownedServiceListener{}, services: map[string]controlv1.Service{}, metadata: meta.PublicMetadata{Services: map[string]meta.Service{}}, project: projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"api": {Protocol: new("http")}, "db": {Protocol: new("postgres")}}}}}}
	for i, name := range []string{"api", "db"} {
		protocol := []controlv1.ServiceProtocol{"http", "postgres"}[i]
		port := []int{443, 15444}[i]
		b.services[name] = controlv1.Service{Id: ids[i], Protocol: protocol, Enabled: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: name + ".example.test", Port: port}}
	}
	b.listeners["api"] = &ownedServiceListener{attempt: &servicePreparation{service: b.services["api"], state: &servingService{sessionID: id, connection: connectorruntime.Connection{Schema: 1, Protocol: "http", Host: "127.0.0.1", Port: 15443, TransportID: "ctg_aaaaaaaaaaaaaaaaaaaaaa"}}}}
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
	var endpoint controlv1.ServiceEndpoint
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
		_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": id, "service": "api", "protocol": "http", "endpoint": endpoint}}})
	})
	approved := b.services["api"]
	b.metadata.Services["api"], _ = meta.NewEndpoint("example.test", approved.Endpoint.Hostname, "http", approved.Endpoint.Port, false)
	b.listeners["api"].attempt.state.(*servingService).connection.URL = "https://api.example.test"
	previous, err := b.Snapshot("api")
	if err != nil || previous.Validate() != nil {
		t.Fatal("fixture has no valid prepared transport", err)
	}
	endpoint = *approved.Endpoint
	endpoint.Hostname, endpoint.Port = "updated.example.test", 443
	fresh, err := b.refreshService(t.Context(), "api", approved, b.workload)
	if err != nil || fresh.Id != approved.Id || fresh.Endpoint.Hostname != endpoint.Hostname || b.ProjectRuntime().Services["api"].Hostname != endpoint.Hostname {
		t.Fatal("approved endpoint stayed stale", err)
	}
	if _, err := b.Prepared("api"); !errors.Is(err, connectorruntime.ErrUnprepared) {
		t.Fatal("new metadata was paired with an old transport", err)
	}
	// recovery publishes the new transport and approved metadata together, while
	// callers retaining an earlier snapshot keep its original metadata and ID.
	current := b.listeners["api"].attempt.state.(*servingService)
	session, err := b.workload.Session()
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.listeners["api"].attempt = &servicePreparation{service: fresh, state: &servingService{sessionID: session.Id, connection: connectorruntime.Connection{Schema: 1, Protocol: "http", Host: "127.0.0.1", Port: current.connection.Port, URL: "https://updated.example.test", TransportID: "ctg_bbbbbbbbbbbbbbbbbbbbbb"}}}
	b.publishLocked()
	b.mu.Unlock()
	recovered, err := b.Snapshot("api")
	if err != nil || recovered.Validate() != nil || recovered.Connection.Port != previous.Connection.Port || recovered.Connection.TransportID == previous.Connection.TransportID || recovered.ProjectRuntime.Services["api"].Hostname != endpoint.Hostname || recovered.Connection.SSL.ServerName != endpoint.Hostname || recovered.Connection.URL != "https://updated.example.test" || recovered.ProjectRuntime.Services["api"].URL != "https://updated.example.test" {
		t.Fatal("recovery did not pair current metadata and transport identity", err)
	}
	if previous.Connection.TransportID != "ctg_aaaaaaaaaaaaaaaaaaaaaa" || previous.ProjectRuntime.Services["api"].Hostname != approved.Endpoint.Hostname || previous.Connection.SSL.ServerName != approved.Endpoint.Hostname {
		t.Fatal("recovery changed a previously returned snapshot")
	}
	replacementID = "svc_" + strings.Repeat("c", 22)
	if _, err := b.refreshService(t.Context(), "api", fresh, b.workload); err == nil {
		t.Fatal("metadata refresh broadened the session's service IDs")
	}
}

func TestConnectionCleanupRevokesSessionWhileFailedRequestsUseOneBudget(t *testing.T) {
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
			// connector owners have no ingress handles to release. an in-flight
			// workload operation and its retry still share the cleanup budget.
			for range 2 {
				_, err := b.workload.CheckService(b.cleanup(), b.services["api"].Id)
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
	b := &connectorConnectionBackend{}
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
