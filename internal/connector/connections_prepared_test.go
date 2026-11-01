package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectionPreparedOnlyAndVerifiedWarmWorkBudget(t *testing.T) {
	now := time.Now()
	id, team := "wls_"+strings.Repeat("s", 22), "tm_"+strings.Repeat("t", 22)
	ids := []string{"svc_" + strings.Repeat("a", 22), "svc_" + strings.Repeat("b", 22), "svc_" + strings.Repeat("c", 22), "svc_" + strings.Repeat("d", 22)}
	names := []string{"db", "sibling", "invalid", "mismatch"}
	session := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: team, ProjectKey: "project", Workload: "worker", Provider: controlv1.WorkloadVercel, Binding: strings.Repeat("a", 64), Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, ServiceIds: ids, ExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(90 * time.Second), RenewAfter: now.Add(30 * time.Second)}
	var mu sync.Mutex
	calls := map[string]int{}
	var public []byte
	expired := false
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls[r.URL.Path]++
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/workload-sessions/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.WorkloadIdentity{Binding: session.Binding, Services: names, AssertionExpiresAt: now.Add(time.Minute)})
		case "/v1/workload-sessions/exchange":
			var input authorityv1.WorkloadExchange
			_ = json.NewDecoder(r.Body).Decode(&input)
			public, _ = base64.RawURLEncoding.DecodeString(input.PublicKey)
			_ = json.NewEncoder(w).Encode(session)
		case "/v1/workload/services":
			services := []any{}
			for i, name := range names {
				hostname, protocol := name+".example.test", "postgres"
				if name == "invalid" {
					hostname = "INVALID.EXAMPLE.TEST"
				}
				if name == "mismatch" {
					protocol = "http"
				}
				services = append(services, map[string]any{"id": ids[i], "service": name, "protocol": protocol, "endpoint": map[string]any{"hostname": hostname, "port": 15443 + i, "public": false}})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"services": services})
		case "/v1/workload/services/" + ids[0] + "/authorization":
			_ = json.NewEncoder(w).Encode(controlv1.WorkloadServiceAuthorization{Subject: session.Subject, ServiceId: ids[0], ValidUntil: session.LeaseExpiresAt, PolicyRevision: 1})
		case "/v1/workload-sessions/" + id + "/assertions":
			var input authorityv1.WorkloadAssertion
			_ = json.NewDecoder(r.Body).Decode(&input)
			signature, _ := base64.RawURLEncoding.DecodeString(input.Signature)
			digest := sha256.Sum256([]byte(input.Assertion))
			if !ed25519.Verify(public, workloadproof.Attach(id, digest), signature) {
				t.Error("attachment lost its key proof")
				w.WriteHeader(403)
				return
			}
			if expired && input.Assertion == "first" || input.Assertion != "first" && input.Assertion != "rotated" {
				w.WriteHeader(403)
				_, _ = w.Write([]byte(`{"status":403,"code":"forbidden","detail":"assertion denied"}`))
				return
			}
			next := session
			next.AssertionExpiresAt = new(now.Add(time.Minute))
			_ = json.NewEncoder(w).Encode(next)
		case "/v1/workload-sessions/" + id:
			w.WriteHeader(204)
		default:
			t.Error("unexpected provider, listener or control work", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	configuration := config.TNL{Services: config.Services{}, Workloads: map[string]config.Workload{"worker": {Provider: "vercel", Services: names}}}
	for _, name := range names {
		configuration.Services[name] = config.Service{Protocol: new("postgres")}
	}
	type processKey struct{}
	setup, cancel := context.WithCancel(context.WithValue(t.Context(), processKey{}, "process-observation"))
	b := &connectorConnectionBackend{scope: connectorruntime.Context{Schema: 1, Server: server.URL, TeamID: team, ProjectKey: "project", SourceID: strings.Repeat("a", 64), Workload: "worker", Services: names}, assertion: "first", httpClient: server.Client(), parentPID: os.Getpid(), project: projectConfiguration{Project: clientproject.Project{Config: configuration}}}
	defer b.Close(t.Context())
	if _, _, err := b.Start(setup); err != nil {
		t.Fatal(err)
	}
	cancel()
	if b.lifetime.Value(processKey{}) != "process-observation" || b.lifetime.Err() != nil {
		t.Fatal("native lifetime dropped process observations or inherited setup cancellation")
	}
	for _, name := range []string{"invalid", "mismatch"} {
		if _, ok := b.services[name]; ok {
			t.Error("invalid inventory remained selectable", name)
		}
		if _, err := b.Connect(t.Context(), name); err == nil {
			t.Error("invalid inventory was accepted", name)
		}
	}
	b.prepared["db"] = &preparedConnection{service: b.services["db"], ready: true, sessionID: id, connection: connectorruntime.Connection{Schema: 1, Protocol: "postgres", Host: "127.0.0.1", Port: 15443, TransportID: "ctg_aaaaaaaaaaaaaaaaaaaaaa"}}
	if _, err := b.Connect(t.Context(), "db"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	cold := 0
	for _, n := range calls {
		cold += n
	}
	mu.Unlock()
	for range 10 {
		if err := b.UseAssertion(t.Context(), "first"); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Connect(t.Context(), "db"); err != nil {
			t.Fatal(err)
		}
		if _, err := b.Prepared("sibling"); !errors.Is(err, connectorruntime.ErrUnprepared) {
			t.Fatal("sync sibling read performed preparation", err)
		}
	}
	mu.Lock()
	warm := 0
	for _, n := range calls {
		warm += n
	}
	mu.Unlock()
	if cold != 5 || warm != cold {
		t.Fatalf("control budget cold=%d warm_delta=%d, want 5/0", cold, warm-cold)
	}
	if len(b.prepared) != 1 {
		t.Fatal("unrequested sibling opened a listener")
	}
	b.prepared["db"].sessionID = "wls_" + strings.Repeat("o", 22)
	b.publishLocked()
	if _, err := b.Prepared("db"); !errors.Is(err, connectorruntime.ErrUnprepared) {
		t.Fatal("old-session adapter inherited a replacement session deadline", err)
	}
	b.prepared["db"].sessionID = id
	b.publishLocked()
	if err := b.UseAssertion(t.Context(), "rotated"); err != nil {
		t.Fatal(err)
	}
	if err := b.UseAssertion(t.Context(), "first"); err != nil {
		t.Fatal("verified exact assertion was not reusable", err)
	}
	mu.Lock()
	count := calls["/v1/workload-sessions/"+id+"/assertions"]
	expired = true
	mu.Unlock()
	if count != 1 {
		t.Fatal("rotation should attach once", count)
	}
	for key, proof := range b.assertions {
		if proof.Digest != b.verification.Digest {
			continue
		}
		proof.ExpiresAt = now.Add(-time.Second)
		b.assertions[key] = proof
	}
	if err := b.UseAssertion(t.Context(), "first"); err == nil {
		t.Fatal("expired verification cache bypassed current authority denial")
	}
	if err := b.UseAssertion(t.Context(), "rotated"); err != nil {
		t.Fatal("one denied assertion poisoned another verified assertion", err)
	}
	t.Logf("native control calls: cold=%d warm(10 requests)=%d; unprepared sibling work=0", cold, warm-cold)
}
