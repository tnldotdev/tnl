package connector

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// real TLS and HTTP proof bytes exercise the connector session boundary. provider
// verification itself is covered by the signed-issuer/PG integration target.
func TestConnectionReplacementRetainsLostExchangeKeyAndNarrowedScope(t *testing.T) {
	runConnectionReplacement(t, false)
}

func TestConnectionPendingReplacementIsRevokedAfterInventoryFailure(t *testing.T) {
	runConnectionReplacement(t, true)
}

func runConnectionReplacement(t *testing.T, pending bool) {
	t.Helper()
	const binding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	team, service := "tm_"+strings.Repeat("t", 22), "svc_"+strings.Repeat("p", 22)
	oldID, newID := "wls_"+strings.Repeat("s", 22), "wls_"+strings.Repeat("n", 22)
	makeSession := func(id string) authorityv1.WorkloadSession {
		now := time.Now()
		return authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat(string(id[len(id)-1]), 43), Binding: binding, TeamId: team, ProjectKey: "project", Workload: "worker", Provider: controlv1.WorkloadVercel, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, ServiceIds: []string{service}, ExpiresAt: now.Add(time.Hour), LeaseExpiresAt: now.Add(90 * time.Second), RenewAfter: now.Add(30 * time.Second)}
	}
	oldSession, newSession := makeSession(oldID), makeSession(newID)
	var mu sync.Mutex
	var oldKey, nextKey []byte
	var nextNonce string
	var exchanges, dropped int
	var revoked bool
	var preparing bool
	var preparedRequests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/workload-sessions/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.WorkloadIdentity{Binding: binding, Services: []string{"db"}, AssertionExpiresAt: time.Now().Add(5 * time.Minute)})
		case "/v1/workload-sessions/exchange":
			var input authorityv1.WorkloadExchange
			if json.NewDecoder(r.Body).Decode(&input) != nil {
				w.WriteHeader(400)
				return
			}
			public, _ := base64.RawURLEncoding.DecodeString(input.PublicKey)
			signature, _ := base64.RawURLEncoding.DecodeString(input.Signature)
			var services []string
			if input.Services != nil {
				services = *input.Services
			}
			digest := sha256.Sum256([]byte(input.Assertion))
			if len(public) != 32 || !ed25519.Verify(public, workloadproof.Exchange(input.TeamId, input.ProjectKey, input.Workload, input.SourceFingerprint, input.Nonce, digest, services), signature) {
				t.Error("invalid native exchange proof")
				w.WriteHeader(403)
				return
			}
			exchanges++
			if oldKey == nil {
				oldKey = public
				_ = json.NewEncoder(w).Encode(oldSession)
				return
			}
			if !reflect.DeepEqual(services, []string{"db"}) || ed25519.PublicKey(public).Equal(ed25519.PublicKey(oldKey)) {
				t.Error("replacement transferred the old key or widened current scope")
				w.WriteHeader(403)
				return
			}
			if nextKey == nil {
				nextKey, nextNonce = public, input.Nonce
			} else if !ed25519.PublicKey(nextKey).Equal(ed25519.PublicKey(public)) || nextNonce != input.Nonce {
				t.Error("lost exchange retry changed its key or nonce")
				w.WriteHeader(403)
				return
			}
			if dropped < 3 {
				dropped++
				c, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_ = c.Close()
				return
			}
			_ = json.NewEncoder(w).Encode(newSession)
		case "/v1/workload-sessions/" + oldID + "/assertions":
			var input authorityv1.WorkloadAssertion
			_ = json.NewDecoder(r.Body).Decode(&input)
			signature, _ := base64.RawURLEncoding.DecodeString(input.Signature)
			digest := sha256.Sum256([]byte(input.Assertion))
			if r.Header.Get("Authorization") != "Bearer "+oldSession.Credential || !ed25519.Verify(oldKey, workloadproof.Attach(oldID, digest), signature) {
				t.Error("attachment did not prove the original session key")
				w.WriteHeader(403)
				return
			}
			// control can narrow expiry before the client's cached deadline.
			w.WriteHeader(410)
			_, _ = w.Write([]byte(`{"status":410,"code":"forbidden","detail":"session expired"}`))
		case "/v1/workload-sessions/" + newID + "/assertions":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"status":403,"code":"forbidden","detail":"session revoked"}`))
		case "/v1/workload/services":
			if r.Header.Get("Authorization") != "Bearer "+newSession.Credential {
				w.WriteHeader(403)
				return
			}
			if pending {
				w.WriteHeader(503)
				_, _ = w.Write([]byte(`{"status":503,"code":"unavailable","detail":"inventory unavailable"}`))
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": service, "service": "db", "protocol": "postgres", "endpoint": controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 15443, Public: false}}}})
		case "/v1/workload/services/" + service + "/authorization":
			_ = json.NewEncoder(w).Encode(controlv1.WorkloadServiceAuthorization{Subject: newSession.Subject, ServiceId: service, ValidUntil: newSession.LeaseExpiresAt, PolicyRevision: 1})
		case "/v1/workload/services/" + service + "/run":
			if !preparing {
				t.Error("attachment eagerly rebuilt a prepared service")
			}
			preparedRequests++
			w.WriteHeader(503)
			_, _ = w.Write([]byte(`{"status":503,"code":"unavailable","detail":"requested preparation barrier"}`))
		case "/v1/workload-sessions/" + newID:
			if r.Method != http.MethodDelete {
				w.WriteHeader(405)
				return
			}
			revoked = true
			w.WriteHeader(204)
		case "/v1/workload-sessions/" + oldID:
			w.WriteHeader(204)
		default:
			t.Error("replacement eagerly started an unrequested service", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := workload.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), team, "project", strings.Repeat("a", 64), "worker", "first", []string{"db", "removed"}); err != nil {
		t.Fatal(err)
	}
	b := &connectorConnectionBackend{scope: connectorruntime.Context{Schema: 1, Server: server.URL, TeamID: team, ProjectKey: "project", SourceID: strings.Repeat("a", 64), Workload: "worker", Services: []string{"db", "removed"}}, httpClient: server.Client(), connectorConnectionSession: connectorConnectionSession{workload: client, deadline: oldSession.ExpiresAt}, prepared: map[string]*preparedConnection{}, project: projectConfiguration{Project: clientproject.Project{Config: config.TNL{Services: config.Services{"db": {Protocol: new("postgres")}}}}}}
	// a replacement session invalidates old snapshots without rebuilding their
	// listeners. only a later Connect for the requested service may do that work.
	b.prepared["db"] = &preparedConnection{ready: true, sessionID: oldID, service: controlv1.Service{Id: service, Protocol: controlv1.Postgres, Enabled: true, Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 15443}}}
	b.prepared["removed"] = &preparedConnection{ready: true, sessionID: oldID}
	if err := b.Attach(t.Context(), "first"); err == nil || b.replacement == nil || b.workload != client {
		t.Fatal("lost replacement exchange abandoned its original key or replaced the live adapter", err)
	}
	err = b.Attach(t.Context(), "rotated")
	if pending {
		if err == nil || b.replacement == nil {
			t.Fatal("fixture did not retain its issued pending replacement", err)
		}
		if _, err := b.replacement.Session(); err != nil {
			t.Fatal(err)
		}
		if err := b.Close(t.Context()); err != nil {
			t.Fatal(err)
		}
		mu.Lock()
		defer mu.Unlock()
		if !revoked {
			t.Fatal("issued pending replacement was not revoked")
		}
		return
	}
	if err != nil {
		t.Fatal("replacement did not recover its committed exchange", err)
	}
	if len(b.prepared) != 2 || len(b.services) != 1 || b.metadata.Services["db"].Protocol != "postgres" {
		t.Fatal("authorized snapshot was confused with prepared listeners")
	}
	current, err := b.workload.Session()
	if err != nil || current.Id != newID || current.Binding != binding {
		t.Fatal("replacement lost verified identity", err)
	}
	previous, _ := client.Session()
	if previous.Id != oldID {
		t.Fatal("existing adapter inherited the new session")
	}
	mu.Lock()
	preparing = true
	mu.Unlock()
	if _, err := b.Connect(t.Context(), "db"); err == nil {
		t.Fatal("requested preparation failure was hidden")
	}
	mu.Lock()
	requests := preparedRequests
	mu.Unlock()
	if requests != 1 {
		t.Fatal("replacement did not rebuild only the requested old-session adapter", requests)
	}
	if err := b.Attach(t.Context(), "rotated"); err == nil {
		t.Fatal("revocation silently created another session")
	}
	mu.Lock()
	count := exchanges
	mu.Unlock()
	if count != 5 {
		t.Fatal("unexpected exchange replay count", count)
	}
	if err := b.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !revoked {
		t.Fatal("replacement session was not revoked during joined cleanup")
	}
}
