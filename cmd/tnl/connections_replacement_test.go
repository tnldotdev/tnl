package main

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

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/connectionruntime"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/workloadclient"
	"github.com/tnldotdev/tnl/internal/workloadproof"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// real TLS and HTTP proof bytes exercise the native session boundary. provider
// verification itself is covered by the signed-issuer/PG integration target.
func TestConnectionReplacementRetainsLostExchangeKeyAndNarrowedScope(t *testing.T) {
	const binding = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	team, service := "tm_"+strings.Repeat("t", 22), "psvc_"+strings.Repeat("p", 22)
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
			_ = json.NewEncoder(w).Encode(map[string]any{"services": []any{map[string]any{"id": service, "service": "db", "protocol": "postgres", "managed_tls": controlv1.ManagedServiceTLS{Hostname: "db.example.test", Port: 15443, Public: false}}}})
		case "/v1/workload-sessions/" + newID:
			if r.Method != http.MethodDelete {
				w.WriteHeader(405)
				return
			}
			revoked = true
			w.WriteHeader(204)
		default:
			t.Error("replacement eagerly started an unrequested service", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	client, err := workloadclient.New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), team, "project", strings.Repeat("a", 64), "worker", "first", []string{"db", "removed"}); err != nil {
		t.Fatal(err)
	}
	b := &nativeConnectionBackend{scope: connectionruntime.Context{Schema: 1, Server: server.URL, TeamID: team, ProjectKey: "project", SourceID: strings.Repeat("a", 64), Workload: "worker", Services: []string{"db", "removed"}}, httpClient: server.Client(), workload: client, deadline: oldSession.ExpiresAt, prepared: map[string]*preparedConnection{}, project: projectConfiguration{Project: projectconfig.Project{Config: config.TNL{Services: config.Services{"db": {Protocol: new("postgres")}}}}}}
	if err := b.Attach(t.Context(), "first"); err == nil || b.replacement == nil || b.workload != client {
		t.Fatal("lost replacement exchange abandoned its original key or replaced the live adapter", err)
	}
	if err := b.Attach(t.Context(), "rotated"); err != nil {
		t.Fatal("replacement did not recover its committed exchange", err)
	}
	if len(b.prepared) != 0 || len(b.services) != 1 || b.metadata.Services["db"].Protocol != "postgres" {
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
