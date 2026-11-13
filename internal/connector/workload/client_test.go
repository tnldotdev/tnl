package workload

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestSessionUpdatesShareImmutableAndNarrowingBoundary(t *testing.T) {
	for _, operation := range []string{"renew", "attach"} {
		for _, tc := range []struct {
			name   string
			mutate func(*authorityv1.WorkloadSession)
			accept bool
		}{
			{"unchanged", func(*authorityv1.WorkloadSession) {}, true},
			{"fresh identity proof", func(s *authorityv1.WorkloadSession) { s.IdentityExpiresAt = s.IdentityExpiresAt.Add(time.Minute) }, true},
			{"identity expiry rollback", func(s *authorityv1.WorkloadSession) { s.IdentityExpiresAt = s.IdentityExpiresAt.Add(-time.Minute) }, false},
			{"lease beyond proof", func(s *authorityv1.WorkloadSession) { s.IdentityExpiresAt = time.Now().Add(time.Second) }, false},
			{"verified proof beyond saved identity", func(s *authorityv1.WorkloadSession) { s.AssertionExpiresAt = new(s.IdentityExpiresAt.Add(time.Minute)) }, true},
			{"expired verified proof", func(s *authorityv1.WorkloadSession) { s.AssertionExpiresAt = new(time.Now().Add(-time.Second)) }, false},
			{"unbounded verified proof", func(s *authorityv1.WorkloadSession) { s.AssertionExpiresAt = new(time.Now().Add(13 * time.Hour)) }, false},
			{"fresh hint cannot extend accepted identity", func(s *authorityv1.WorkloadSession) {
				s.AssertionExpiresAt = new(s.IdentityExpiresAt.Add(time.Minute))
				s.IdentityExpiresAt = s.LeaseExpiresAt.Add(-time.Second)
			}, false},
			{"fresh hint cannot revive expired identity", func(s *authorityv1.WorkloadSession) {
				s.AssertionExpiresAt = new(s.IdentityExpiresAt.Add(time.Minute))
				s.IdentityExpiresAt = time.Now().Add(-time.Second)
			}, false},
			{"negative sequence", func(s *authorityv1.WorkloadSession) { s.RenewalSequence = -1 }, false},
			{"sequence rollback", func(s *authorityv1.WorkloadSession) { s.RenewalSequence = 1 }, false},
			{"sequence jump", func(s *authorityv1.WorkloadSession) { s.RenewalSequence += 2 }, false},
			{"shorter expiry", func(s *authorityv1.WorkloadSession) { s.ExpiresAt = new(s.ExpiresAt.Add(-time.Minute)) }, true},
			{"fewer rights", func(s *authorityv1.WorkloadSession) { s.ServiceIds = []string{} }, true},
			{"binding", func(s *authorityv1.WorkloadSession) { s.Binding = strings.Repeat("c", 64) }, false},
			{"id", func(s *authorityv1.WorkloadSession) {
				s.Id = "wls_" + strings.Repeat("a", 22)
				s.Subject.WorkloadSessionId = new(s.Id)
			}, false},
			{"credential", func(s *authorityv1.WorkloadSession) { s.Credential = "wlc_" + strings.Repeat("z", 43) }, false},
			{"longer expiry", func(s *authorityv1.WorkloadSession) { s.ExpiresAt = new(s.ExpiresAt.Add(time.Minute)) }, false},
			{"removed hard expiry", func(s *authorityv1.WorkloadSession) { s.ExpiresAt = nil }, false},
			{"team", func(s *authorityv1.WorkloadSession) { s.TeamId = "tm_" + strings.Repeat("a", 22) }, false},
			{"project", func(s *authorityv1.WorkloadSession) { s.ProjectKey = "other" }, false},
			{"workload", func(s *authorityv1.WorkloadSession) { s.Workload = "other" }, false},
			{"provider", func(s *authorityv1.WorkloadSession) { s.Provider = controlv1.WorkloadFly; s.Github = nil }, false},
			{"repository", func(s *authorityv1.WorkloadSession) { s.Github.RepositoryId = "99" }, false},
			{"repository owner", func(s *authorityv1.WorkloadSession) { s.Github.RepositoryOwnerId = "99" }, false},
			{"run", func(s *authorityv1.WorkloadSession) { s.Github.RunId = "99" }, false},
			{"attempt", func(s *authorityv1.WorkloadSession) { s.Github.RunAttempt = "2" }, false},
			{"check run", func(s *authorityv1.WorkloadSession) { s.Github.CheckRunId = "99" }, false},
			{"subject", func(s *authorityv1.WorkloadSession) {
				s.Subject.WorkloadSessionId = new("wls_" + strings.Repeat("a", 22))
			}, false},
			{"expanded rights", func(s *authorityv1.WorkloadSession) {
				s.ServiceIds = append(s.ServiceIds, "svc_"+strings.Repeat("a", 22))
			}, false},
			{"replaced rights", func(s *authorityv1.WorkloadSession) { s.ServiceIds[0] = "svc_" + strings.Repeat("a", 22) }, false},
			{"expired lease", func(s *authorityv1.WorkloadSession) { s.LeaseExpiresAt = time.Now().Add(-time.Second) }, false},
		} {
			t.Run(operation+"/"+tc.name, func(t *testing.T) {
				original := sessionFixture(controlv1.WorkloadGitHub)
				original.RenewalSequence = 2
				next := cloneSession(original)
				if operation == "renew" {
					next.RenewalSequence++
				}
				tc.mutate(&next)
				calls := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					value := original
					if calls > 0 {
						value = next
					}
					calls++
					_ = json.NewEncoder(w).Encode(value)
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				if _, err := client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil); err != nil {
					t.Fatal(err)
				}
				before, _ := client.Session()
				var updated authorityv1.WorkloadSession
				if operation == "renew" {
					updated, err = client.Renew(t.Context())
				} else {
					updated, err = client.Attach(t.Context(), "new assertion")
				}
				if (err == nil) != tc.accept {
					t.Fatalf("update accepted = %t, want %t: %v", err == nil, tc.accept, err)
				}
				saved, _ := client.Session()
				if !tc.accept {
					if !reflect.DeepEqual(saved, before) || updated.Id != "" {
						t.Fatal("failed update changed retained session or returned a usable session")
					}
					return
				}
				if !reflect.DeepEqual(saved, updated) || !saved.ExpiresAt.Equal(*next.ExpiresAt) || len(saved.ServiceIds) != len(next.ServiceIds) {
					t.Fatal("successful narrowing was not retained")
				}
				updated.Github.RunId = "777"
				if len(updated.ServiceIds) > 0 {
					updated.ServiceIds[0] = "changed"
				}
				*updated.Subject.WorkloadSessionId = "changed"
				after, _ := client.Session()
				if !reflect.DeepEqual(saved, after) {
					t.Fatal("returned update aliased retained session")
				}
			})
		}
	}
}

func TestRenewalLostResponseRetryAndSerialization(t *testing.T) {
	original := sessionFixture(controlv1.WorkloadGitHub)
	stored := cloneSession(original)
	var public ed25519.PublicKey
	var lost authorityv1.WorkloadRenewal
	requests, applied := 0, 0
	var serverState sync.Mutex
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serverState.Lock()
		defer serverState.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/exchange") {
			var exchange authorityv1.WorkloadExchange
			if err := json.NewDecoder(r.Body).Decode(&exchange); err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			key, err := base64.RawURLEncoding.DecodeString(exchange.PublicKey)
			if err != nil {
				t.Error(err)
				w.WriteHeader(400)
				return
			}
			public = key
			_ = json.NewEncoder(w).Encode(original)
			return
		}
		var body authorityv1.WorkloadRenewal
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		signature, err := base64.RawURLEncoding.Strict().DecodeString(body.Signature)
		if err != nil || !ed25519.Verify(public, workloadproof.Renew(original.Id, body.Sequence), signature) || r.Header.Get("Authorization") != "Bearer "+original.Credential {
			t.Error("renewal was not signed by the exchanged key")
			w.WriteHeader(403)
			return
		}
		requests++
		if body.Sequence == stored.RenewalSequence+1 {
			stored.RenewalSequence = body.Sequence
			applied++
		} else if body.Sequence != stored.RenewalSequence {
			t.Error("concurrent renewal skipped a sequence")
			w.WriteHeader(403)
			return
		}
		if requests == 1 {
			lost = body
			// drop the connection after commit, before sending a response byte.
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		if requests == 2 && !reflect.DeepEqual(body, lost) {
			t.Error("lost response retried a different proof")
		}
		_ = json.NewEncoder(w).Encode(stored)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil); err != nil {
		t.Fatal(err)
	}
	before, _ := client.Session()
	if _, err := client.Renew(t.Context()); err == nil {
		t.Fatal("lost response was reported as success")
	}
	if saved, _ := client.Session(); !reflect.DeepEqual(saved, before) {
		t.Fatal("unacknowledged mutation changed the local session")
	}
	if retried, err := client.Renew(t.Context()); err != nil || retried.RenewalSequence != 1 {
		t.Fatal("lost response retry failed", err)
	}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if _, err := client.Renew(t.Context()); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	serverState.Lock()
	defer serverState.Unlock()
	if saved, _ := client.Session(); saved.RenewalSequence != 9 || applied != 9 || requests != 10 {
		t.Fatal("renewals were not serialized or retry was applied twice", saved.RenewalSequence, applied, requests)
	}
}

func TestSessionSequenceUpdatesAndOverflow(t *testing.T) {
	for _, operation := range []string{"renew", "attach", "exchange"} {
		for _, sequence := range []int64{-1, 1, 2, 3, 4, math.MaxInt64} {
			t.Run(operation+"/"+strconv.FormatInt(sequence, 10), func(t *testing.T) {
				original := sessionFixture(controlv1.WorkloadGitHub)
				original.RenewalSequence = 2
				calls := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					value := original
					if calls > 1 {
						value.RenewalSequence = sequence
					}
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(value)
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client())
				if err != nil {
					t.Fatal(err)
				}
				exchange := func() (authorityv1.WorkloadSession, error) {
					return client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil)
				}
				if _, err := exchange(); err != nil {
					t.Fatal(err)
				}
				before, _ := client.Session()
				var next authorityv1.WorkloadSession
				switch operation {
				case "renew":
					next, err = client.Renew(t.Context())
				case "attach":
					next, err = client.Attach(t.Context(), "assertion")
				case "exchange":
					next, err = exchange()
				}
				accepted := sequence == 3 || operation != "renew" && sequence == 2
				if (err == nil) != accepted {
					t.Fatal("unexpected sequence acceptance", err)
				}
				if !accepted {
					if saved, _ := client.Session(); !reflect.DeepEqual(saved, before) || next.Id != "" {
						t.Fatal("invalid sequence changed the retained session")
					}
				}
			})
		}
	}
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("overflow sent an HTTP request") }))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	client.session = sessionFixture(controlv1.WorkloadGitHub)
	client.session.RenewalSequence = math.MaxInt64
	if _, err := client.Renew(t.Context()); err == nil {
		t.Fatal("renewal sequence overflow attempted a request")
	}
}

func sessionFixture(provider controlv1.WorkloadProvider) authorityv1.WorkloadSession {
	id := "wls_" + strings.Repeat("s", 22)
	now := time.Now()
	s := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: "tm_" + strings.Repeat("t", 22), ProjectKey: "store", Workload: "storefront", Provider: provider, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, LeaseExpiresAt: now.Add(90 * time.Second), ExpiresAt: new(now.Add(time.Hour)), RenewAfter: now.Add(30 * time.Second), ServiceIds: []string{"svc_" + strings.Repeat("p", 22)}}
	s.Binding = strings.Repeat("b", 64)
	s.IdentityExpiresAt = now.Add(5 * time.Minute)
	if provider == controlv1.WorkloadGitHub {
		s.Github = &authorityv1.WorkloadGitHubExecution{RepositoryId: "12345", RepositoryOwnerId: "6789", RunId: "111", RunAttempt: "1", CheckRunId: "222"}
	}
	return s
}

func TestSessionProviderExecutionValidation(t *testing.T) {
	for _, provider := range []controlv1.WorkloadProvider{controlv1.WorkloadGitHub, controlv1.WorkloadVercel, controlv1.WorkloadFly, controlv1.WorkloadOIDC} {
		s := sessionFixture(provider)
		if err := validateSession(s); err != nil {
			t.Fatal("valid provider session rejected", provider, err)
		}
		if provider != controlv1.WorkloadGitHub {
			s.Github = sessionFixture(controlv1.WorkloadGitHub).Github
			if err := validateSession(s); err == nil {
				t.Fatal("another provider accepted GitHub execution", provider)
			}
		}
	}
	s := sessionFixture(controlv1.WorkloadGitHub)
	s.Github = nil
	if err := validateSession(s); err == nil {
		t.Fatal("GitHub session accepted missing execution")
	}
	for _, field := range []string{"repository_id", "repository_owner_id", "run_id", "run_attempt", "check_run_id"} {
		for _, bad := range []string{"", "0", "job-name", "123456789012345678901"} {
			s := sessionFixture(controlv1.WorkloadGitHub)
			data, _ := json.Marshal(s.Github)
			var execution map[string]string
			_ = json.Unmarshal(data, &execution)
			execution[field] = bad
			data, _ = json.Marshal(execution)
			if err := json.Unmarshal(data, s.Github); err != nil {
				t.Fatal(err)
			}
			if err := validateSession(s); err == nil {
				t.Fatalf("GitHub session accepted invalid %s", field)
			}
		}
	}
}

func TestSessionRenewalRetainsProviderExecutionAndCopiesMetadata(t *testing.T) {
	for _, field := range []string{"provider", "repository_id", "repository_owner_id", "run_id", "run_attempt", "check_run_id", "subject"} {
		t.Run(field, func(t *testing.T) {
			original := sessionFixture(controlv1.WorkloadGitHub)
			next := cloneSession(original)
			next.RenewalSequence++
			switch field {
			case "provider":
				next.Provider = controlv1.WorkloadVercel
				next.Github = nil
			case "repository_id":
				next.Github.RepositoryId = "99"
			case "repository_owner_id":
				next.Github.RepositoryOwnerId = "99"
			case "run_id":
				next.Github.RunId = "99"
			case "run_attempt":
				next.Github.RunAttempt = "2"
			case "check_run_id":
				next.Github.CheckRunId = "99"
			case "subject":
				next.Subject.WorkloadSessionId = new("wls_" + strings.Repeat("a", 22))
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				value := original
				if strings.HasSuffix(r.URL.Path, "/renew") {
					value = next
				}
				_ = json.NewEncoder(w).Encode(value)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			exchanged, err := client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil)
			if err != nil {
				t.Fatal(err)
			}
			exchanged.Github.RunId = "333"
			saved, err := client.Session()
			if err != nil || saved.Github.RunId != "111" {
				t.Fatal("returned execution mutated retained session", err)
			}
			if _, err = client.Renew(t.Context()); err == nil {
				t.Fatal("renewal accepted changed immutable metadata", field)
			}
		})
	}
}

func TestSessionDecoderRejectsLegacyExecutionFields(t *testing.T) {
	original := sessionFixture(controlv1.WorkloadGitHub)
	data, _ := json.Marshal(original)
	var wire map[string]any
	_ = json.Unmarshal(data, &wire)
	wire["run_id"] = "111"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(wire)
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if _, err = client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil); err == nil {
		t.Fatal("legacy top-level GitHub field was accepted")
	}
}

func TestSessionDecoderPreservesSDKWireAssertions(t *testing.T) {
	check := func(t *testing.T, provider controlv1.WorkloadProvider, mutate func(map[string]any)) {
		t.Helper()
		original := sessionFixture(provider)
		data, _ := json.Marshal(original)
		var wire map[string]any
		_ = json.Unmarshal(data, &wire)
		mutate(wire)
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(wire)
		}))
		defer server.Close()
		client, err := New(server.URL, server.Client())
		if err != nil {
			t.Fatal(err)
		}
		if _, err = client.Exchange(t.Context(), original.TeamId, original.ProjectKey, strings.Repeat("a", 64), original.Workload, "assertion", nil); err == nil {
			t.Fatal("invalid session wire accepted")
		}
	}
	for _, provider := range []controlv1.WorkloadProvider{controlv1.WorkloadGitHub, controlv1.WorkloadVercel, controlv1.WorkloadFly, controlv1.WorkloadOIDC} {
		t.Run(string(provider), func(t *testing.T) {
			for _, field := range []string{"run_id", "run_attempt", "check_run_id", "unknown"} {
				check(t, provider, func(w map[string]any) { w[field] = "" })
			}
			if provider != controlv1.WorkloadGitHub {
				for _, value := range []any{nil, map[string]any{}, sessionFixture(controlv1.WorkloadGitHub).Github} {
					check(t, provider, func(w map[string]any) { w["github"] = value })
				}
			}
		})
	}
	for _, field := range []string{"repository_id", "repository_owner_id", "run_id", "run_attempt", "check_run_id"} {
		for _, value := range []any{nil, "", "0", "job-name", strings.Repeat("1", 21), 123} {
			check(t, controlv1.WorkloadGitHub, func(w map[string]any) { w["github"].(map[string]any)[field] = value })
		}
		check(t, controlv1.WorkloadGitHub, func(w map[string]any) { delete(w["github"].(map[string]any), field) })
	}
	check(t, controlv1.WorkloadGitHub, func(w map[string]any) { w["github"].(map[string]any)["unknown"] = "claim" })
	check(t, controlv1.WorkloadGitHub, func(w map[string]any) { w["provider"] = "unknown" })
	check(t, controlv1.WorkloadGitHub, func(w map[string]any) { delete(w, "renewal_sequence") })
	check(t, controlv1.WorkloadGitHub, func(w map[string]any) { delete(w, "identity_expires_at") })
	check(t, controlv1.WorkloadGitHub, func(w map[string]any) { w["identity_expires_at"] = nil })
	for _, value := range []any{nil, "-1", 0, 0.5, "9223372036854775808", json.Number("9223372036854775808")} {
		check(t, controlv1.WorkloadGitHub, func(w map[string]any) { w["renewal_sequence"] = value })
	}
}
