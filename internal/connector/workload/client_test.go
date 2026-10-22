package workload

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

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
			{"shorter expiry", func(s *authorityv1.WorkloadSession) { s.ExpiresAt = s.ExpiresAt.Add(-time.Minute) }, true},
			{"fewer rights", func(s *authorityv1.WorkloadSession) { s.ServiceIds = []string{} }, true},
			{"binding", func(s *authorityv1.WorkloadSession) { s.Binding = strings.Repeat("c", 64) }, false},
			{"id", func(s *authorityv1.WorkloadSession) {
				s.Id = "wls_" + strings.Repeat("a", 22)
				s.Subject.WorkloadSessionId = new(s.Id)
			}, false},
			{"credential", func(s *authorityv1.WorkloadSession) { s.Credential = "wlc_" + strings.Repeat("z", 43) }, false},
			{"longer expiry", func(s *authorityv1.WorkloadSession) { s.ExpiresAt = s.ExpiresAt.Add(time.Minute) }, false},
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
				next := cloneSession(original)
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
				if !reflect.DeepEqual(saved, updated) || !saved.ExpiresAt.Equal(next.ExpiresAt) || len(saved.ServiceIds) != len(next.ServiceIds) {
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

func sessionFixture(provider controlv1.WorkloadProvider) authorityv1.WorkloadSession {
	id := "wls_" + strings.Repeat("s", 22)
	now := time.Now()
	s := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: "tm_" + strings.Repeat("t", 22), ProjectKey: "store", Workload: "storefront", Provider: provider, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, LeaseExpiresAt: now.Add(90 * time.Second), ExpiresAt: now.Add(time.Hour), RenewAfter: now.Add(30 * time.Second), ServiceIds: []string{"svc_" + strings.Repeat("p", 22)}}
	s.Binding = strings.Repeat("b", 64)
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
