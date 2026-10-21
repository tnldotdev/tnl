package workloadclient

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func sessionFixture(provider controlv1.WorkloadProvider) authorityv1.WorkloadSession {
	id := "wls_" + strings.Repeat("s", 22)
	now := time.Now()
	s := authorityv1.WorkloadSession{Id: id, Credential: "wlc_" + strings.Repeat("x", 43), TeamId: "tm_" + strings.Repeat("t", 22), ProjectKey: "store", Workload: "storefront", Provider: provider, Subject: controlv1.VisitorSubject{Kind: "workload_session", WorkloadSessionId: &id}, LeaseExpiresAt: now.Add(90 * time.Second), ExpiresAt: now.Add(time.Hour), RenewAfter: now.Add(30 * time.Second), ServiceIds: []string{"psvc_" + strings.Repeat("p", 22)}}
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
