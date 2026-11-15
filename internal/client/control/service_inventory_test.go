package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceInventoryReturnsDefiningSummariesForExplicitAccessPath(t *testing.T) {
	const id = "svc_0123456789abcdefghijkl"
	for _, path := range []controlv1.ServiceAccessPath{controlv1.ServiceAccessPathConnector, controlv1.ServiceAccessPathPublicEndpoint} {
		t.Run(string(path), func(t *testing.T) {
			expected := controlv1.ServiceSummary{Id: id, TeamId: "tm_0123456789abcdefghijkl", TeamName: "studio", VisitorAccess: "identity_grant",
				Name: "web", Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, TrustRevision: 1,
				Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true}}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/visitor/services" || r.URL.Query().Get("access_path") != string(path) ||
					r.Header.Get("Authorization") != "Bearer visitor" || r.URL.Query().Has("team_id") {
					t.Error("visitor listing changed its explicit access path or authentication boundary")
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{expected}})
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "visitor")
			if err != nil {
				t.Fatal(err)
			}
			items, err := client.ListAvailableServices(t.Context(), path)
			if err != nil || !reflect.DeepEqual(items, []controlv1.ServiceSummary{expected}) {
				t.Fatal("client changed defining summary facts", items, err)
			}
			encoded, err := json.Marshal(items)
			if err != nil {
				t.Fatal(err)
			}
			for _, fabricated := range []string{"endpoint_revision", "ephemeral", "require_post_quantum", "target_tls", "http_limits"} {
				if strings.Contains(string(encoded), `"`+fabricated+`"`) {
					t.Fatal("summary inventory fabricated a full-service field", fabricated)
				}
			}
		})
	}
}

func TestServiceInventoryRejectsPublisherOnlyTrustAndLimits(t *testing.T) {
	for _, field := range []string{`"target_tls":{"hostname":"target.internal","pem":"private-ca-secret","system":false,"digest":"invalid"}`, `"http_limits":{"total":81}`} {
		t.Run(strings.SplitN(field, ":", 2)[0], func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"services":[{"id":"svc_0123456789abcdefghijkl","name":"web","protocol":"http","enabled":true,"publisher_pool":false,"trust_revision":"1","created_at":"2026-01-01T00:00:00Z",` + field + `}]}`))
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "visitor")
			if err != nil {
				t.Fatal(err)
			}
			_, err = client.ListAvailableServices(t.Context(), controlv1.ServiceAccessPathConnector)
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerResponseInvalid || strings.Contains(err.Error(), "private-ca-secret") {
				t.Fatal("visitor summary accepted publisher-only data or disclosed it in an error", err)
			}
		})
	}
}

func TestServiceInventoryManagementReturnsSummariesWithoutVisitorFacts(t *testing.T) {
	expected := controlv1.ServiceSummary{Id: "svc_0123456789abcdefghijkl", TeamId: "tm_0123456789abcdefghijkl", Name: "web",
		Protocol: controlv1.ServiceProtocolHTTP, Enabled: true, TrustRevision: 2,
		Source:   &controlv1.LocalServiceSource{ProjectKey: "local-project", SourceFingerprint: strings.Repeat("a", 64), WorktreeKey: "worktree", Service: "web"},
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example.test", Port: 443, Public: true}}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/services" || r.URL.Query().Get("team_id") != expected.TeamId ||
			len(r.URL.Query()) != 1 || r.Header.Get("Authorization") != "Bearer manager" {
			t.Errorf("management summaries required visitor or exact-service reads: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{expected}})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "manager")
	if err != nil {
		t.Fatal(err)
	}
	items, err := client.ListServices(t.Context(), expected.TeamId)
	if err != nil || !reflect.DeepEqual(items, []controlv1.ServiceSummary{expected}) {
		t.Fatal("management inventory changed its defining summary or source binding", items, err)
	}
	encoded, err := json.Marshal(items)
	if err != nil {
		t.Fatal(err)
	}
	for _, absent := range []string{"team_name", "visitor_access", "endpoint_revision", "ephemeral", "require_post_quantum", "target_tls", "http_limits"} {
		if strings.Contains(string(encoded), `"`+absent+`"`) {
			t.Fatal("management inventory fabricated visitor or full-service facts", absent)
		}
	}
}
