package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNativeManagementUsesExistingGeneratedOperationsAndExplicitConditions(t *testing.T) {
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Authorization") != "Bearer pta_scoped" || r.URL.Query().Get("team_id") != "team" {
			t.Error("management lost scoped authorization")
		}
		if r.Method == http.MethodPost && r.Header.Get("Idempotency-Key") != "original" {
			t.Error("creation replaced the original request key")
		}
		if (r.Method == http.MethodPatch || r.Method == http.MethodDelete) && r.Header.Get("If-Match") != `"3"` {
			t.Error("mutation lost its explicit condition")
		}
		if r.Method == http.MethodDelete {
			w.WriteHeader(204)
			return
		}
		w.Header().Set("ETag", `"3"`)
		if r.Method == http.MethodPost {
			w.WriteHeader(201)
		}
		_, _ = w.Write([]byte(`{"id":"dpl_0123456789ABCDEFGHIJKL","team_id":"team","project_key":"shop","name":"selected","revision":3,"targets":{},"services":{}}`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "pta_scoped")
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []DeploymentManagementRequest{
		{Operation: "deployments.create", IdempotencyKey: "original", Body: json.RawMessage(`{"name":"selected","targets":{"db":{"address":"db:5432"}}}`)},
		{Operation: "deployments.get", Deployment: "selected"},
		{Operation: "deployments.update", Deployment: "selected", IfMatch: `"3"`, Body: json.RawMessage(`{"targets":{"db":{"address":"changed:5432"}}}`)},
		{Operation: "deployments.delete", Deployment: "selected", IfMatch: `"3"`},
	} {
		result, err := client.ManageDeployment(t.Context(), "team", "shop", request)
		if err != nil {
			t.Fatal(err)
		}
		if request.Operation != "deployments.delete" && result.ETag != `"3"` {
			t.Fatal("management result lost its ETag")
		}
	}
	for _, request := range []DeploymentManagementRequest{{Operation: "credentials.create"}, {Operation: "deployments.update", IfMatch: `W/"3"`}, {Operation: "deployments.delete", IfMatch: "3"}, {Operation: "deployments.create", Body: json.RawMessage(`{"unexpected":true}`)}} {
		if _, err := client.ManageDeployment(t.Context(), "team", "shop", request); !errors.Is(err, ErrDeploymentManagementRequest) {
			t.Fatal("accepted invalid or unapproved management operation", err)
		}
	}
	if requests != 4 {
		t.Fatal("invalid management input reached control")
	}
}

func TestNativeManagementRetainsCanonicalJSONAndRequiresResponseETag(t *testing.T) {
	for _, header := range []string{`"3"`, "", `W/"3"`, `"4"`} {
		t.Run(header, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("ETag", header)
				_, _ = w.Write([]byte(`{"id":"dpl_0123456789ABCDEFGHIJKL","team_id":"team","project_key":"shop","name":"production","revision":3,"targets":{}}`))
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "pta_scoped")
			if err != nil {
				t.Fatal(err)
			}
			result, err := client.ManageDeployment(t.Context(), "team", "shop", DeploymentManagementRequest{Operation: "deployments.get", Deployment: "production"})
			if header != `"3"` {
				if err == nil {
					t.Fatal("accepted missing, weak or mismatched response ETag")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			data, ok := result.Data.(json.RawMessage)
			var value map[string]any
			if !ok || json.Unmarshal(data, &value) != nil {
				t.Fatal("native did not retain original response JSON")
			}
			if _, present := value["services"]; present {
				t.Fatal("native filled a missing required field before Python validation")
			}
		})
	}
}

func TestNativeManagementRetainsKnownHTTPProblemsWithoutRetry(t *testing.T) {
	for _, test := range []struct {
		status int
		code   string
	}{
		{401, "unauthenticated"}, {403, "forbidden"}, {404, "not_found"}, {409, "conflict"}, {412, "conflict"}, {428, "invalid_request"}, {429, "rate_limited"}, {503, "unavailable"},
	} {
		calls := 0
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			calls++
			w.WriteHeader(test.status)
			_ = json.NewEncoder(w).Encode(map[string]any{"type": "https://tnl.dev/problems/" + test.code, "title": "rejected", "status": test.status, "code": test.code, "request_id": "original", "detail": "request rejected"})
		}))
		client, err := New(server.URL, server.Client(), "pta_scoped")
		if err != nil {
			t.Fatal(err)
		}
		result, err := client.ManageDeployment(t.Context(), "team", "shop", DeploymentManagementRequest{Operation: "deployments.get", Deployment: "production"})
		server.Close()
		if err != nil || result.Status != test.status || result.Problem == nil || string(result.Problem.Code) != test.code || result.Problem.RequestId != "original" || calls != 1 {
			t.Fatalf("lost HTTP problem %d: %#v %v", test.status, result, err)
		}
	}
}

func TestNativeManagementPublisherOperationsShareGeneratedClient(t *testing.T) {
	var methods, paths []string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		if r.URL.Query().Get("team_id") != "team" || r.Header.Get("Authorization") != "Bearer pta_scoped" {
			t.Error("publisher operation lost exact scope")
		}
		switch r.Method {
		case http.MethodPost:
			if r.Header.Get("Idempotency-Key") != "setup-original" {
				t.Error("publisher enrollment lost original key")
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(`{"enrollment_key":"private","enrollment_id":"original","deployment_id":"dpl_0123456789ABCDEFGHIJKL","expires_at":"2026-11-13T10:00:00Z","max_members":1,"services":{"db":"postgres"}}`))
		case http.MethodDelete:
			w.WriteHeader(204)
		default:
			if r.URL.Query().Get("after") != "" {
				if r.URL.Query().Get("after") != "previous" || r.URL.Query().Get("limit") != "1" {
					t.Error("lost pagination")
				}
				_, _ = w.Write([]byte(`{"publishers":[],"next_cursor":"next"}`))
			} else {
				_, _ = w.Write([]byte(`{"team_id":"team","project_key":"shop","deployment_id":"dpl_0123456789ABCDEFGHIJKL"}`))
			}
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "pta_scoped")
	if err != nil {
		t.Fatal(err)
	}
	for _, request := range []DeploymentManagementRequest{
		{Operation: "publishers.create_enrollment", Deployment: "selected", IdempotencyKey: "setup-original", Body: json.RawMessage(`{"services":["db"]}`)},
		{Operation: "publishers.list", Deployment: "selected", After: "previous", Limit: 1},
		{Operation: "publishers.get", Deployment: "selected", Publisher: "publisher"},
		{Operation: "publishers.revoke", Deployment: "selected", Publisher: "publisher"},
	} {
		if _, err := client.ManageDeployment(t.Context(), "team", "shop", request); err != nil {
			t.Fatal(err)
		}
	}
	if len(paths) != 4 || paths[0] != "/v1/projects/shop/deployments/selected/publisher-enrollments" || paths[2] != "/v1/projects/shop/deployments/selected/publishers/publisher" || methods[3] != http.MethodDelete {
		t.Fatal("publisher adapter did not use canonical operations", methods, paths)
	}
}
