package controlclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAdminListRelaysReadsEveryPage(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet || request.URL.Path != "/v1/admin/relays" || request.Header.Get("Authorization") != "Bearer access" || request.Header.Get("Accept") != "application/json, application/problem+json" {
			t.Errorf("unexpected admin request: %s %s", request.Method, request.URL)
			http.Error(response, "unexpected request", http.StatusBadRequest)
			return
		}
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Query().Get("cursor") {
		case "":
			_, _ = response.Write([]byte(`{"relays":[{"relay_id":"relay_a"}],"next_cursor":"relay_a"}`))
		case "relay_a":
			_, _ = response.Write([]byte(`{"relays":[{"relay_id":"relay_b"}]}`))
		default:
			t.Errorf("cursor = %q", request.URL.Query().Get("cursor"))
			http.Error(response, "unexpected cursor", http.StatusBadRequest)
		}
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	page, err := client.AdminListRelays(t.Context())
	if err != nil || len(page.Relays) != 2 || page.Relays[0].RelayId != "relay_a" ||
		page.Relays[1].RelayId != "relay_b" || page.NextCursor != nil {
		t.Fatalf("relay page = %#v, %v", page, err)
	}
}

func TestAdminListRelaysRejectsNonAdvancingCursor(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"relays":[{"relay_id":"relay_a"}],"next_cursor":"relay_a"}`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	if page, err := client.AdminListRelays(t.Context()); err == nil || page.Relays != nil {
		t.Fatalf("relay page = %#v, error %v", page, err)
	}
}

func TestAdminServerStatusRejectsEmptyObject(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{}`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	status, err := client.AdminServerStatus(t.Context())
	if err == nil || !status.StartedAt.IsZero() || status.Role != "" {
		t.Fatalf("status = %#v, error = %v", status, err)
	}
}

func TestAdminServerStatusRejectsNegativeCounters(t *testing.T) {
	now := time.Now().UTC().Format(time.RFC3339Nano)
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		_, _ = response.Write([]byte(`{"role":"control","started_at":"` + now + `","current_time":"` + now + `","enabled_routes":-1,"suspended_routes":0,"starting_publish_runs":0,"ready_publish_runs":0,"ingress_leases":0,"relay_leases":0}`))
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), "access")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.AdminServerStatus(t.Context()); err == nil {
		t.Fatal("negative status counter was accepted")
	}
}
