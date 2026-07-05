package controlclient

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAdminListRelaysReadsEveryPage(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "application/json")
		switch request.URL.Query().Get("cursor") {
		case "":
			_, _ = response.Write([]byte(`{"relays":[{"relay_id":"relay_a"}],"next_cursor":"relay_a"}`))
		case "relay_a":
			_, _ = response.Write([]byte(`{"relays":[{"relay_id":"relay_b"}]}`))
		default:
			t.Fatalf("cursor = %q", request.URL.Query().Get("cursor"))
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
