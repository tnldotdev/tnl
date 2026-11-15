package authority

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/credentials"
)

func TestBrowserHandoffUsesExactServiceAndParentRefreshCredential(t *testing.T) {
	const service = "svc_0123456789abcdefghijkl"
	const handoff = "https://web.example.test/__tnl/team/handoff/one-use"
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if r.Method != http.MethodPost || r.URL.Path != "/v1/auth/browser-handoff" || r.Header.Get("Authorization") != "Bearer parent-access" ||
			len(body) != 2 || body["service_id"] != service || body["refresh_token"] != "parent-refresh" {
			t.Error("browser handoff lost its exact service or parent credentials")
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{"url": handoff})
	}))
	defer server.Close()
	client, err := New(server.URL, server.Client(), credentials.AccessToken("parent-access"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.IssueControlBrowserHandoff(t.Context(), service, credentials.RefreshToken("parent-refresh"))
	if err != nil || result != handoff || calls != 1 {
		t.Fatalf("browser handoff calls=%d err=%v", calls, err)
	}
}
