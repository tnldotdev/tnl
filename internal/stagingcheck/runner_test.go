package stagingcheck

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCLIEventAndStatusSelection(t *testing.T) {
	for _, input := range []string{
		`{"schema_version":1,"type":"ready","url":"https://a.example","tunnel_id":"tunnel_1","publish_run_number":0}`,
		`{"schema_version":1,"type":"error","code":"TNL_UNAVAILABLE"}`,
		`{"schema_version":2,"type":"ready"}`,
		`{`,
	} {
		if _, err := parseReady([]byte(input)); err == nil {
			t.Fatalf("accepted invalid publisher event %s", input)
		}
	}
	ready, err := parseReady([]byte(`{"schema_version":1,"type":"ready","url":"https://a.example","tunnel_id":"tunnel_1","publish_run_number":2}`))
	if err != nil || ready.URL != "https://a.example" || ready.PublishRunNumber != 2 {
		t.Fatalf("ready event = %+v, %v", ready, err)
	}
	status := []byte(`{"tunnels":[{"tunnel_id":"tunnel_1","server":"https://other.example","public_url_id":"wrong"},{"tunnel_id":"tunnel_1","server":"https://control.example","public_url_id":"ours"}]}`)
	if id, err := statusPublicURLID(status, "tunnel_1", "https://control.example"); err != nil || id != "ours" {
		t.Fatalf("selected ID = %q, %v", id, err)
	}
	if _, err := statusPublicURLID(status, "tunnel_2", "https://control.example"); err == nil {
		t.Fatal("accepted another tunnel's public URL ID")
	}
}

func TestCLIVisitorRejectsUnrelatedService(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/release-check/testnonce" {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(struct{ Host, Nonce string }{r.Host, "testnonce"})
	}))
	defer server.Close()
	if err := visitWithClient(t.Context(), server.Client(), server.URL, "testnonce"); err != nil {
		t.Fatal(err)
	}
	if err := visitWithClient(t.Context(), server.Client(), "http://example.test", "testnonce"); err == nil || !strings.Contains(err.Error(), "invalid public URL") {
		t.Fatalf("insecure visitor URL = %v", err)
	}
	wrong := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(struct{ Host, Nonce string }{"wrong.example", "testnonce"})
	}))
	defer wrong.Close()
	if err := visitWithClient(t.Context(), wrong.Client(), wrong.URL, "testnonce"); err == nil {
		t.Fatal("accepted a response from an unrelated local service")
	}
}
