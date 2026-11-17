package control

import (
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceDeleteClientCarriesExplicitConditions(t *testing.T) {
	for _, test := range []struct {
		name, query string
		conditions  controlv1.DeleteServiceParams
		guest       bool
	}{
		{"revision", "expected_service_revision=9223372036854775807", controlv1.DeleteServiceParams{ExpectedServiceRevision: new(int64(9223372036854775807))}, false},
		{"unconditional", "unconditional_delete=true", controlv1.DeleteServiceParams{UnconditionalDelete: new(true)}, false},
		{"guest credential cleanup", "", controlv1.DeleteServiceParams{}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Method != http.MethodDelete || r.URL.Path != "/v1/services/svc_selected" ||
					r.URL.RawQuery != test.query || r.Header.Get("Authorization") != "Bearer exact-credential" {
					t.Error("delete changed exact service, credential, or explicit condition", r.URL)
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "exact-credential")
			if err != nil {
				t.Fatal(err)
			}
			if test.guest {
				err = client.DeleteGuestService(t.Context(), "svc_selected")
			} else {
				err = client.DeleteService(t.Context(), "svc_selected", test.conditions)
			}
			if err != nil || calls != 1 {
				t.Fatal("delete failed or retried unexpectedly", calls, err)
			}
		})
	}
}

func TestServiceDeleteClientRejectsInvalidConditionsBeforeHTTP(t *testing.T) {
	var client *Client
	for _, conditions := range []controlv1.DeleteServiceParams{
		{}, {ExpectedServiceRevision: new(int64(0))}, {ExpectedServiceRevision: new(int64(-1))},
		{UnconditionalDelete: new(false)}, {ExpectedServiceRevision: new(int64(1)), UnconditionalDelete: new(true)},
	} {
		if err := client.DeleteService(t.Context(), "svc_selected", conditions); err == nil {
			t.Fatal("invalid management deletion reached HTTP")
		}
	}
}
