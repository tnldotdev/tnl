package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestDeploymentSelectionKeepsSourceAuthenticationSeparate(t *testing.T) {
	for _, kind := range []string{"device", "registered_key", "workload"} {
		t.Run(kind, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/v1/projects/shop/deployments/customer/services/db/select" || r.URL.Query().Get("team_id") != "team-selected" {
					t.Error("request lost its captured deployment selection")
				}
				want := ""
				if kind == "device" {
					want = "Bearer control-session-secret"
				}
				if r.Header.Get("Authorization") != want {
					t.Error("request mixed body credentials and a control bearer")
				}
				var body controlv1.SelectDeploymentServiceRunJSONRequestBody
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				var source struct {
					Kind string `json:"kind"`
				}
				if err := json.Unmarshal(body.Source, &source); err != nil || source.Kind != kind {
					t.Error("request changed its visitor source", err)
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(controlv1.ServiceSelection{ServiceId: "selected-service"}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "control-session-secret")
			if err != nil {
				t.Fatal(err)
			}
			source, err := json.Marshal(map[string]string{"kind": kind})
			if err != nil {
				t.Fatal(err)
			}
			selected, err := client.SelectDeploymentServiceRun(t.Context(), "team-selected", "shop", "customer", "db", source)
			if err != nil || selected.ServiceId != "selected-service" {
				t.Fatal("generated deployment selection request failed", err)
			}
		})
	}
}
