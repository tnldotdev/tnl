package control

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestServiceAccessPaginationRejectsIncompleteOrUnsafePages(t *testing.T) {
	const service = "svc_0123456789abcdefghijkl"
	for _, kind := range []string{"grants", "invitations"} {
		for _, corrupt := range []string{"missing array", "too many", "empty next", "short next", "wrong next", "cycle", "overlap", "wrong scope", "secret", "denied second page"} {
			t.Run(kind+"/"+corrupt, func(t *testing.T) {
				calls := 0
				server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls++
					if calls > 2 {
						t.Error("unsafe cursor caused another request")
						w.WriteHeader(500)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					if calls == 2 && corrupt == "denied second page" {
						w.WriteHeader(404)
						_ = json.NewEncoder(w).Encode(controlv1.Problem{Code: controlv1.NotFound})
						return
					}
					prefix := "sgr_"
					if kind == "invitations" {
						prefix = "sivt_"
					}
					n, start := 100, 1
					if calls == 2 && corrupt != "cycle" && corrupt != "overlap" {
						start = 101
					}
					if corrupt == "too many" {
						n = 101
					}
					if corrupt == "empty next" {
						n = 0
					}
					if corrupt == "short next" {
						n = 1
					}
					rows := make([]map[string]any, 0, n)
					for i := range n {
						row := map[string]any{"id": fmt.Sprintf("%s%022d", prefix, start+i), "service_id": service}
						if kind == "grants" {
							row["kind"] = "identity"
						}
						if corrupt == "wrong scope" {
							row["service_id"] = "svc_abcdefghijkl0123456789"
						}
						if corrupt == "secret" {
							row["secret"] = "never-print-this-secret"
						}
						rows = append(rows, row)
					}
					next := fmt.Sprintf("%s%022d", prefix, 100)
					if corrupt == "wrong next" {
						next = fmt.Sprintf("%s%022d", prefix, 99)
					}
					page := map[string]any{kind: rows, "next_cursor": next}
					if corrupt == "missing array" {
						delete(page, kind)
					}
					if corrupt == "overlap" && calls == 2 {
						delete(page, "next_cursor")
					}
					_ = json.NewEncoder(w).Encode(page)
				}))
				defer server.Close()
				client, err := New(server.URL, server.Client(), "manager")
				if err != nil {
					t.Fatal(err)
				}
				if kind == "grants" {
					rows, listErr := client.ListServiceGrants(t.Context(), service)
					err = listErr
					if rows != nil {
						t.Fatal("partial grants escaped a failed list")
					}
				} else {
					rows, listErr := client.ListServiceInvitations(t.Context(), service)
					err = listErr
					if rows != nil {
						t.Fatal("partial invitations escaped a failed list")
					}
				}
				want := failure.ServerResponseInvalid
				if corrupt == "denied second page" {
					want = failure.ServerResourceNotFound
				}
				if reason, ok := failure.ReasonOf(err); !ok || reason != want {
					t.Fatalf("unsafe pagination returned %v; want %s", err, want)
				}
			})
		}
	}
}
