package ingress

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

func TestHTTPPublicServiceAdmissionKeepsExactExclusionsAndDoesNotRetryFailures(t *testing.T) {
	for _, mode := range []string{"success", "control failure", "lost response"} {
		t.Run(mode, func(t *testing.T) {
			expected := ingressv1.PublicServiceVisitorClaim{
				IngressRunId: "process", IngressLeaseRevision: 4, IngressPoolId: "pool",
				DestinationPort: 25443, ObservedSourceIp: "192.0.2.4",
				VisitorConnectionId: publicServiceTestID(t, "vc_"),
				ExcludedRuns:        []ingressv1.ServiceRunReference{{ServiceId: publicServiceTestID(t, "svc_"), ServiceRunId: publicServiceTestID(t, "srun_"), RunNumber: 3}},
			}
			approved := ingressv1.PublicServiceVisitorAdmission{
				ServiceId: expected.ExcludedRuns[0].ServiceId, ServiceRunId: publicServiceTestID(t, "srun_"),
				RunNumber: 4, VisitorConnectionId: expected.VisitorConnectionId, ExpiresAt: time.Now().UTC().Add(time.Second),
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/ingresses/ingress/public-services/admit" {
					t.Error("wrong admission operation", r.Method, r.URL.Path)
				}
				var body ingressv1.PublicServiceVisitorClaim
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || !reflect.DeepEqual(body, expected) {
					t.Error("HTTP admission changed the visitor, lease, selector, or exact exclusions", body, err)
				}
				switch mode {
				case "control failure":
					http.Error(w, "control unavailable", http.StatusServiceUnavailable)
				case "lost response":
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Error(err)
						return
					}
					_ = connection.Close()
				default:
					w.Header().Set("Content-Type", "application/json")
					_ = json.NewEncoder(w).Encode(approved)
				}
			}))
			defer server.Close()
			generated, err := ingressv1.NewClientWithResponses(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			client, err := NewHTTPControlClient(generated)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			actual, err := client.AdmitPublicServiceVisitor(ctx, "ingress", expected)
			if calls.Load() != 1 {
				t.Fatal("transport adapter retried a possibly created reservation", calls.Load())
			}
			if mode == "success" {
				if err != nil || !reflect.DeepEqual(actual, approved) {
					t.Fatal("HTTP admission changed the chosen run", actual, err)
				}
			} else if err == nil {
				t.Fatal("transport adapter accepted an ambiguous or failed admission")
			}
		})
	}
}
