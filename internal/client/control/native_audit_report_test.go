package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestNativeAuditUsesExactRunTokenAndPair(t *testing.T) {
	const run = "srun_0123456789ABCDEFGHIJKL"
	const service = "svc_0123456789ABCDEFGHIJKL"
	const token = credentials.ServiceRunToken("private-service-run-token")
	o := serviceaudit.Observation{EventID: serviceaudit.NewID(), ServiceID: service, ServiceKind: "service", EventType: "connection.open",
		OccurredAt: time.Now(), RunID: run, RunNumber: 7, PairID: "npp_0123456789ABCDEFGHIJKL", VisitorConnectionID: "vc_0123456789ABCDEFGHIJKL", SourceIP: "192.0.2.1", Outcome: "allowed"}
	calls := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Method != "POST" || r.URL.Path != "/v1/services/"+service+"/runs/"+run+"/service-observations" || r.Header.Get("Authorization") != "Bearer "+token.String() {
			t.Error("native audit used another authentication scope")
		}
		var body controlv1.ServiceRunObservations
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RunNumber != 7 || len(body.Events) != 1 || body.Events[0].PairId == nil || *body.Events[0].PairId != o.PairID {
			t.Error("native observation lost its pair scope")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accepted":0,"duplicates":1}`))
	}))
	defer server.Close()
	c, err := New(server.URL, server.Client(), "person-token")
	if err != nil {
		t.Fatal(err)
	}
	batch := serviceaudit.Batch{Events: []serviceaudit.Observation{o}}
	if err := c.ReportServiceRunObservations(t.Context(), service, run, 7, token, batch); err != nil {
		t.Fatal(err)
	}
	if err := c.ReportServiceRunObservations(t.Context(), service, run, 8, token, batch); !errors.Is(err, serviceaudit.ErrRejected) || calls != 1 {
		t.Fatal("another run number reached the network", err)
	}
	batch.Events[0].PairID = ""
	if err := c.ReportServiceRunObservations(t.Context(), service, run, 7, token, batch); !errors.Is(err, serviceaudit.ErrRejected) || calls != 1 {
		t.Fatal("an unbound native report reached the network", err)
	}
}
