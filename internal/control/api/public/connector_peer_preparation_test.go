package public

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
)

type connectorPreparationTestStore struct {
	ConnectorPeerPairStore
	report *controlstate.ConnectorPeerPairPrepared
}

func (s *connectorPreparationTestStore) ConfirmConnectorPeerPairPrepared(_ context.Context, _, _, _, _ string, report controlstate.ConnectorPeerPairPrepared, _ time.Time) error {
	s.report = &report
	return nil
}

func TestConnectorPeerPreparationRequiresExplicitPhase(t *testing.T) {
	for _, test := range []struct {
		name, field, phase string
	}{
		{"omitted", "", ""},
		{"empty", `"phase":"",`, ""},
		{"null", `"phase":null,`, ""},
		{"unknown", `"phase":"prepared",`, ""},
		{"installed", `"phase":"installed",`, "installed"},
		{"proved", `"phase":"proved",`, "proved"},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &connectorPreparationTestStore{}
			handler := testHandler(t, Config{}, nil, nil, nil, Stores{ConnectorPeerPairs: store})
			request := httptest.NewRequest(http.MethodPost, "/v1/services/svc_1234567890123456789012/runs/srun_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/prepared", strings.NewReader(`{`+test.field+`"delivery_id":"AQEBAQEBAQEBAQEBAQEBAQ","delivery_generation":1,"binding_expires_at":"2026-11-11T12:00:00Z"}`))
			request.Header.Set("Authorization", "Bearer run-token")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if test.phase == "" {
				if response.Code != http.StatusBadRequest || store.report != nil {
					t.Fatal("invalid phase reached state", response.Code)
				}
				return
			}
			if response.Code != http.StatusNoContent || store.report == nil || store.report.Phase != test.phase || store.report.OperationID != "" {
				t.Fatal("explicit phase changed or fabricated an initial rebind operation", response.Code)
			}
		})
	}
}
