package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type connectorCandidateTestStore struct {
	ConnectorPeerPairStore
	page controlstate.ConnectorPeerPairCandidates
}

func (s connectorCandidateTestStore) ListConnectorPeerPairs(context.Context, string, string, string, string, time.Time) (controlstate.ConnectorPeerPairCandidates, error) {
	return s.page, nil
}

func TestConnectorPeerCandidateSerializesOptionalOwnerAuthority(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, observed := range []bool{false, true} {
		candidate := controlstate.ConnectorPeerPairCandidate{PairID: "cpp_1234567890123456789012", DeliveryGeneration: 7}
		if observed {
			candidate.OwnerAuthority = &controlstate.ConnectorPeerPairOwnerAuthority{ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
		}
		store := connectorCandidateTestStore{page: controlstate.ConnectorPeerPairCandidates{Items: []controlstate.ConnectorPeerPairCandidate{candidate}}}
		handler := testHandler(t, Config{}, nil, nil, nil, Stores{ConnectorPeerPairs: store})
		request := httptest.NewRequest(http.MethodGet, "/v1/services/svc_1234567890123456789012/runs/srun_1234567890123456789012/connector-peer-pairs", nil)
		request.Header.Set("Authorization", "Bearer run-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		var page controlv1.ConnectorPeerPairCandidates
		if response.Code != http.StatusOK || response.Header().Get("Cache-Control") != "no-store" || json.Unmarshal(response.Body.Bytes(), &page) != nil || len(page.Items) != 1 {
			t.Fatal("invalid candidate response", response.Code)
		}
		authority := page.Items[0].OwnerAuthority
		if (authority != nil) != observed || observed && (!authority.ObservedAt.Equal(now) || !authority.ExpiresAt.Equal(now.Add(time.Minute))) {
			t.Fatal("candidate changed or fabricated an owner observation")
		}
		var raw struct {
			Items []map[string]json.RawMessage `json:"items"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &raw); err != nil {
			t.Fatal(err)
		}
		for field := range raw.Items[0] {
			if field != "pair_id" && field != "delivery_generation" && field != "owner_authority" {
				t.Fatal("candidate disclosed delivery or subject facts", field)
			}
		}
	}
}
