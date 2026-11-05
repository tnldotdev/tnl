package public

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectorPeerRebindFailsClosedUntilAuthorityIsWired(t *testing.T) {
	handler := testHandler(t, Config{}, nil, nil, nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost,
		"/v1/services/svc_1234567890123456789012/connector-peer-pairs/cpp_1234567890123456789012/rebind", nil))
	var problem controlv1.Problem
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil || response.Code != http.StatusServiceUnavailable ||
		problem.Code != controlv1.Unavailable || response.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("unwired rebind status=%d code=%s error=%v", response.Code, problem.Code, err)
	}
}
