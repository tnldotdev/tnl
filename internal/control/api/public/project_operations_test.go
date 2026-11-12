package public

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestProjectConfigurationPoolConflict(t *testing.T) {
	w := httptest.NewRecorder()
	projectOperationProblem(t.Context(), w, "allocate environment service", fmt.Errorf("allocation: %w", controlstate.ErrServicePoolPinned))
	var problem controlv1.Problem
	if err := json.Unmarshal(w.Body.Bytes(), &problem); err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusConflict || problem.Code != controlv1.Conflict || problem.RetryAt != nil ||
		problem.Detail != "service port reservation belongs to another ingress pool; keep its saved pool or create a separate service" {
		t.Fatal("pool conflict lost its classification or next action", w.Code, problem)
	}
}
