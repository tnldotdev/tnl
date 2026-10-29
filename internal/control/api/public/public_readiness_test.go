package public

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicPreparationStore struct {
	Store
	ready bool
	calls int
}

func (*publicPreparationStore) PublishRunAuthentication(_ context.Context, id string, number uint64, token credentials.PublishRunToken) (controlstate.PublishRunAuthentication, error) {
	return controlstate.PublishRunAuthentication{PublishRunID: id, PublishRunNumber: number, PublishRunToken: token}, nil
}

func (s *publicPreparationStore) MarkPublishRunReady(_ context.Context, auth controlstate.PublishRunAuthentication, now time.Time) (controlstate.PublishRunLifecycle, error) {
	s.calls++
	if !s.ready {
		return controlstate.PublishRunLifecycle{}, controlstate.ErrPublishRunNotReady
	}
	return controlstate.PublishRunLifecycle{PublishRunID: auth.PublishRunID, PublishRunNumber: auth.PublishRunNumber, State: controlstate.PublishRunReady, ReadyAt: &now, CreatedAt: now}, nil
}

func TestPublicReadinessAPIHasOneFinalStateDecision(t *testing.T) {
	store := &publicPreparationStore{}
	h := handler{store: store}
	for _, ready := range []bool{false, true} {
		store.ready = ready
		request := httptest.NewRequest(http.MethodPost, "/v1/publish-runs/run/ready", strings.NewReader(`{"publish_run_number":1}`))
		request.Header.Set("Authorization", "Bearer publisher-token")
		response := httptest.NewRecorder()
		h.MarkPublishRunReady(response, request, "run")
		if !ready {
			if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), "not ready") {
				t.Fatalf("pending preparation: %d %s", response.Code, response.Body.String())
			}
			continue
		}
		var lifecycle controlv1.PublishRun
		if err := json.Unmarshal(response.Body.Bytes(), &lifecycle); err != nil || response.Code != http.StatusOK || lifecycle.ReadyAt == nil || lifecycle.State != controlv1.PublishRunStateReady {
			t.Fatalf("final readiness: %d %s, %v", response.Code, response.Body.String(), err)
		}
	}
	if store.calls != 2 {
		t.Fatalf("readiness made %d state decisions for two requests", store.calls)
	}
}
