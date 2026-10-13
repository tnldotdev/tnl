package controlclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestFeedbackSignInProblemPreservesDistinctCause(t *testing.T) {
	payload, err := json.Marshal(controlv1.Problem{Code: controlv1.FeedbackSignInRequired, Title: "sign in to leave feedback", Status: 401})
	if err != nil {
		t.Fatal(err)
	}
	err = responseError(http.StatusUnauthorized, nil, payload)
	var problem *ProblemError
	if !errors.Is(err, ErrFeedbackSignInRequired) || errors.Is(err, ErrUnauthenticated) || !errors.As(err, &problem) || problem.Status != 401 {
		t.Fatalf("feedback problem cause=%v", err)
	}
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.FeedbackSignInRequired {
		t.Fatalf("reason=%s", reason)
	}
}
