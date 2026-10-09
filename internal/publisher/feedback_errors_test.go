package publisher

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestFeedbackErrorsKeepSignInAccessAndAvailabilityDistinct(t *testing.T) {
	for _, test := range []struct {
		err     error
		status  int
		message string
	}{
		{errors.Join(errors.New("credential-secret"), controlclient.ErrFeedbackSignInRequired), 401, "sign in to leave feedback"},
		{&controlclient.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Title: "credential-secret"}}, 403, "feedback requires current preview access"},
		{errors.Join(errors.New("credential-secret"), controlclient.ErrUnavailable), 503, "feedback request failed; retry"},
	} {
		response := httptest.NewRecorder()
		(&feedbackRuntime{}).writeResult(response, nil, test.err)
		if response.Code != test.status || strings.TrimSpace(response.Body.String()) != test.message || strings.Contains(response.Body.String(), "credential-secret") {
			t.Fatalf("feedback error=%d %q", response.Code, response.Body.String())
		}
	}
}
