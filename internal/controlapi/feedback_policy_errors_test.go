package controlapi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
)

type feedbackBrowserFailureStore struct {
	BrowserAccessStore
	err error
}

func (s feedbackBrowserFailureStore) BrowserSession(context.Context, string, string, time.Time) (controlstate.BrowserAccessSession, error) {
	return controlstate.BrowserAccessSession{}, s.err
}

func TestFeedbackBrowserFailuresPreserveCauseAndHTTPMeaning(t *testing.T) {
	for _, test := range []struct {
		cause  error
		status int
	}{
		{controlstate.ErrPreviewAccess, 403},
		{authorization.ErrUnauthenticated, 403},
		{authorityclient.ErrUnauthenticated, 403},
		{authorization.ErrUnavailable, 503},
		{authorityclient.ErrUnavailable, 503},
	} {
		cause := errors.Join(test.cause, errors.New("issuer-and-credential-secret"))
		h := &handler{browserAccess: feedbackBrowserFailureStore{err: cause}, authorizer: &recordingAuthorizer{}}
		_, err := h.feedbackBrowserActor(httptest.NewRequest("POST", "/", nil), controlstate.PublishRunAuthentication{}, controlstate.FeedbackActor{Kind: "reviewer", BrowserCookieSecret: make([]byte, 32)})
		if !errors.Is(err, cause) {
			t.Fatalf("lost browser cause: %v", err)
		}
		response := httptest.NewRecorder()
		writeControlStateProblem(response, "verify reviewer", err)
		if response.Code != test.status || strings.Contains(response.Body.String(), "issuer-and-credential-secret") {
			t.Fatalf("response=%d %s", response.Code, response.Body.String())
		}
	}
	response := httptest.NewRecorder()
	writeControlStateProblem(response, "write reviewer feedback", controlstate.ErrFeedbackSignInRequired)
	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"feedback_sign_in_required"`) {
		t.Fatalf("sign-in problem=%d %s", response.Code, response.Body.String())
	}
}
