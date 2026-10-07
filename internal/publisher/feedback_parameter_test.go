package publisher

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFeedbackParameterErrorsDoNotEchoVisitorInput(t *testing.T) {
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/__tnl/feedback/fb_example/events?after_cursor=private-test-secret", nil)
	newFeedbackHandler(nil).ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || response.Body.String() != "invalid feedback parameter\n" || strings.Contains(response.Body.String(), "private-test-secret") {
		t.Fatalf("feedback parameter failure = %d %q", response.Code, response.Body.String())
	}
}
