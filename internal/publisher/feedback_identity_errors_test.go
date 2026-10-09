package publisher

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type feedbackIdentityFailure struct{ err error }

func (c feedbackIdentityFailure) CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error) {
	return controlv1.BrowserAccessResponse{}, c.err
}

type feedbackPolicyReader struct {
	feedbackClient
	calls int
}

func (c *feedbackPolicyReader) GetFeedbackAccess(context.Context, string, controlv1.FeedbackAccessRequest, credentials.PublishRunToken) (controlv1.FeedbackAccess, error) {
	c.calls++
	return controlv1.FeedbackAccess{}, nil
}

func TestFeedbackMetadataPreservesUnexpectedIdentityRejections(t *testing.T) {
	for _, code := range []controlv1.ProblemCode{controlv1.Forbidden, controlv1.InvalidRequest, "future_code", ""} {
		t.Run(string(code), func(t *testing.T) {
			client := &feedbackPolicyReader{}
			runtime := &feedbackRuntime{
				client: client, browser: &browserAccess{},
				identityClient: feedbackIdentityFailure{err: &controlclient.ProblemError{
					Status:  http.StatusForbidden,
					Problem: controlv1.Problem{Code: code, Detail: "private identity error"},
				}},
			}
			request := httptest.NewRequest(http.MethodGet, "/__tnl/feedback/access", nil)
			request.AddCookie(&http.Cookie{Name: browserAccessCookieName, Value: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})
			response := httptest.NewRecorder()
			runtime.access(response, request, controlv1.FeedbackReviewerAccess{AllowedIp: true})
			if code == controlv1.Forbidden {
				if response.Code != http.StatusOK || client.calls != 1 || !strings.Contains(response.Body.String(), `"identity_state":"expired"`) {
					t.Fatalf("expired session = %d %s; policy calls %d", response.Code, response.Body.String(), client.calls)
				}
			} else if response.Code != http.StatusServiceUnavailable || client.calls != 0 {
				t.Fatalf("unexpected identity rejection = %d %s; policy calls %d", response.Code, response.Body.String(), client.calls)
			}
			if strings.Contains(response.Body.String(), "private identity error") {
				t.Fatal("identity error detail was exposed")
			}
		})
	}
}
