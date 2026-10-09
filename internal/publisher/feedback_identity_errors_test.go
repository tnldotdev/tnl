package publisher

import (
	"context"
	"errors"
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
	calls    int
	required bool
	err      error
	body     controlv1.FeedbackAccessRequest
}

func (c *feedbackPolicyReader) GetFeedbackAccess(_ context.Context, _ string, body controlv1.FeedbackAccessRequest, _ credentials.PublishRunToken) (controlv1.FeedbackAccess, error) {
	c.calls++
	c.body = body
	return controlv1.FeedbackAccess{RequireSignIn: c.required}, c.err
}

func TestReadyFeedbackPolicyDistinguishesOptionalRequiredAndUnavailable(t *testing.T) {
	for _, required := range []bool{false, true} {
		client := &feedbackPolicyReader{required: required}
		runtime := &feedbackRuntime{client: client, previewID: "preview", runID: "run", version: 7}
		policy := runtime.readyPolicy(t.Context())
		if policy == nil || *policy != required || client.calls != 1 || client.body.PreviewId != "preview" || client.body.PublishRunNumber != 7 || !client.body.Access.AllowedIp || client.body.Access.BrowserCookieSecret != nil {
			t.Fatalf("ready policy = %v, request %+v", policy, client.body)
		}
		client.err = errors.New("policy unavailable")
		if runtime.readyPolicy(t.Context()) != nil {
			t.Fatal("failed policy lookup was presented as optional sign-in")
		}
	}
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
