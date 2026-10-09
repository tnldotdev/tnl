package publisher

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
)

type feedbackAccessClient interface {
	GetFeedbackAccess(context.Context, string, controlv1.FeedbackAccessRequest, credentials.PublishRunToken) (controlv1.FeedbackAccess, error)
}

func feedbackBrowserCredential(request *http.Request) (string, bool, bool) {
	cookies := request.CookiesNamed(browserAccessCookieName)
	if len(cookies) == 0 {
		// net/http skips malformed cookie values; retain their presence for writes.
		for _, header := range request.Header.Values("Cookie") {
			for _, field := range strings.Split(header, ";") {
				name, _, _ := strings.Cut(strings.TrimSpace(field), "=")
				if name == browserAccessCookieName {
					return "", true, false
				}
			}
		}
		return "", false, false
	}
	if len(cookies) != 1 {
		return "", true, false
	}
	secret := cookies[0].Value
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	return secret, true, err == nil && len(raw) == 32 && base64.RawURLEncoding.EncodeToString(raw) == secret
}

func (f *feedbackRuntime) access(response http.ResponseWriter, request *http.Request, access controlv1.FeedbackReviewerAccess) {
	client, ok := f.client.(feedbackAccessClient)
	if !ok {
		http.Error(response, "feedback policy is unavailable", http.StatusServiceUnavailable)
		return
	}
	result := publisherv1.BrowserFeedbackAccess{IdentityState: publisherv1.Anonymous, SignInAvailable: f.browser != nil}
	secret, present, valid := feedbackBrowserCredential(request)
	if present {
		if !valid {
			result.IdentityState = publisherv1.Expired
		} else {
			identity, verified := request.Context().Value(browserIdentityKey{}).(controlv1.BrowserAccessResponse)
			var err error
			if !verified {
				if f.identityClient == nil {
					http.Error(response, "browser identity is unavailable", http.StatusServiceUnavailable)
					return
				}
				identity, err = f.identityClient.CheckBrowserAccess(request.Context(), f.runID, f.version, secret, f.token)
			}
			var problem *controlclient.ProblemError
			if errors.Is(err, controlclient.ErrUnauthenticated) || errors.As(err, &problem) && problem.Status == http.StatusForbidden && problem.Problem.Code == controlv1.Forbidden {
				result.IdentityState = publisherv1.Expired
			} else if err != nil {
				http.Error(response, "browser identity is unavailable", http.StatusServiceUnavailable)
				return
			} else if identity.IdentityId == "" || strings.TrimSpace(identity.DisplayName) == "" || utf8.RuneCountInString(identity.IdentityId) > 256 || utf8.RuneCountInString(identity.DisplayName) > 256 {
				http.Error(response, "browser identity is unavailable", http.StatusServiceUnavailable)
				return
			} else {
				result.IdentityState = publisherv1.SignedIn
				result.Identity = &publisherv1.BrowserIdentity{IdentityId: identity.IdentityId, DisplayName: identity.DisplayName}
				access.BrowserCookieSecret = &secret
			}
		}
		if result.IdentityState == publisherv1.Expired {
			access.BrowserCookieSecret = nil
		}
	}
	policy, err := client.GetFeedbackAccess(request.Context(), f.runID, controlv1.FeedbackAccessRequest{
		PreviewId: f.previewID, PublishRunNumber: int64(f.version), Access: access,
	}, f.token)
	if err != nil {
		f.writeResult(response, nil, err)
		return
	}
	result.RequireSignIn = policy.RequireSignIn
	f.writeResult(response, result, nil)
}

// an author expectation only constrains a write; current control-validated
// identity and policy still authorize it. this fences a cookie change between
// the toolbar's preflight and the actual request, including an uncertain retry.
func (f *feedbackRuntime) postingIdentity(response http.ResponseWriter, request *http.Request, expected *string) bool {
	if expected == nil {
		return true
	}
	if len(*expected) > 300 || *expected != "anonymous" && (!strings.HasPrefix(*expected, "identity:") || len(*expected) == len("identity:")) {
		http.Error(response, "invalid posting identity", http.StatusBadRequest)
		return false
	}
	secret, present, valid := feedbackBrowserCredential(request)
	actual := "anonymous"
	if present {
		if !valid {
			http.Error(response, "browser sign-in expired; sign in again", http.StatusUnauthorized)
			return false
		}
		identity, verified := request.Context().Value(browserIdentityKey{}).(controlv1.BrowserAccessResponse)
		if !verified {
			if f.identityClient == nil {
				http.Error(response, "browser identity is unavailable", http.StatusServiceUnavailable)
				return false
			}
			var err error
			identity, err = f.identityClient.CheckBrowserAccess(request.Context(), f.runID, f.version, secret, f.token)
			if err != nil {
				if errors.Is(err, controlclient.ErrUnauthenticated) {
					http.Error(response, "sign in to leave feedback", http.StatusUnauthorized)
				} else {
					f.writeResult(response, nil, err)
				}
				return false
			}
		}
		if identity.IdentityId == "" {
			http.Error(response, "browser identity is unavailable", http.StatusServiceUnavailable)
			return false
		}
		actual = "identity:" + identity.IdentityId
	}
	if actual != *expected {
		if actual == "anonymous" {
			http.Error(response, "sign in to leave feedback", http.StatusUnauthorized)
			return false
		}
		http.Error(response, "posting identity changed; review feedback before retrying", http.StatusConflict)
		return false
	}
	return true
}
