package publisher

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/sourcestate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/publisherv1"
)

type feedbackRequestContextKey struct{}

type feedbackRequestContext struct {
	browser [32]byte
	method  string
	path    string
	started time.Time
}

type failedRequest = publisherv1.BrowserFailedRequest

type browserTrail struct {
	lastSeen time.Time
	failures []failedRequest
}

func (f *feedbackRuntime) prepareBrowser(response http.ResponseWriter, request *http.Request) *http.Request {
	var raw []byte
	if cookie, err := request.Cookie(feedbackBrowserCookieName); err == nil {
		raw, _ = base64.RawURLEncoding.DecodeString(cookie.Value)
	}
	if len(raw) != 32 {
		raw = make([]byte, 32)
		if _, err := rand.Read(raw); err != nil {
			return request
		}
		http.SetCookie(response, &http.Cookie{
			Name: feedbackBrowserCookieName, Value: base64.RawURLEncoding.EncodeToString(raw),
			Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
			Expires: time.Now().Add(24 * time.Hour),
		})
	}
	key := sha256.Sum256(raw)
	return request.WithContext(context.WithValue(request.Context(), feedbackRequestContextKey{}, feedbackRequestContext{
		browser: key, method: request.Method, path: request.URL.Path, started: time.Now(),
	}))
}

func (f *feedbackRuntime) observe(request *http.Request, status int) {
	if request == nil || status > 0 && status < 400 {
		return
	}
	info, ok := request.Context().Value(feedbackRequestContextKey{}).(feedbackRequestContext)
	if !ok || !strings.HasPrefix(info.path, "/") || len(info.path) > 2048 {
		return
	}
	entry := failedRequest{
		Method: info.method, Path: info.path, Status: status,
		DurationMs: int(min(time.Since(info.started).Milliseconds(), 600000)),
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	trail := f.browsers[info.browser]
	if trail == nil {
		if len(f.browsers) >= maximumFeedbackBrowsers {
			var oldest [32]byte
			var at time.Time
			for key, candidate := range f.browsers {
				if at.IsZero() || candidate.lastSeen.Before(at) {
					oldest, at = key, candidate.lastSeen
				}
			}
			delete(f.browsers, oldest)
		}
		trail = &browserTrail{}
		f.browsers[info.browser] = trail
	}
	trail.lastSeen = time.Now()
	trail.failures = append(trail.failures, entry)
	if len(trail.failures) > maximumFailedRequests {
		trail.failures = trail.failures[len(trail.failures)-maximumFailedRequests:]
	}
}

func (f *feedbackRuntime) evidenceForBrowser(request *http.Request) []failedRequest {
	result := make([]failedRequest, 0)
	cookie, err := request.Cookie(feedbackBrowserCookieName)
	if err != nil {
		return result
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(raw) != 32 {
		return result
	}
	key := sha256.Sum256(raw)
	f.mu.Lock()
	defer f.mu.Unlock()
	if trail := f.browsers[key]; trail != nil && time.Since(trail.lastSeen) < 15*time.Minute {
		result = append(result, trail.failures...)
	}
	return result
}

func (f *feedbackRuntime) sourceState(ctx context.Context) (controlv1.SourceState, error) {
	if !f.demo {
		return sourcestate.Capture(ctx, f.projectRoot)
	}
	return controlv1.SourceState{SchemaVersion: 1, ChangedFiles: []controlv1.SourceFileState{}, Complete: false}, nil
}
