package integrationurls

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/publisher"
)

// Observer records a login before sending the authorization response to the browser.
func Observer(state *clientstate.Database, server, hostname, group, tunnelID string) publisher.ResponseObserver {
	return func(response *http.Response, run publisher.PublishRunIdentity) error {
		location, err := url.Parse(response.Header.Get("Location"))
		if err != nil || location.Scheme != "https" || location.Host == "" {
			return nil
		}
		query, err := url.ParseQuery(location.RawQuery)
		if err != nil || len(query["response_type"]) > 1 || len(query["response_type"]) == 1 && query.Get("response_type") != "code" {
			return nil
		}
		callback, err := url.Parse(query.Get("redirect_uri"))
		if err != nil || callback.Host != hostname {
			return nil
		}
		if len(query["state"]) != 1 || query.Get("state") == "" || len(query["state"][0]) > 8192 || len(query["redirect_uri"]) != 1 ||
			callback.Scheme != "https" || callback.User != nil || callback.Fragment != "" || callback.RawPath != "" || !localproxy.ValidMountPrefix(callback.Path) {
			return diagnostic.Wrap(diagnostic.RequestRejected, errors.New("invalid OAuth authorization redirect"))
		}
		static, err := url.ParseQuery(callback.RawQuery)
		if err != nil {
			return diagnostic.Wrap(diagnostic.RequestRejected, err)
		}
		for _, key := range []string{"state", "code", "error", "error_description", "iss"} {
			if _, found := static[key]; found {
				return diagnostic.Wrap(diagnostic.RequestRejected, errors.New("redirect URI contains an OAuth response parameter"))
			}
		}
		ctx, cancel := context.WithTimeout(response.Request.Context(), 2*time.Second)
		defer cancel()
		ready, err := state.IntegrationURLReady(ctx, server, hostname)
		if err != nil {
			return diagnostic.Wrap(diagnostic.OAuthCallbackUnavailable, err)
		}
		if !ready {
			return diagnostic.Wrap(diagnostic.OAuthCallbackUnavailable, errors.New("OAuth callback publisher is not ready"))
		}
		if err := state.SaveOAuthCallbackOrigin(ctx, server, hostname, group, query.Get("state"), tunnelID, callback.Path, callback.RawQuery, run.Hostname, run.PublicURLID, run.Number); err != nil {
			return diagnostic.Wrap(diagnostic.OAuthCallbackUnavailable, err)
		}
		return nil
	}
}

// OAuthHandler returns the browser to the same path on the originating worktree.
func OAuthHandler(state *clientstate.Database, server, hostname string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Cache-Control", "no-store")
		response.Header().Set("Referrer-Policy", "no-referrer")
		authority, err := naming.CanonicalizeAuthority(request.Host)
		if err != nil || authority != hostname {
			diagnostic.WriteHTTP(response, request, diagnostic.RequestMisdirected)
			return
		}
		query, err := url.ParseQuery(request.URL.RawQuery)
		if err != nil || request.Method != http.MethodGet || request.URL.RawPath != "" || !localproxy.ValidMountPrefix(request.URL.EscapedPath()) ||
			len(query["state"]) != 1 || query.Get("state") == "" || len(query.Get("state")) > 8192 {
			diagnostic.WriteHTTP(response, request, diagnostic.RequestRejected)
			return
		}
		callback, origin, err := state.ConsumeOAuthCallback(request.Context(), server, hostname, query.Get("state"), request.URL.EscapedPath())
		if err != nil {
			code := diagnostic.OAuthCallbackUnavailable
			if errors.Is(err, sql.ErrNoRows) {
				code = diagnostic.OAuthCallbackExpired
			}
			diagnostic.WriteHTTP(response, request, code)
			return
		}
		// providers already retain static redirect-URI query parameters. preserve
		// their response exactly instead of appending the static query a second time.
		http.Redirect(response, request, origin.PublicURL+callback.Path+"?"+request.URL.RawQuery, http.StatusSeeOther)
	})
}
