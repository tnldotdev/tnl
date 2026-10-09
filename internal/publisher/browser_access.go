package publisher

import (
	"context"
	"encoding/base64"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

const browserAccessCookieName = "__Host-tnl-browser"

type browserAccessClient interface {
	RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error)
	CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error)
	RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
}

type browserAccess struct {
	client                                    browserAccessClient
	previewID, publicURLID, runID, controlURL string
	version                                   uint64
	token                                     credentials.PublishRunToken
	shares                                    *shareAccess
}

type browserIdentityKey struct{}

func browserAccessForRun(config Config, setup controlv1.PublishRunSetup, token credentials.PublishRunToken, shares *shareAccess) *browserAccess {
	if config.PreviewID == "" || config.Demo || !config.BrowserLoginAvailable || !strings.HasPrefix(config.ControlURL, "https://") || shares == nil {
		return nil
	}
	client, ok := config.Control.(browserAccessClient)
	if !ok {
		return nil
	}
	return &browserAccess{client: client, previewID: config.PreviewID, publicURLID: setup.PublicUrl.Id,
		runID: setup.PublishRun.Id, version: uint64(setup.PublishRun.PublishRunNumber), token: token,
		controlURL: config.ControlURL, shares: shares}
}

func browserCookie(response http.ResponseWriter, secret string, expires time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: browserAccessCookieName, Value: secret, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: expires,
	})
}

func (a *browserAccess) check(request *http.Request) (controlv1.BrowserAccessResponse, bool) {
	cookie, err := request.Cookie(browserAccessCookieName)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(raw) != 32 {
		return controlv1.BrowserAccessResponse{}, false
	}
	result, err := a.client.CheckBrowserAccess(request.Context(), a.runID, a.version, cookie.Value, a.token)
	if err != nil || result.IdentityId == "" || result.DisplayName == "" {
		return controlv1.BrowserAccessResponse{}, false
	}
	return result, true
}

func (a *browserAccess) handle(response http.ResponseWriter, request *http.Request, permitted bool) bool {
	const root = "/__tnl/team/"
	if !strings.HasPrefix(request.URL.Path, root) {
		return false
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	switch {
	case request.URL.Path == root+"login" && request.Method == http.MethodGet:
		if !permitted && !a.shares.permitsTeamLogin() {
			http.Error(response, "team sign-in is not enabled for this preview", http.StatusForbidden)
			return true
		}
		path := request.URL.Query().Get("return")
		if path == "" {
			path = "/"
		}
		if !validBrowserPath(path) {
			http.Error(response, "invalid return path", http.StatusBadRequest)
			return true
		}
		endpoint, err := url.Parse(a.controlURL + "/v1/browser/login")
		if err != nil {
			http.Error(response, "sign-in is unavailable", http.StatusServiceUnavailable)
			return true
		}
		query := endpoint.Query()
		query.Set("preview_id", a.previewID)
		query.Set("public_url_id", a.publicURLID)
		query.Set("return_path", path)
		endpoint.RawQuery = query.Encode()
		http.Redirect(response, request, endpoint.String(), http.StatusSeeOther)
		return true
	case strings.HasPrefix(request.URL.Path, root+"handoff/") && request.Method == http.MethodGet:
		ticket := strings.TrimPrefix(request.URL.Path, root+"handoff/")
		raw, err := base64.RawURLEncoding.DecodeString(ticket)
		if err != nil || len(raw) != 32 {
			http.NotFound(response, request)
			return true
		}
		result, err := a.client.RedeemBrowserHandoff(request.Context(), a.runID, a.version, ticket, a.token)
		if err != nil || !validBrowserPath(result.ReturnPath) {
			http.Error(response, "browser sign-in expired", http.StatusForbidden)
			return true
		}
		browserCookie(response, result.CookieSecret, result.ExpiresAt)
		next := result.ReturnPath
		if result.NextUrl != nil {
			parsed, err := url.Parse(*result.NextUrl)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || len(*result.NextUrl) > 4096 {
				http.Error(response, "invalid browser handoff", http.StatusServiceUnavailable)
				return true
			}
			next = *result.NextUrl
		}
		if result.Bridge != nil && *result.Bridge {
			response.Header().Set("Content-Type", "text/html; charset=utf-8")
			response.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'")
			response.WriteHeader(http.StatusOK)
			link := html.EscapeString(next)
			_, _ = io.WriteString(response, `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="refresh" content="0;url=`+link+`"><title>tnl preview</title></head><body><a href="`+link+`">continue to the preview</a></body></html>`)
			return true
		}
		http.Redirect(response, request, next, http.StatusSeeOther)
		return true
	case request.URL.Path == root+"session" && request.Method == http.MethodGet:
		result, ok := a.check(request)
		if !ok {
			httpjson.Write(response, http.StatusOK, struct {
				SignedIn bool `json:"signed_in"`
			}{})
			return true
		}
		httpjson.Write(response, http.StatusOK, struct {
			SignedIn     bool   `json:"signed_in"`
			DisplayName  string `json:"display_name"`
			VisitAllowed bool   `json:"visit_allowed"`
		}{SignedIn: true, DisplayName: result.DisplayName, VisitAllowed: result.VisitAllowed})
		return true
	case request.URL.Path == root+"logout" && request.Method == http.MethodPost:
		if request.Header.Get("Origin") != "https://"+request.Host {
			http.Error(response, "invalid logout origin", http.StatusForbidden)
			return true
		}
		if cookie, err := request.Cookie(browserAccessCookieName); err == nil {
			if err := a.client.RevokeBrowserAccess(request.Context(), a.runID, a.version, cookie.Value, a.token); err != nil {
				http.Error(response, "could not sign out", http.StatusServiceUnavailable)
				return true
			}
		}
		http.SetCookie(response, &http.Cookie{Name: browserAccessCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
		response.WriteHeader(http.StatusNoContent)
		return true
	default:
		http.NotFound(response, request)
		return true
	}
}

func validBrowserPath(path string) bool {
	return path != "" && len(path) <= 2048 && strings.HasPrefix(path, "/") && !strings.HasPrefix(path, "//") && !strings.ContainsAny(path, "\\\r\n#")
}
