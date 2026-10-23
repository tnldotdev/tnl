package publisher

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const browserAccessCookieName = "__Host-tnl-browser"
const shareAccessHeaderName = "Tnl-Share-Token"

type browserAccessClient interface {
	RedeemBrowserHandoff(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error)
	CheckBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error)
	RevokeBrowserAccess(context.Context, string, uint64, string, credentials.PublishRunToken) error
}

type browserAccess struct {
	subject                                   visitorscope.Scope
	client                                    browserAccessClient
	previewID, publicURLID, runID, controlURL string
	version                                   uint64
	token                                     credentials.PublishRunToken
	tokens                                    *browserTokens
	policy                                    *visitorPolicy
}

func browserAccessForRun(config Config, setup controlv1.PublishRunSetup, token credentials.PublishRunToken) *browserAccess {
	if !strings.HasPrefix(config.ControlURL, "https://") || setup.PublicUrl.ServiceProtocol != controlv1.Http {
		return nil
	}
	var candidate any = config.Control
	if config.VisitorControl != nil {
		candidate = config.VisitorControl
	}
	client, ok := candidate.(browserAccessClient)
	if !ok {
		return nil
	}
	return &browserAccess{subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: setup.PublicUrl.Id}, client: client, previewID: config.PreviewID, publicURLID: setup.PublicUrl.Id,
		runID: setup.PublishRun.Id, version: uint64(setup.PublishRun.PublishRunNumber), token: token,
		controlURL: config.ControlURL}
}

func browserCookie(response http.ResponseWriter, secret string, expires time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: browserAccessCookieName, Value: secret, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: expires,
	})
}

func (a *browserAccess) checkCurrent(request *http.Request) (controlv1.BrowserAccessResponse, error) {
	cookie, err := request.Cookie(browserAccessCookieName)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, errors.New("browser sign-in is missing")
	}
	raw, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(raw) != 32 {
		return controlv1.BrowserAccessResponse{}, errors.New("browser sign-in is invalid")
	}
	result, err := a.client.CheckBrowserAccess(request.Context(), a.runID, a.version, cookie.Value, a.token)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	if result.IdentityId == "" || result.DisplayName == "" {
		return controlv1.BrowserAccessResponse{}, errors.New("browser identity is invalid")
	}
	return result, nil
}

func (a *browserAccess) handle(response http.ResponseWriter, request *http.Request) bool {
	const root = "/__tnl/team/"
	if !strings.HasPrefix(request.URL.Path, root) {
		return false
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	switch {
	case request.URL.Path == root+"login" && request.Method == http.MethodGet:
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
		if a.previewID != "" {
			query.Set("preview_id", a.previewID)
		}
		if request.URL.Query().Get("switch") == "1" {
			query.Set("switch_account", "true")
		}
		if a.subject.Kind == visitorscope.Service {
			endpoint.Path = "/v1/browser/service-login"
			query.Set("service_id", a.subject.ID)
		} else {
			query.Set("public_url_id", a.publicURLID)
		}
		query.Set("return_path", path)
		endpoint.RawQuery = query.Encode()
		markBrowserLoginAttempt(response)
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
		if a.tokens != nil {
			source, err := json.Marshal(controlv1.VisitorTokenBrowserSessionSource{Kind: controlv1.VisitorTokenBrowserSession, Secret: result.CookieSecret})
			if err == nil {
				err = a.prepareToken(request.Context(), source, result.Permission, result.ExpiresAt)
			}
			if err != nil {
				http.Error(response, "browser visitor permission is unavailable", http.StatusServiceUnavailable)
				return true
			}
		}
		if err := visitorPermissionCookie(response, result.Permission); err != nil {
			http.Error(response, "browser visitor permission is unavailable", http.StatusServiceUnavailable)
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
		if _, err := request.Cookie(browserAccessCookieName); err != nil {
			httpjson.Write(response, http.StatusOK, struct {
				SignedIn bool `json:"signed_in"`
			}{})
			return true
		}
		result, err := a.checkCurrent(request)
		if err != nil {
			status := http.StatusServiceUnavailable
			if errors.Is(err, clientcontrol.ErrUnauthenticated) {
				status = http.StatusUnauthorized
			}
			http.Error(response, "could not check browser sign-in; retry", status)
			return true
		}
		httpjson.Write(response, http.StatusOK, struct {
			SignedIn     bool   `json:"signed_in"`
			DisplayName  string `json:"display_name"`
			TeamMember   bool   `json:"team_member"`
			VisitAllowed bool   `json:"visit_allowed"`
		}{SignedIn: true, DisplayName: result.DisplayName, TeamMember: result.TeamMember, VisitAllowed: result.VisitAllowed})
		return true
	case (request.URL.Path == root+"logout" || request.URL.Path == root+"switch") && request.Method == http.MethodPost:
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
		http.SetCookie(response, &http.Cookie{Name: visitorTokenCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
		if request.URL.Path == root+"switch" {
			path := request.URL.Query().Get("return")
			if path == "" {
				path = "/"
			}
			if !validBrowserPath(path) {
				http.Error(response, "invalid return path", http.StatusBadRequest)
				return true
			}
			http.Redirect(response, request, root+"login?switch=1&return="+url.QueryEscape(path), http.StatusSeeOther)
		} else {
			response.WriteHeader(http.StatusNoContent)
		}
		return true
	default:
		http.NotFound(response, request)
		return true
	}
}

func (a *browserAccess) prepareToken(ctx context.Context, source json.RawMessage, permission controlv1.VisitorTokenResponse, parent time.Time) error {
	if a.policy == nil || a.tokens == nil {
		return errors.New("browser token preparation is unavailable")
	}
	if err := a.tokens.install(source, permission, parent); err == nil {
		return nil
	}
	// redemption is explicit credential preparation. a new revision or signing
	// key is loaded here, before redirecting to an ordinary application request.
	if err := a.policy.refresh(ctx); err != nil {
		return err
	}
	return a.tokens.install(source, permission, parent)
}

func validBrowserPath(path string) bool {
	if path == "" || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n#\x00") {
		return false
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && !strings.HasPrefix(parsed.Path, "//") && !strings.ContainsAny(parsed.Path, "\\\r\n\x00") && !strings.HasPrefix(parsed.Path, "/__tnl/")
}
