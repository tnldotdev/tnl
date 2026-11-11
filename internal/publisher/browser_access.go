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
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const browserAccessCookieName = "__Host-tnl-browser"
const shareAccessHeaderName = "Tnl-Share-Token"

type browserAccessClient interface {
	RedeemBrowserHandoff(context.Context, string, uint64, string, string, string, credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error)
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
	controlURL, err := naming.CanonicalControlURL(config.ControlURL)
	if err != nil || setup.PublicUrl.ServiceProtocol != controlv1.Http {
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
		controlURL: controlURL}
}

func browserCookie(response http.ResponseWriter, secret string, expires time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: browserAccessCookieName, Value: secret, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: expires,
	})
}

func shareSessionCookie(request *http.Request) (string, string, error) {
	count := suppliedCookieCount(request, shareCookieName)
	if count == 0 {
		return "", "", nil
	}
	cookies := request.CookiesNamed(shareCookieName)
	if count != 1 || len(cookies) != 1 {
		return "", "", visitortoken.ErrToken
	}
	id, secret, found := strings.Cut(cookies[0].Value, ".")
	raw, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if !found || !opaqueid.Valid(id, opaqueid.SharePrefix) || err != nil || len(raw) != 32 {
		return "", "", visitortoken.ErrToken
	}
	return id, secret, nil
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
		shareID, shareSecret, shareErr := "", "", error(nil)
		if a.subject.Kind == visitorscope.PublicURL {
			shareID, shareSecret, shareErr = shareSessionCookie(request)
		}
		if shareErr != nil {
			http.Error(response, "invalid share session", http.StatusForbidden)
			return true
		}
		result, err := a.client.RedeemBrowserHandoff(request.Context(), a.runID, a.version, ticket, shareID, shareSecret, a.token)
		if err != nil || !validBrowserPath(result.ReturnPath) {
			http.Error(response, "browser sign-in expired", http.StatusForbidden)
			return true
		}
		if a.tokens != nil {
			permission, verifyErr := a.tokens.verify(result.Permission, result.ExpiresAt)
			if verifyErr != nil && a.policy != nil {
				if refreshErr := a.policy.refresh(request.Context()); refreshErr == nil {
					permission, verifyErr = a.tokens.verify(result.Permission, result.ExpiresAt)
				}
			}
			if errors.Is(verifyErr, visitortoken.ErrPolicy) && permission.Valid() {
				// signature and response binding identify the source. preparation
				// below must obtain current permission before installing its cookie.
				verifyErr = nil
			}
			source, sourceErr := json.Marshal(controlv1.VisitorTokenBrowserSessionSource{Kind: controlv1.VisitorTokenBrowserSession, Secret: result.CookieSecret})
			if verifyErr == nil {
				if share, ok := permission.Facts().Subject.(visitortoken.Share); ok && share.ShareID == shareID && shareSecret != "" {
					source, sourceErr = json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: shareID, Secret: shareSecret})
				} else if _, ok := permission.Facts().Subject.(visitortoken.Browser); !ok {
					sourceErr = visitortoken.ErrBinding
				}
			}
			err = verifyErr
			if err == nil {
				err = sourceErr
			}
			if err == nil {
				if shareID != "" && permission.Facts().Subject == (visitortoken.Share{ShareID: shareID}) {
					result.Permission, err = a.prepareSessionToken(request.Context(), source, result.Permission)
				} else {
					result.Permission, err = a.prepareToken(request.Context(), source, result.Permission, result.ExpiresAt)
				}
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
	case request.URL.Path == root+"renew" && request.Method == http.MethodGet:
		path := request.URL.Query().Get("return")
		if a.tokens == nil || !validBrowserPath(path) || request.Header.Get(visitorTokenHeader) != "" || request.Header.Get(shareAccessHeaderName) != "" {
			http.Error(response, "invalid visitor renewal", http.StatusBadRequest)
			return true
		}
		shareID, secret, err := shareSessionCookie(request)
		if a.subject.Kind == visitorscope.Service {
			shareID, secret, err = "", "", nil
			cookies := request.CookiesNamed(shareCookieName)
			if suppliedCookieCount(request, shareCookieName) != len(cookies) || len(cookies) > 1 {
				err = visitortoken.ErrToken
			}
			if len(cookies) == 1 {
				shareID, secret = "service", cookies[0].Value
			}
		}
		if err != nil {
			http.Error(response, "invalid share session", http.StatusForbidden)
			return true
		}
		var source json.RawMessage
		if shareID == "service" {
			source, err = json.Marshal(controlv1.VisitorTokenGrantSource{Kind: controlv1.VisitorTokenGrant, Credential: secret})
		} else if shareID != "" {
			source, err = json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: shareID, Secret: secret})
		} else {
			source, err = browserSessionSource(request)
			if err != nil {
				http.Error(response, "invalid browser sign-in", http.StatusForbidden)
				return true
			}
		}
		if err != nil {
			http.Error(response, "invalid visitor renewal", http.StatusBadRequest)
			return true
		}
		issue := func(source json.RawMessage) (controlv1.VisitorTokenResponse, error) {
			return a.tokens.client.IssueVisitorToken(request.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(a.subject.Kind), Id: a.subject.ID}, Source: source})
		}
		result, err := issue(source)
		// a revoked share does not revoke an independent browser sign-in. only
		// an explicit denial permits another source; outages remain unavailable.
		if shareID != "" && browserTokenDenied(err) {
			if browserSource, sourceErr := browserSessionSource(request); sourceErr == nil {
				source = browserSource
				result, err = issue(source)
			}
		}
		if err != nil {
			status := http.StatusForbidden
			message := "visitor session expired; sign in or reopen the share"
			var problem *clientcontrol.ProblemError
			if errors.Is(err, clientcontrol.ErrUnavailable) || errors.As(err, &problem) && problem != nil && problem.Status >= http.StatusInternalServerError {
				status, message = http.StatusServiceUnavailable, "visitor permission is unavailable; retry"
			}
			http.Error(response, message, status)
			return true
		}
		result, err = a.prepareSessionToken(request.Context(), source, result)
		if err != nil || visitorPermissionCookie(response, result) != nil {
			http.Error(response, "visitor permission is unavailable", http.StatusServiceUnavailable)
			return true
		}
		http.Redirect(response, request, path, http.StatusSeeOther)
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

func browserSessionSource(request *http.Request) (json.RawMessage, error) {
	cookies := request.CookiesNamed(browserAccessCookieName)
	if suppliedCookieCount(request, browserAccessCookieName) != 1 || len(cookies) != 1 {
		return nil, visitortoken.ErrToken
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(cookies[0].Value); err != nil || len(raw) != 32 {
		return nil, visitortoken.ErrToken
	}
	return json.Marshal(controlv1.VisitorTokenBrowserSessionSource{Kind: controlv1.VisitorTokenBrowserSession, Secret: cookies[0].Value})
}

func (a *browserAccess) prepareToken(ctx context.Context, source json.RawMessage, permission controlv1.VisitorTokenResponse, parent time.Time) (controlv1.VisitorTokenResponse, error) {
	return a.preparePermission(ctx, source, permission, parent, false)
}

func (a *browserAccess) prepareSessionToken(ctx context.Context, source json.RawMessage, permission controlv1.VisitorTokenResponse) (controlv1.VisitorTokenResponse, error) {
	return a.preparePermission(ctx, source, permission, permission.ExpiresAt, true)
}

func (a *browserAccess) preparePermission(ctx context.Context, source json.RawMessage, permission controlv1.VisitorTokenResponse, parent time.Time, session bool) (controlv1.VisitorTokenResponse, error) {
	if a.policy == nil || a.tokens == nil {
		return controlv1.VisitorTokenResponse{}, errors.New("browser token preparation is unavailable")
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	for range 3 {
		if err := refreshContextError(call); err != nil {
			return controlv1.VisitorTokenResponse{}, err
		}
		if session {
			parent = permission.ExpiresAt
		}
		install := func() error { return a.tokens.installSource(source, permission, parent, session) }
		if err := install(); err == nil {
			return permission, nil
		} else if !errors.Is(err, visitortoken.ErrPolicy) && !errors.Is(err, visitortoken.ErrKey) {
			return controlv1.VisitorTokenResponse{}, err
		}
		// only explicit credential preparation fetches policy. ordinary app
		// requests cannot wait for policy or issue another visitor permission.
		if err := a.policy.refresh(call); err != nil {
			return controlv1.VisitorTokenResponse{}, err
		}
		if err := refreshContextError(call); err != nil {
			return controlv1.VisitorTokenResponse{}, err
		}
		if err := install(); err == nil {
			return permission, nil
		}
		proof, err := a.tokens.verify(permission, parent)
		view, enabled, _ := a.policy.lease.Current()
		if !errors.Is(err, visitortoken.ErrPolicy) || !proof.Valid() || !enabled || proof.Facts().VisitorPolicyRevision >= view.VisitorPolicyRevision {
			if err == nil {
				err = visitortoken.ErrPolicy
			}
			return controlv1.VisitorTokenResponse{}, err
		}
		// policy can advance after control redeemed the session. the signed old
		// token proves its subject, not current access; control must authorize a
		// replacement for that same session before any cookie is installed.
		next, err := a.tokens.client.IssueVisitorToken(call, controlv1.VisitorTokenRequest{Resource: permission.Resource, Source: source})
		if err != nil {
			return controlv1.VisitorTokenResponse{}, err
		}
		if err := refreshContextError(call); err != nil {
			return controlv1.VisitorTokenResponse{}, err
		}
		nextParent := parent
		if session {
			nextParent = next.ExpiresAt
		}
		nextProof, err := a.tokens.verify(next, nextParent)
		if err != nil && !errors.Is(err, visitortoken.ErrPolicy) {
			return controlv1.VisitorTokenResponse{}, err
		}
		if !nextProof.Valid() || !nextProof.SameIdentity(proof) {
			return controlv1.VisitorTokenResponse{}, visitortoken.ErrBinding
		}
		permission = next
	}
	return controlv1.VisitorTokenResponse{}, visitortoken.ErrPolicy
}

func validBrowserPath(path string) bool {
	if path == "" || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n#\x00") {
		return false
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && !parsed.IsAbs() && parsed.Host == "" && !strings.HasPrefix(parsed.Path, "//") && !strings.ContainsAny(parsed.Path, "\\\r\n\x00") && !strings.HasPrefix(parsed.Path, "/__tnl/")
}
