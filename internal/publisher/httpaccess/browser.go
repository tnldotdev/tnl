package httpaccess

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/browserpage"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const BrowserCookieName = "__Host-tnl-browser"
const ShareHeaderName = "Tnl-Share-Token"

type BrowserClient interface {
	RedeemServiceBrowserHandoff(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) error
}

// Browser binds sign-in endpoints to one resource and publisher run. run owners
// prepare policy and renewal once, then share this immutable composition.
type Browser struct {
	Subject                      visitorscope.Scope
	Client                       BrowserClient
	PreviewID, RunID, ControlURL string
	Number                       int64
	Token                        credentials.ServiceRunToken
	Tokens                       *Tokens
	Policy                       *Policy
}

// MarshalJSON keeps run credentials and live clients out of diagnostic snapshots.
func (Browser) MarshalJSON() ([]byte, error) { return []byte("{}"), nil }

func browserCookie(response http.ResponseWriter, secret string, expires time.Time) {
	http.SetCookie(response, &http.Cookie{
		Name: BrowserCookieName, Value: secret, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: expires,
	})
}

func shareSessionCookie(request *http.Request) (string, string, error) {
	count := SuppliedCookieCount(request, ShareCookieName)
	if count == 0 {
		return "", "", nil
	}
	cookies := request.CookiesNamed(ShareCookieName)
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

func (a *Browser) checkCurrent(request *http.Request) (controlv1.BrowserAccessResponse, error) {
	secret, err := browserSessionSecret(request)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	result, err := a.Client.CheckServiceBrowserSession(request.Context(), a.Subject.ID, a.RunID, a.Token, controlv1.ServiceBrowserRequest{RunNumber: a.Number, Secret: secret})
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	if result.IdentityId == "" || result.DisplayName == "" {
		return controlv1.BrowserAccessResponse{}, errors.New("browser identity is invalid")
	}
	return result, nil
}

func (a *Browser) Handle(response http.ResponseWriter, request *http.Request) bool {
	const root = "/__tnl/team/"
	if !strings.HasPrefix(request.URL.Path, root) {
		return false
	}
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Referrer-Policy", "no-referrer")
	if a.Client == nil || a.Subject.Kind != visitorscope.Service || !a.Subject.Valid() ||
		!opaqueid.Valid(a.RunID, opaqueid.ServiceRunPrefix) || a.Number < 1 || a.Token == "" {
		if request.URL.Path == root+"session" {
			http.Error(response, "browser sign-in is unavailable", http.StatusServiceUnavailable)
		} else {
			browserpage.Error(response, request, "browser sign-in is unavailable", http.StatusServiceUnavailable)
		}
		return true
	}
	switch {
	case request.URL.Path == root+"login" && request.Method == http.MethodGet:
		path := request.URL.Query().Get("return")
		if path == "" {
			path = "/"
		}
		if !validBrowserPath(path) {
			browserpage.Error(response, request, "invalid return path", http.StatusBadRequest)
			return true
		}
		endpoint, err := url.Parse(a.ControlURL + "/v1/browser/service-login")
		if err != nil {
			browserpage.Error(response, request, "sign-in is unavailable", http.StatusServiceUnavailable)
			return true
		}
		query := endpoint.Query()
		if a.PreviewID != "" {
			query.Set("preview_id", a.PreviewID)
		}
		if request.URL.Query().Get("switch") == "1" {
			query.Set("switch_account", "true")
		}
		query.Set("service_id", a.Subject.ID)
		query.Set("return_path", path)
		endpoint.RawQuery = query.Encode()
		markBrowserLoginAttempt(response)
		http.Redirect(response, request, endpoint.String(), http.StatusSeeOther)
		return true
	case strings.HasPrefix(request.URL.Path, root+"handoff/") && request.Method == http.MethodGet:
		ticket := strings.TrimPrefix(request.URL.Path, root+"handoff/")
		raw, err := base64.RawURLEncoding.Strict().DecodeString(ticket)
		if err != nil || len(raw) != 32 {
			browserpage.Error(response, request, "404 page not found", http.StatusNotFound)
			return true
		}
		shareID, shareSecret, shareErr := shareSessionCookie(request)
		if shareErr != nil {
			browserpage.Error(response, request, "invalid share session", http.StatusForbidden)
			return true
		}
		input := controlv1.ServiceBrowserRequest{RunNumber: a.Number, Secret: ticket}
		if shareID != "" {
			input.ShareId, input.ShareCookieSecret = &shareID, &shareSecret
		}
		result, err := a.Client.RedeemServiceBrowserHandoff(request.Context(), a.Subject.ID, a.RunID, a.Token, input)
		if err != nil || !validBrowserPath(result.ReturnPath) {
			browserpage.Error(response, request, "browser sign-in expired", http.StatusForbidden)
			return true
		}
		if raw, err := base64.RawURLEncoding.Strict().DecodeString(result.CookieSecret); err != nil || len(raw) != 32 || !result.ExpiresAt.After(time.Now()) {
			browserpage.Error(response, request, "browser sign-in is unavailable", http.StatusServiceUnavailable)
			return true
		}
		if result.Permission != nil {
			if a.Tokens == nil || a.Policy == nil {
				browserpage.Error(response, request, "browser visitor permission is unavailable", http.StatusServiceUnavailable)
				return true
			}
			permission, verifyErr := a.Tokens.verify(*result.Permission, result.ExpiresAt)
			if verifyErr != nil && a.Policy != nil {
				if refreshErr := a.Policy.Refresh(request.Context()); refreshErr == nil {
					permission, verifyErr = a.Tokens.verify(*result.Permission, result.ExpiresAt)
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
				var prepared controlv1.VisitorTokenResponse
				if shareID != "" && permission.Facts().Subject == (visitortoken.Share{ShareID: shareID}) {
					prepared, err = a.PrepareSessionToken(request.Context(), source, *result.Permission)
				} else {
					prepared, err = a.PrepareToken(request.Context(), source, *result.Permission, result.ExpiresAt)
				}
				result.Permission = &prepared
			}
			if err != nil {
				browserpage.Error(response, request, "browser visitor permission is unavailable", http.StatusServiceUnavailable)
				return true
			}
			if err := PermissionCookie(response, *result.Permission); err != nil {
				browserpage.Error(response, request, "browser visitor permission is unavailable", http.StatusServiceUnavailable)
				return true
			}
		} else {
			// identity is not visit permission. discard an older visitor cookie
			// rather than retaining its unrelated authority after sign-in.
			http.SetCookie(response, &http.Cookie{Name: VisitorTokenCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
			if shareID != "" {
				http.SetCookie(response, &http.Cookie{Name: ShareCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
			}
		}
		browserCookie(response, result.CookieSecret, result.ExpiresAt)
		next := result.ReturnPath
		if result.NextUrl != nil {
			parsed, err := url.Parse(*result.NextUrl)
			if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.Fragment != "" || len(*result.NextUrl) > 4096 {
				browserpage.Error(response, request, "invalid browser handoff", http.StatusServiceUnavailable)
				return true
			}
			next = *result.NextUrl
		}
		if result.Bridge != nil && *result.Bridge {
			browserpage.Redirect(response, next)
			return true
		}
		http.Redirect(response, request, next, http.StatusSeeOther)
		return true
	case request.URL.Path == root+"renew" && request.Method == http.MethodGet:
		path := request.URL.Query().Get("return")
		if a.Tokens == nil || !validBrowserPath(path) || request.Header.Get(VisitorTokenHeader) != "" || request.Header.Get(ShareHeaderName) != "" {
			browserpage.Error(response, request, "invalid visitor renewal", http.StatusBadRequest)
			return true
		}
		shareID, secret, err := shareSessionCookie(request)
		if err != nil {
			browserpage.Error(response, request, "invalid share session", http.StatusForbidden)
			return true
		}
		var source json.RawMessage
		if shareID != "" {
			source, err = json.Marshal(controlv1.VisitorTokenShareSessionSource{Kind: controlv1.VisitorTokenShareSession, ShareId: shareID, Secret: secret})
		} else {
			source, err = browserSessionSource(request)
			if err != nil {
				browserpage.Error(response, request, "invalid browser sign-in", http.StatusForbidden)
				return true
			}
		}
		if err != nil {
			browserpage.Error(response, request, "invalid visitor renewal", http.StatusBadRequest)
			return true
		}
		issue := func(source json.RawMessage) (controlv1.VisitorTokenResponse, error) {
			return a.Tokens.client.IssueVisitorToken(request.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(a.Subject.Kind), Id: a.Subject.ID}, Source: source})
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
			browserpage.Error(response, request, message, status)
			return true
		}
		result, err = a.PrepareSessionToken(request.Context(), source, result)
		if err != nil || PermissionCookie(response, result) != nil {
			browserpage.Error(response, request, "visitor permission is unavailable", http.StatusServiceUnavailable)
			return true
		}
		http.Redirect(response, request, path, http.StatusSeeOther)
		return true
	case request.URL.Path == root+"session" && request.Method == http.MethodGet:
		if _, err := request.Cookie(BrowserCookieName); err != nil {
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
			browserpage.Error(response, request, "invalid logout origin", http.StatusForbidden)
			return true
		}
		if cookie, err := request.Cookie(BrowserCookieName); err == nil {
			if err := a.Client.RevokeServiceBrowserSession(request.Context(), a.Subject.ID, a.RunID, a.Token, controlv1.ServiceBrowserRequest{RunNumber: a.Number, Secret: cookie.Value}); err != nil {
				browserpage.Error(response, request, "could not sign out", http.StatusServiceUnavailable)
				return true
			}
		}
		http.SetCookie(response, &http.Cookie{Name: BrowserCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
		http.SetCookie(response, &http.Cookie{Name: VisitorTokenCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
		if request.URL.Path == root+"switch" {
			path := request.URL.Query().Get("return")
			if path == "" {
				path = "/"
			}
			if !validBrowserPath(path) {
				browserpage.Error(response, request, "invalid return path", http.StatusBadRequest)
				return true
			}
			http.Redirect(response, request, root+"login?switch=1&return="+url.QueryEscape(path), http.StatusSeeOther)
		} else {
			response.WriteHeader(http.StatusNoContent)
		}
		return true
	default:
		browserpage.Error(response, request, "404 page not found", http.StatusNotFound)
		return true
	}
}

func browserSessionSource(request *http.Request) (json.RawMessage, error) {
	secret, err := browserSessionSecret(request)
	if err != nil {
		return nil, err
	}
	return json.Marshal(controlv1.VisitorTokenBrowserSessionSource{Kind: controlv1.VisitorTokenBrowserSession, Secret: secret})
}

func browserSessionSecret(request *http.Request) (string, error) {
	cookies := request.CookiesNamed(BrowserCookieName)
	if SuppliedCookieCount(request, BrowserCookieName) != 1 || len(cookies) != 1 {
		return "", visitortoken.ErrToken
	}
	if raw, err := base64.RawURLEncoding.Strict().DecodeString(cookies[0].Value); err != nil || len(raw) != 32 {
		return "", visitortoken.ErrToken
	}
	return cookies[0].Value, nil
}

func (a *Browser) PrepareToken(ctx context.Context, source json.RawMessage, permission controlv1.VisitorTokenResponse, parent time.Time) (controlv1.VisitorTokenResponse, error) {
	return a.preparePermission(ctx, source, permission, parent, false)
}

func (a *Browser) PrepareSessionToken(ctx context.Context, source json.RawMessage, permission controlv1.VisitorTokenResponse) (controlv1.VisitorTokenResponse, error) {
	return a.preparePermission(ctx, source, permission, permission.ExpiresAt, true)
}

func (a *Browser) preparePermission(ctx context.Context, source json.RawMessage, permission controlv1.VisitorTokenResponse, parent time.Time, session bool) (controlv1.VisitorTokenResponse, error) {
	if a.Policy == nil || a.Tokens == nil {
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
		install := func() error { return a.Tokens.installSource(source, permission, parent, session) }
		if err := install(); err == nil {
			return permission, nil
		} else if !errors.Is(err, visitortoken.ErrPolicy) && !errors.Is(err, visitortoken.ErrKey) {
			return controlv1.VisitorTokenResponse{}, err
		}
		// only explicit credential preparation fetches policy. ordinary app
		// requests cannot wait for policy or issue another visitor permission.
		if err := a.Policy.Refresh(call); err != nil {
			return controlv1.VisitorTokenResponse{}, err
		}
		if err := refreshContextError(call); err != nil {
			return controlv1.VisitorTokenResponse{}, err
		}
		if err := install(); err == nil {
			return permission, nil
		}
		proof, err := a.Tokens.verify(permission, parent)
		view, enabled, _ := a.Policy.lease.Current()
		if !errors.Is(err, visitortoken.ErrPolicy) || !proof.Valid() || !enabled || proof.Facts().VisitorPolicyRevision >= view.VisitorPolicyRevision {
			if err == nil {
				err = visitortoken.ErrPolicy
			}
			return controlv1.VisitorTokenResponse{}, err
		}
		// policy can advance after control redeemed the session. the signed old
		// token proves its subject, not current access; control must authorize a
		// replacement for that same session before any cookie is installed.
		next, err := a.Tokens.client.IssueVisitorToken(call, controlv1.VisitorTokenRequest{Resource: permission.Resource, Source: source})
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
		nextProof, err := a.Tokens.verify(next, nextParent)
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
