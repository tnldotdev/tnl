package public

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"golang.org/x/oauth2"
)

const browserCallbackPath = "/v1/browser/callback"
const browserLoginCookieName = "__Host-tnl-browser-login"

func validBrowserReturnPath(path string) bool {
	if path == "" || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n#") {
		return false
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && parsed.Host == "" && !parsed.IsAbs() && !strings.HasPrefix(parsed.Path, "//") && !strings.ContainsAny(parsed.Path, "\\\r\n\x00") && !strings.HasPrefix(parsed.Path, "/__tnl/")
}

func (h *handler) BeginServiceBrowserLogin(response http.ResponseWriter, request *http.Request, params controlv1.BeginServiceBrowserLoginParams) {
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Cache-Control", "no-store")
	if h.browserAccess == nil || h.browserOIDC == nil || h.browserAuthority == nil {
		writeProblem(response, 503, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	subject := visitorscope.Scope{Kind: visitorscope.Service, ID: params.ServiceId}
	if !subject.Valid() || !validBrowserReturnPath(params.ReturnPath) {
		writeProblem(response, 400, controlv1.InvalidRequest, "invalid managed browser sign-in")
		return
	}
	store, ok := h.dependencies.ServiceHTTP, h.dependencies.ServiceHTTP != nil
	if !ok {
		writeProblem(response, 503, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	team, err := store.ServiceHTTPBrowserTeam(request.Context(), subject, time.Now())
	if err != nil {
		writeManagedCertificateProblem(request.Context(), response, "read managed browser subject", err)
		return
	}
	preview := ""
	if params.PreviewId != nil {
		preview = *params.PreviewId
	}
	h.beginBrowserLogin(response, request, subject, team, preview, params.ReturnPath, params.SwitchAccount)
}

func (h *handler) beginBrowserLogin(response http.ResponseWriter, request *http.Request, subject visitorscope.Scope, team, preview, path string, switchAccount *bool) {
	verifier := oauth2.GenerateVerifier()
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		writeUnavailableProblem(request.Context(), response, "create browser nonce", "browser sign-in is unavailable", failure.ServerAPIInternal, err)
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	binding := make([]byte, 32)
	if _, err := rand.Read(binding); err != nil {
		writeUnavailableProblem(request.Context(), response, "create browser binding", "browser sign-in is unavailable", failure.ServerAPIInternal, err)
		return
	}
	now := time.Now()
	var intent *controlstate.CompanyLoginIntent
	var err error
	if store := h.dependencies.CompanyBrowser; store != nil {
		intent, err = store.PrepareCompanyBrowser(request.Context(), team, h.config.OIDCIssuer, h.config.OIDCClientID, h.config.ControlURL+browserCallbackPath, now)
		if err != nil {
			writeControlStateProblem(request.Context(), response, "select company browser sign-in", err)
			return
		}
		if intent != nil {
			nonce = intent.Nonce
		}
	}
	state, err := h.dependencies.ServiceHTTP.BeginServiceBrowserLogin(request.Context(), subject, preview, path, nonce, verifier, binding, intent, now)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "start browser sign-in", err)
		return
	}
	http.SetCookie(response, serverhttp.ControlCookie(h.config.ControlURL, http.Cookie{Name: browserLoginCookieName, Value: base64.RawURLEncoding.EncodeToString(binding), Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: now.Add(5 * time.Minute)}))
	authorization, err := h.browserOIDC.AuthorizationURL(request.Context(), state, nonce, verifier)
	if intent != nil {
		authorization, err = h.browserOIDC.CompanyAuthorizationURL(request.Context(), state, nonce, verifier, intent.ID, intent.BindingToken)
	}
	if err != nil {
		writeUnavailableProblem(request.Context(), response, "discover browser identity provider", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
		return
	}
	if switchAccount != nil && *switchAccount {
		parsed, _ := url.Parse(authorization)
		q := parsed.Query()
		q.Set("prompt", "select_account")
		parsed.RawQuery = q.Encode()
		authorization = parsed.String()
	}
	http.Redirect(response, request, authorization, http.StatusFound)
}

func (h *handler) CompletePreviewBrowserLogin(response http.ResponseWriter, request *http.Request, params controlv1.CompletePreviewBrowserLoginParams) {
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Cache-Control", "no-store")
	if h.browserAccess == nil || h.browserOIDC == nil || h.browserAuthority == nil || params.Code == "" || len(params.Code) > 4096 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid browser sign-in")
		return
	}
	now := time.Now()
	bindingCookie, err := request.Cookie(serverhttp.ControlCookieName(h.config.ControlURL, browserLoginCookieName))
	if err != nil {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "browser sign-in expired")
		return
	}
	binding, err := base64.RawURLEncoding.DecodeString(bindingCookie.Value)
	if err != nil || len(binding) != 32 {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "browser sign-in expired")
		return
	}
	attempt, err := h.browserAccess.ConsumeBrowserLogin(request.Context(), params.State, binding, now)
	if err != nil {
		if errors.Is(err, controlstate.ErrPreviewAccess) {
			writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "browser sign-in expired")
		} else {
			writeControlStateProblem(request.Context(), response, "consume browser sign-in", err)
		}
		return
	}
	http.SetCookie(response, serverhttp.ControlCookie(h.config.ControlURL, http.Cookie{Name: browserLoginCookieName, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1}))
	identity, err := h.browserOIDC.Redeem(request.Context(), params.Code, attempt.Nonce, attempt.Verifier)
	if errors.Is(err, oidc.ErrUnavailable) {
		writeUnavailableProblem(request.Context(), response, "verify browser identity", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "invalid browser sign-in")
		return
	}
	sessionStore, ok := h.dependencies.BrowserSessions, h.dependencies.BrowserSessions != nil
	if !ok {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	issued, err := sessionStore.CreateOIDCControlSession(request.Context(), h.config.ManagedDomain, controlstate.OIDCIdentity{Issuer: identity.Issuer, Subject: identity.Subject, DisplayName: identity.DisplayName, NormalizedEmail: identity.NormalizedEmail, EmailVerified: identity.EmailVerified, AssertionDigest: identity.AssertionDigest, AssertionExpiry: identity.ExpiresAt, TeamContexts: identity.TeamContexts, Nonce: identity.Nonce, ClientID: identity.ClientID, IssuedAt: identity.IssuedAt, CompanyIntent: attempt.CompanyIntent, AuthenticatedAt: identity.AuthenticatedAt, TenantID: identity.TenantID, HostedDomain: identity.HostedDomain, Groups: identity.Groups}, h.config.AccessTokenLifetime, h.config.RefreshTokenLifetime, now)
	if err != nil {
		if errors.Is(err, clientauthority.ErrUnauthenticated) || errors.Is(err, controlstate.ErrControlAuthentication) {
			writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "browser sign-in failed")
		} else {
			writeUnavailableProblem(request.Context(), response, "save browser sign-in", "browser sign-in could not be saved", failure.ServerAuthorityUnavailable, err)
		}
		return
	}
	validated := issued
	retained := false
	defer func() {
		if !retained {
			logoutCtx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), 5*time.Second)
			defer cancel()
			if err := h.browserAuthority.LogoutWithAccessToken(logoutCtx, credentials.AccessToken(validated.AccessToken)); err != nil {
				operatorlog.Report("discard browser session", failure.ServerAuthorityUnavailable, "", err)
			}
		}
	}()
	principal, err := h.authorizer.AuthorizeControlReads(request.Context(), validated.AccessToken.String())
	if errors.Is(err, authorization.ErrUnavailable) || errors.Is(err, clientauthority.ErrUnavailable) {
		writeUnavailableProblem(request.Context(), response, "authorize browser identity", "browser authorization is unavailable", failure.ServerAuthorityUnavailable, err)
		return
	}
	if err != nil || principal.identityID != issued.Identity.Identity.ID {
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "browser identity changed")
		return
	}
	handoff, err := h.browserAccess.IssueBrowserHandoff(request.Context(), attempt, controlstate.BrowserAccessSession{
		IdentityID: principal.identityID, DisplayName: principal.displayName,
		AccessToken: validated.AccessToken.String(), RefreshToken: validated.RefreshToken.String(),
		AccessExpiresAt: validated.AccessExpiresAt, ExpiresAt: validated.RefreshExpiresAt,
	}, now)
	if err != nil {
		writeControlStateProblem(request.Context(), response, "save browser sign-in", err)
		return
	}
	retained = true
	http.Redirect(response, request, handoff.Origin+"/__tnl/team/handoff/"+handoff.Token, http.StatusSeeOther)
}

func (h *handler) refreshBrowserSignIn(ctx context.Context, scope visitorscope.Scope, token string) (controlstate.BrowserAccessSession, error) {
	now := time.Now()
	store := h.dependencies.ServiceHTTP
	if store == nil {
		return controlstate.BrowserAccessSession{}, clientauthority.ErrUnavailable
	}
	if !scope.Valid() {
		return controlstate.BrowserAccessSession{}, controlstate.ErrVisitorSignIn
	}
	return store.RefreshServiceBrowserSession(ctx, scope.ID, token, now, h.rotateBrowserCredentials)
}

func (h *handler) rotateBrowserCredentials(ctx context.Context, refreshToken string) (controlstate.BrowserTokenRotation, error) {
	if h.browserAuthority == nil {
		return controlstate.BrowserTokenRotation{}, clientauthority.ErrUnavailable
	}
	issued, err := h.browserAuthority.Refresh(ctx, credentials.RefreshToken(refreshToken))
	if err != nil {
		return controlstate.BrowserTokenRotation{}, err
	}
	rotated, err := clientauthority.ValidateControlSessionResponse(issued, "", time.Time{})
	if err != nil {
		return controlstate.BrowserTokenRotation{}, err
	}
	return controlstate.BrowserTokenRotation{IdentityID: issued.Identity.Identity.Id, AccessToken: rotated.AccessToken,
		RefreshToken: rotated.RefreshToken, AccessExpiresAt: rotated.AccessExpiresAt}, nil
}

func (h *handler) browserSessionAccess(ctxRequest *http.Request, auth controlstate.ServiceHTTPRun, token string) (controlstate.BrowserAccessSession, controlReadPrincipal, bool, error) {
	session, err := h.refreshBrowserSignIn(ctxRequest.Context(), auth.Subject, token)
	if err != nil {
		return controlstate.BrowserAccessSession{}, controlReadPrincipal{}, false, err
	}
	decision, err := h.dependencies.ServiceHTTP.ServiceBrowserSession(ctxRequest.Context(), auth, token, false, time.Now())
	if err != nil {
		return session, controlReadPrincipal{}, false, err
	}
	session.IdentityID, session.DisplayName = decision.IdentityID, decision.DisplayName
	principal := controlReadPrincipal{identityID: decision.IdentityID, displayName: decision.DisplayName}
	return session, principal, decision.TeamMember, nil
}
