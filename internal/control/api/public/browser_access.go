package public

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/control/oidc"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/operatorlog"
	"github.com/tnldotdev/tnl/internal/policy/authorization"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
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

func (h *handler) BeginPreviewBrowserLogin(response http.ResponseWriter, request *http.Request, params controlv1.BeginPreviewBrowserLoginParams) {
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Cache-Control", "no-store")
	if h.browserAccess == nil || h.browserOIDC == nil || h.browserAuthority == nil || h.config.ServerDomain == "" {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	if !validBrowserReturnPath(params.ReturnPath) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid preview return path")
		return
	}
	preview := controlstate.Preview{}
	if params.PreviewId != nil {
		var err error
		preview, err = h.previews.GetPreview(request.Context(), *params.PreviewId)
		if err != nil {
			writeControlStateProblem(response, "read browser preview", err)
			return
		}
		if !slices.Contains(preview.PublicURLIDs, params.PublicUrlId) {
			writeProblem(response, http.StatusNotFound, controlv1.NotFound, "preview not found")
			return
		}
	}
	publicURL, err := h.store.GetPublicURLForAuthorization(request.Context(), params.PublicUrlId)
	if err != nil {
		writeControlStateProblem(response, "read browser public URL", err)
		return
	}
	if preview.ID != "" && publicURL.TeamID != preview.TeamID || publicURL.LifecycleState != controlstate.PublicURLLifecycleEnabled || publicURL.Purpose != controlstate.PublicURLPurposeApp && publicURL.Purpose != controlstate.PublicURLPurposeAlias || publicURL.ServiceProtocol != controlstate.PublicURLServiceHTTP {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "public URL not found")
		return
	}
	h.beginBrowserLogin(response, request, visitorscope.Scope{Kind: visitorscope.PublicURL, ID: publicURL.ID}, publicURL.TeamID, preview.ID, params.ReturnPath, params.SwitchAccount)
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
	store, ok := h.store.(serviceHTTPStore)
	if !ok {
		writeProblem(response, 503, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	team, err := store.ServiceHTTPBrowserTeam(request.Context(), subject, time.Now())
	if err != nil {
		writeManagedCertificateProblem(response, "read managed browser subject", err)
		return
	}
	h.beginBrowserLogin(response, request, subject, team, "", params.ReturnPath, params.SwitchAccount)
}

func (h *handler) beginBrowserLogin(response http.ResponseWriter, request *http.Request, subject visitorscope.Scope, team, preview, path string, switchAccount *bool) {
	verifier := oauth2.GenerateVerifier()
	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		writeUnavailableProblem(response, "create browser nonce", "browser sign-in is unavailable", failure.ServerAPIInternal, err)
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	binding := make([]byte, 32)
	if _, err := rand.Read(binding); err != nil {
		writeUnavailableProblem(response, "create browser binding", "browser sign-in is unavailable", failure.ServerAPIInternal, err)
		return
	}
	now := time.Now()
	var intent *controlstate.CompanyLoginIntent
	var err error
	if store, ok := h.store.(interface {
		PrepareCompanyBrowser(context.Context, string, string, string, string, time.Time) (*controlstate.CompanyLoginIntent, error)
	}); ok {
		intent, err = store.PrepareCompanyBrowser(request.Context(), team, h.config.OIDCIssuer, h.config.OIDCClientID, h.config.ControlURL+browserCallbackPath, now)
		if err != nil {
			writeControlStateProblem(response, "select company browser sign-in", err)
			return
		}
		if intent != nil {
			nonce = intent.Nonce
		}
	}
	var state string
	if subject.Kind == visitorscope.Service {
		state, err = h.store.(serviceHTTPStore).BeginServiceBrowserLogin(request.Context(), subject, path, nonce, verifier, binding, intent, now)
	} else {
		state, err = h.browserAccess.BeginBrowserLogin(request.Context(), preview, subject.ID, path, nonce, verifier, binding, intent, now)
	}
	if err != nil {
		writeControlStateProblem(response, "start browser sign-in", err)
		return
	}
	http.SetCookie(response, &http.Cookie{Name: browserLoginCookieName, Value: base64.RawURLEncoding.EncodeToString(binding), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: now.Add(5 * time.Minute)})
	authorization, err := h.browserOIDC.AuthorizationURL(request.Context(), state, nonce, verifier)
	if intent != nil {
		authorization, err = h.browserOIDC.CompanyAuthorizationURL(request.Context(), state, nonce, verifier, intent.ID, intent.BindingToken)
	}
	if err != nil {
		writeUnavailableProblem(response, "discover browser identity provider", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
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
	bindingCookie, err := request.Cookie(browserLoginCookieName)
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
			writeControlStateProblem(response, "consume browser sign-in", err)
		}
		return
	}
	http.SetCookie(response, &http.Cookie{Name: browserLoginCookieName, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	identity, err := h.browserOIDC.Redeem(request.Context(), params.Code, attempt.Nonce, attempt.Verifier)
	if errors.Is(err, oidc.ErrUnavailable) {
		writeUnavailableProblem(response, "verify browser identity", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "invalid browser sign-in")
		return
	}
	sessionStore, ok := h.store.(interface {
		CreateOIDCControlSession(context.Context, string, controlstate.OIDCIdentity, time.Duration, time.Duration, time.Time) (controlstate.ControlSession, error)
	})
	if !ok {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	issued, err := sessionStore.CreateOIDCControlSession(request.Context(), h.config.ManagedDomain, controlstate.OIDCIdentity{Issuer: identity.Issuer, Subject: identity.Subject, DisplayName: identity.DisplayName, NormalizedEmail: identity.NormalizedEmail, EmailVerified: identity.EmailVerified, AssertionDigest: identity.AssertionDigest, AssertionExpiry: identity.ExpiresAt, TeamContexts: identity.TeamContexts, Nonce: identity.Nonce, ClientID: identity.ClientID, IssuedAt: identity.IssuedAt, CompanyIntent: attempt.CompanyIntent, AuthenticatedAt: identity.AuthenticatedAt, TenantID: identity.TenantID, HostedDomain: identity.HostedDomain, Groups: identity.Groups}, h.config.AccessTokenLifetime, h.config.RefreshTokenLifetime, now)
	if err != nil {
		if errors.Is(err, clientauthority.ErrUnauthenticated) || errors.Is(err, controlstate.ErrControlAuthentication) {
			writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "browser sign-in failed")
		} else {
			writeUnavailableProblem(response, "save browser sign-in", "browser sign-in could not be saved", failure.ServerAuthorityUnavailable, err)
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
	principal, err := h.authorizer.AuthorizePublicURLReads(request.Context(), validated.AccessToken.String())
	if errors.Is(err, authorization.ErrUnavailable) || errors.Is(err, clientauthority.ErrUnavailable) {
		writeUnavailableProblem(response, "authorize browser identity", "browser authorization is unavailable", failure.ServerAuthorityUnavailable, err)
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
		writeControlStateProblem(response, "save browser sign-in", err)
		return
	}
	retained = true
	if handoff.Origin != "" {
		http.Redirect(response, request, handoff.Origin+"/__tnl/team/handoff/"+handoff.Token, http.StatusSeeOther)
		return
	}
	publicURL, err := h.store.GetPublicURLForAuthorization(request.Context(), attempt.PublicURLID)
	if err != nil {
		writeControlStateProblem(response, "read signed-in browser public URL", err)
		return
	}
	http.Redirect(response, request, "https://"+publicURL.CanonicalHostname+"/__tnl/team/handoff/"+handoff.Token, http.StatusSeeOther)
}

func (h *handler) RedeemPreviewBrowserHandoff(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.BrowserHandoffRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 || (body.ShareId == nil) != (body.ShareSecret == nil) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid browser handoff")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	cookie, path, next, bridge, _, err := h.browserAccess.RedeemBrowserHandoff(request.Context(), auth, body.Token, time.Now())
	if err != nil && !errors.Is(err, controlstate.ErrPreviewAccess) {
		writeControlStateProblem(response, "redeem browser handoff", err)
		return
	}
	if err != nil || !validBrowserReturnPath(path) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "browser handoff expired")
		return
	}
	permission, err := h.redeemedBrowserHandoffPermission(request.Context(), auth.PublicURLID, cookie, body)
	if err != nil {
		writeVisitorTokenProblem(response, err)
		return
	}
	session, err := h.browserAccess.BrowserSession(request.Context(), auth.PublicURLID, cookie, time.Now())
	if err != nil {
		writeControlStateProblem(response, "read redeemed browser session", err)
		return
	}
	// the handoff deadline limits ticket redemption, not the browser sign-in.
	// the signed visitor permission retains its separate, shorter deadline.
	writeJSON(response, http.StatusOK, controlv1.BrowserHandoffResponse{CookieSecret: cookie, ReturnPath: path, NextUrl: &next, Bridge: &bridge, ExpiresAt: session.ExpiresAt, Permission: permission})
}

func (h *handler) redeemedBrowserHandoffPermission(ctx context.Context, urlID, cookie string, body controlv1.BrowserHandoffRequest) (controlv1.VisitorTokenResponse, error) {
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: urlID}
	permission, err := h.redeemedVisitorPermission(ctx, scope, controlstate.BrowserSessionTokenSource{Secret: cookie})
	if errors.Is(err, controlstate.ErrVisitorPermission) && body.ShareId != nil && body.ShareSecret != nil {
		// sign-in establishes identity for feedback; the share remains the
		// independent authority to visit when this person has no team grant.
		return h.redeemedVisitorPermission(ctx, scope, controlstate.ShareSessionTokenSource{ShareID: *body.ShareId, Secret: *body.ShareSecret})
	}
	return permission, err
}

func (h *handler) refreshBrowserSignIn(ctx context.Context, scope visitorscope.Scope, token string) (controlstate.BrowserAccessSession, error) {
	now := time.Now()
	if scope.Kind == visitorscope.Service {
		store, ok := h.store.(interface {
			RefreshServiceBrowserSession(context.Context, string, string, time.Time, func(context.Context, string) (controlstate.BrowserTokenRotation, error)) (controlstate.BrowserAccessSession, error)
		})
		if !ok {
			return controlstate.BrowserAccessSession{}, clientauthority.ErrUnavailable
		}
		return store.RefreshServiceBrowserSession(ctx, scope.ID, token, now, h.rotateBrowserCredentials)
	}
	if h.browserAccess == nil {
		return controlstate.BrowserAccessSession{}, clientauthority.ErrUnavailable
	}
	session, err := h.browserAccess.BrowserSession(ctx, scope.ID, token, now)
	if err != nil {
		return controlstate.BrowserAccessSession{}, err
	}
	if !session.AccessExpiresAt.After(now.Add(30 * time.Second)) {
		session, err = h.browserAccess.RefreshBrowserSession(ctx, scope.ID, token, now, h.rotateBrowserCredentials)
		if err != nil {
			return controlstate.BrowserAccessSession{}, err
		}
	}
	return session, nil
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

func (h *handler) browserSessionAccess(ctxRequest *http.Request, auth controlstate.PublishRunAuthentication, token string) (controlstate.BrowserAccessSession, publicURLReadPrincipal, bool, error) {
	session, err := h.refreshBrowserSignIn(ctxRequest.Context(), visitorscope.Scope{Kind: visitorscope.PublicURL, ID: auth.PublicURLID}, token)
	if err != nil {
		return controlstate.BrowserAccessSession{}, publicURLReadPrincipal{}, false, err
	}
	principal, err := h.authorizer.AuthorizePublicURLReads(ctxRequest.Context(), session.AccessToken)
	if err != nil {
		return controlstate.BrowserAccessSession{}, publicURLReadPrincipal{}, false, err
	}
	if principal.identityID != session.IdentityID {
		return controlstate.BrowserAccessSession{}, publicURLReadPrincipal{}, false, authorization.ErrUnauthenticated
	}
	decision, err := h.browserAccess.BrowserAuthorizationForRun(ctxRequest.Context(), auth, token, time.Now())
	if err != nil {
		return session, principal, false, err
	}
	session.IdentityID, session.DisplayName = decision.IdentityID, decision.DisplayName
	session.TeamMember = decision.TeamMember
	principal.displayName = decision.DisplayName
	return session, principal, decision.VisitAllowed, nil
}

func (h *handler) CheckPreviewBrowserAccess(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.BrowserAccessRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid browser access")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	session, principal, member, err := h.browserSessionAccess(request, auth, body.CookieSecret)
	if err != nil {
		switch {
		case errors.Is(err, controlstate.ErrPreviewAccess), errors.Is(err, controlstate.ErrVisitorSignIn), errors.Is(err, authorization.ErrUnauthenticated), errors.Is(err, clientauthority.ErrUnauthenticated):
			writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "browser sign-in expired")
		case errors.Is(err, authorization.ErrUnavailable), errors.Is(err, clientauthority.ErrUnavailable):
			writeUnavailableProblem(response, "check browser access", "browser access is unavailable", failure.ServerAuthorityUnavailable, err)
		default:
			writeControlStateProblem(response, "check browser access", err)
		}
		return
	}
	observability.AuthorizationDecision(request.Context(), "preview_browser_session", member)
	writeJSON(response, http.StatusOK, controlv1.BrowserAccessResponse{
		IdentityId: session.IdentityID, DisplayName: principal.displayName, VisitAllowed: member, TeamMember: session.TeamMember,
	})
}

func (h *handler) RevokePreviewBrowserAccess(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.BrowserAccessRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid browser logout")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if err := h.browserAccess.RevokeBrowserSession(request.Context(), auth.PublicURLID, body.CookieSecret, time.Now()); err != nil {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "browser logout failed")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
