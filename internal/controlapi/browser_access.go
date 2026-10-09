package controlapi

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/httpclient"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/operatorlog"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/oauth2"
)

const browserCallbackPath = "/v1/browser/callback"
const browserLoginCookieName = "__Host-tnl-browser-login"

func validBrowserReturnPath(path string) bool {
	if path == "" || len(path) > 2048 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") || strings.ContainsAny(path, "\\\r\n#") {
		return false
	}
	parsed, err := url.ParseRequestURI(path)
	return err == nil && parsed.Host == "" && !parsed.IsAbs()
}

func (h *handler) browserHTTPClient() *http.Client {
	client := h.config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return httpclient.NoRedirects(client)
}

func (h *handler) browserOAuthConfig(request *http.Request) (*oauth2.Config, error) {
	client := h.browserHTTPClient()
	provider, err := oidc.NewProvider(oidc.ClientContext(request.Context(), client), h.config.OIDCIssuer)
	if err != nil {
		return nil, err
	}
	return &oauth2.Config{
		ClientID:    h.config.BrowserOIDCClientID,
		Endpoint:    provider.Endpoint(),
		RedirectURL: "https://control." + h.config.ServerDomain + browserCallbackPath,
		Scopes:      []string{"openid", "offline_access"},
	}, nil
}

func (h *handler) BeginPreviewBrowserLogin(response http.ResponseWriter, request *http.Request, params controlv1.BeginPreviewBrowserLoginParams) {
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Cache-Control", "no-store")
	if h.browserAccess == nil || h.browserVerifier == nil || h.browserAuthority == nil || h.config.ServerDomain == "" {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	if !validBrowserReturnPath(params.ReturnPath) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid preview return path")
		return
	}
	var preview controlstate.Preview
	if params.PreviewId != nil && *params.PreviewId != "" {
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
	if preview.ID != "" && publicURL.TeamID != preview.TeamID || publicURL.LifecycleState != controlstate.PublicURLLifecycleEnabled || publicURL.Purpose != controlstate.PublicURLPurposeApp {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "public URL not found")
		return
	}
	config, err := h.browserOAuthConfig(request)
	if err != nil {
		writeUnavailableProblem(response, "discover browser identity provider", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
		return
	}
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
	state, err := h.browserAccess.BeginBrowserLogin(request.Context(), preview.ID, publicURL.ID, params.ReturnPath, nonce, verifier, binding, now)
	if err != nil {
		writeControlStateProblem(response, "start browser sign-in", err)
		return
	}
	http.SetCookie(response, &http.Cookie{Name: browserLoginCookieName, Value: base64.RawURLEncoding.EncodeToString(binding), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: now.Add(5 * time.Minute)})
	http.Redirect(response, request, config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier), oauth2.SetAuthURLParam("nonce", nonce)), http.StatusFound)
}

func (h *handler) CompletePreviewBrowserLogin(response http.ResponseWriter, request *http.Request, params controlv1.CompletePreviewBrowserLoginParams) {
	response.Header().Set("Referrer-Policy", "no-referrer")
	response.Header().Set("Cache-Control", "no-store")
	if h.browserAccess == nil || h.browserVerifier == nil || h.browserAuthority == nil || params.Code == "" || len(params.Code) > 4096 {
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
	config, err := h.browserOAuthConfig(request)
	if err != nil {
		writeUnavailableProblem(response, "discover browser identity provider", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
		return
	}
	client := h.browserHTTPClient()
	result, err := config.Exchange(oidc.ClientContext(request.Context(), client), params.Code, oauth2.VerifierOption(attempt.Verifier))
	if err != nil {
		var rejected *oauth2.RetrieveError
		if errors.As(err, &rejected) && (rejected.ErrorCode == "invalid_grant" || rejected.ErrorCode == "access_denied") {
			writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "browser sign-in failed")
		} else {
			writeUnavailableProblem(response, "exchange browser authorization code", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
		}
		return
	}
	raw, ok := result.Extra("id_token").(string)
	if !ok {
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "identity token missing")
		return
	}
	identity, err := h.browserVerifier.Verify(request.Context(), raw)
	if errors.Is(err, oidcauth.ErrUnavailable) {
		writeUnavailableProblem(response, "verify browser identity", "identity provider is unavailable", failure.ServerIdentityProviderUnavailable, err)
		return
	}
	if err != nil || subtle.ConstantTimeCompare([]byte(identity.Nonce), []byte(attempt.Nonce)) != 1 {
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "invalid browser sign-in")
		return
	}
	issued, err := h.browserAuthority.ExchangeBrowserOIDC(request.Context(), raw)
	if err != nil {
		if errors.Is(err, authorityclient.ErrUnauthenticated) {
			writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "browser sign-in failed")
		} else {
			writeUnavailableProblem(response, "save browser sign-in", "browser sign-in could not be saved", failure.ServerAuthorityUnavailable, err)
		}
		return
	}
	validated, err := authorityclient.ValidateControlSessionResponse(issued, "", time.Time{})
	if err != nil {
		writeUnavailableProblem(response, "validate browser session", "authority returned an invalid browser session", failure.ServerAuthorityUnavailable, err)
		return
	}
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
	principal, err := h.authorizer.AuthorizePublicURLReads(request.Context(), validated.AccessToken)
	if errors.Is(err, authorization.ErrUnavailable) || errors.Is(err, authorityclient.ErrUnavailable) {
		writeUnavailableProblem(response, "authorize browser identity", "browser authorization is unavailable", failure.ServerAuthorityUnavailable, err)
		return
	}
	if err != nil || principal.identityID != issued.Identity.Identity.Id {
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "browser identity changed")
		return
	}
	handoff, err := h.browserAccess.IssueBrowserHandoff(request.Context(), attempt, controlstate.BrowserAccessSession{
		IdentityID: principal.identityID, DisplayName: principal.displayName,
		AccessToken: validated.AccessToken, RefreshToken: validated.RefreshToken,
		AccessExpiresAt: validated.AccessExpiresAt, ExpiresAt: validated.RefreshExpiresAt,
	}, now)
	if err != nil {
		writeControlStateProblem(response, "save browser sign-in", err)
		return
	}
	retained = true
	publicURL, err := h.store.GetPublicURLForAuthorization(request.Context(), attempt.PublicURLID)
	if err != nil {
		writeControlStateProblem(response, "read signed-in browser public URL", err)
		return
	}
	http.Redirect(response, request, "https://"+publicURL.CanonicalHostname+"/__tnl/team/handoff/"+handoff.Token, http.StatusSeeOther)
}

func (h *handler) EnableBrowserAccess(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.PublishRunVersionRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid browser capability request")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if h.browserAccess == nil || h.browserVerifier == nil || h.browserAuthority == nil || h.config.ServerDomain == "" {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "browser sign-in is unavailable")
		return
	}
	if err := h.browserAccess.EnableBrowserAccess(request.Context(), auth, time.Now()); err != nil {
		writeControlStateProblem(response, "register browser capability", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) requireBrowserAccess(response http.ResponseWriter, request *http.Request, auth controlstate.PublishRunAuthentication) bool {
	if h.browserAccess == nil || h.browserAuthority == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "browser access is unavailable")
		return false
	}
	if err := h.browserAccess.RequireBrowserAccess(request.Context(), auth, time.Now()); err != nil {
		writeControlStateProblem(response, "check browser capability", err)
		return false
	}
	return true
}

func (h *handler) RedeemPreviewBrowserHandoff(response http.ResponseWriter, request *http.Request, runID controlv1.PublishRunID) {
	var body controlv1.BrowserHandoffRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid browser handoff")
		return
	}
	auth, ok := h.authenticatePublishRunRequest(response, request, runID, uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	if !h.requireBrowserAccess(response, request, auth) {
		return
	}
	cookie, path, next, bridge, expires, err := h.browserAccess.RedeemBrowserHandoff(request.Context(), auth, body.Token, time.Now())
	if err != nil && !errors.Is(err, controlstate.ErrPreviewAccess) {
		writeControlStateProblem(response, "redeem browser handoff", err)
		return
	}
	if err != nil || !validBrowserReturnPath(path) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "browser handoff expired")
		return
	}
	writeJSON(response, http.StatusOK, controlv1.BrowserHandoffResponse{CookieSecret: cookie, ReturnPath: path, NextUrl: &next, Bridge: &bridge, ExpiresAt: expires})
}

func (h *handler) browserSessionIdentity(ctxRequest *http.Request, auth controlstate.PublishRunAuthentication, token string) (controlstate.BrowserAccessSession, publicURLReadPrincipal, error) {
	now := time.Now()
	session, err := h.browserAccess.BrowserSession(ctxRequest.Context(), auth.PublicURLID, token, now)
	if err != nil {
		return controlstate.BrowserAccessSession{}, publicURLReadPrincipal{}, err
	}
	if !session.AccessExpiresAt.After(now.Add(30 * time.Second)) {
		session, err = h.browserAccess.RefreshBrowserSession(ctxRequest.Context(), auth.PublicURLID, token, now,
			func(ctx context.Context, refreshToken string) (controlstate.BrowserTokenRotation, error) {
				issued, err := h.browserAuthority.Refresh(ctx, credentials.RefreshToken(refreshToken))
				if err != nil {
					return controlstate.BrowserTokenRotation{}, err
				}
				rotated, err := authorityclient.ValidateControlSessionResponse(issued, "", time.Time{})
				if err != nil {
					return controlstate.BrowserTokenRotation{}, err
				}
				return controlstate.BrowserTokenRotation{
					IdentityID: issued.Identity.Identity.Id, AccessToken: rotated.AccessToken,
					RefreshToken: rotated.RefreshToken, AccessExpiresAt: rotated.AccessExpiresAt,
				}, nil
			})
		if err != nil {
			return controlstate.BrowserAccessSession{}, publicURLReadPrincipal{}, err
		}
	}
	principal, err := h.authorizer.AuthorizePublicURLReads(ctxRequest.Context(), session.AccessToken)
	if err != nil {
		return controlstate.BrowserAccessSession{}, publicURLReadPrincipal{}, err
	}
	if principal.identityID != session.IdentityID {
		return controlstate.BrowserAccessSession{}, publicURLReadPrincipal{}, authorization.ErrUnauthenticated
	}
	return session, principal, nil
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
	if !h.requireBrowserAccess(response, request, auth) {
		return
	}
	_, principal, err := h.browserSessionIdentity(request, auth, body.CookieSecret)
	var access controlstate.BrowserAuthorization
	if err == nil {
		access, err = h.browserAccess.BrowserAuthorizationForRun(request.Context(), auth, body.CookieSecret, time.Now())
		if err == nil && access.Identity.IdentityID != principal.identityID {
			err = authorization.ErrUnauthenticated
		}
	}
	if err != nil {
		switch {
		case errors.Is(err, controlstate.ErrPreviewAccess), errors.Is(err, authorization.ErrUnauthenticated), errors.Is(err, authorityclient.ErrUnauthenticated):
			writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "browser access expired")
		case errors.Is(err, authorization.ErrUnavailable), errors.Is(err, authorityclient.ErrUnavailable):
			writeUnavailableProblem(response, "check browser access", "browser access is unavailable", failure.ServerAuthorityUnavailable, err)
		default:
			writeControlStateProblem(response, "check browser access", err)
		}
		return
	}
	writeJSON(response, http.StatusOK, controlv1.BrowserAccessResponse{
		IdentityId: access.Identity.IdentityID, DisplayName: access.Identity.DisplayName, VisitAllowed: access.VisitAllowed,
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
	if !h.requireBrowserAccess(response, request, auth) {
		return
	}
	if err := h.browserAccess.RevokeBrowserSession(request.Context(), auth.PublicURLID, body.CookieSecret, time.Now()); err != nil {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "browser logout failed")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
