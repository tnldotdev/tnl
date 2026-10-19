package authorityapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/oidcauth"
	"github.com/tnldotdev/tnl/internal/operatorlog"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"golang.org/x/oauth2"
)

const deviceCallbackPath = "/v1/auth/device/callback"
const deviceCookie = "__Host-tnl-device"

type DeviceStore interface {
	CreateDeviceLogin(context.Context, controlstate.DeviceLoginOptions, time.Time) (controlstate.DeviceLogin, string, error)
	ReadDeviceBrowser(context.Context, string, time.Time) (controlstate.DeviceLogin, error)
	ResolveLoginTeam(context.Context, string) (string, error)
	PrepareCompanyBrowser(context.Context, string, string, string, string, time.Time) (*controlstate.CompanyLoginIntent, error)
	PollDeviceLogin(context.Context, string, time.Time) (controlstate.DeviceLogin, error)
	CancelDeviceLogin(context.Context, string, time.Time) error
	BeginDeviceBrowser(context.Context, string, string, string, string, []byte, string, *controlstate.CompanyLoginIntent, time.Time) error
	ConsumeDeviceBrowser(context.Context, string, []byte, time.Time) (controlstate.DeviceLogin, error)
	VerifyDeviceBrowser(context.Context, string, []byte, controlstate.OIDCIdentity, time.Time) error
	DenyDeviceBrowser(context.Context, string, []byte, time.Time) error
	ApproveDeviceLogin(context.Context, string, []byte, string, time.Duration, time.Duration, time.Time) error
}

func (h *handler) deviceAvailable(w http.ResponseWriter) bool {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action 'self'; frame-ancestors 'none'")
	if h.oidc == nil || h.devices == nil {
		writeAuthenticationUnavailable(w, "device login", nil)
		return false
	}
	return true
}

func (h *handler) deviceError(w http.ResponseWriter, err error) {
	if errors.Is(err, controlstate.ErrTeamNotFound) {
		writeProblem(w, 404, authorityv1.NotFound, "team not found; use the exact team name")
		return
	}
	if errors.Is(err, controlstate.ErrAuthorityAccess) {
		writeProblem(w, 403, authorityv1.Forbidden, "company sign-in is unavailable for this team")
		return
	}
	if errors.Is(err, controlstate.ErrDeviceLogin) || errors.Is(err, controlstate.ErrControlAuthentication) || errors.Is(err, controlstate.ErrOIDCAssertionReplay) || errors.Is(err, oidcauth.ErrUnauthenticated) {
		writeProblem(w, http.StatusUnauthorized, authorityv1.Unauthenticated, "login is invalid, cancelled, or expired; start again")
		return
	}
	if errors.Is(err, oidcauth.ErrUnavailable) {
		requestID := writeProblem(w, http.StatusServiceUnavailable, authorityv1.Unavailable, "identity provider is unavailable; reopen the approval URL to retry")
		operatorlog.Report("authenticate device browser", failure.ServerIdentityProviderUnavailable, requestID, err)
		return
	}
	writeAuthenticationUnavailable(w, "device login", err)
}

func (h *handler) StartDeviceLogin(w http.ResponseWriter, r *http.Request) {
	if !h.deviceAvailable(w) {
		return
	}
	var body authorityv1.StartDeviceLoginRequest
	if decodeJSON(w, r, &body) != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid device login request")
		return
	}
	options := controlstate.DeviceLoginOptions{}
	if body.Team != nil {
		options.Team = *body.Team
	}
	if body.RefreshToken != nil {
		options.RefreshToken = *body.RefreshToken
	}
	l, credential, err := h.devices.CreateDeviceLogin(r.Context(), options, time.Now())
	if err != nil {
		h.deviceError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, authorityv1.DeviceLoginChallenge{PollingCredential: credential, ApprovalUrl: h.config.ControlURL + "/v1/auth/device/approve?code=" + url.QueryEscape(l.UserCode), UserCode: l.UserCode, ExpiresAt: l.ExpiresAt, IntervalSeconds: 2})
}

func (h *handler) PollDeviceLogin(w http.ResponseWriter, r *http.Request) {
	if !h.deviceAvailable(w) {
		return
	}
	var body authorityv1.DeviceLoginCredential
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid polling credential")
		return
	}
	l, err := h.devices.PollDeviceLogin(r.Context(), body.PollingCredential, time.Now())
	if err != nil {
		h.deviceError(w, err)
		return
	}
	result := authorityv1.DeviceLoginResult{Status: authorityv1.DeviceLoginResultStatus(l.Status)}
	if l.Session != nil {
		session := controlSessionResponse(*l.Session)
		result.Session = &session
	}
	writeJSON(w, 200, result)
}

func (h *handler) CancelDeviceLogin(w http.ResponseWriter, r *http.Request) {
	if !h.deviceAvailable(w) {
		return
	}
	var body authorityv1.DeviceLoginCredential
	if err := decodeJSON(w, r, &body); err != nil {
		writeProblem(w, 400, authorityv1.InvalidRequest, "invalid polling credential")
		return
	}
	if err := h.devices.CancelDeviceLogin(r.Context(), body.PollingCredential, time.Now()); err != nil {
		h.deviceError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func deviceRandom() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

func (h *handler) BeginDeviceBrowser(w http.ResponseWriter, r *http.Request, _ authorityv1.BeginDeviceBrowserParams) {
	if !h.deviceAvailable(w) {
		return
	}
	code := r.URL.Query().Get("code")
	l, err := h.devices.ReadDeviceBrowser(r.Context(), code, time.Now())
	if err != nil {
		h.deviceError(w, err)
		return
	}
	team := l.TeamID
	if team == "" {
		if !r.URL.Query().Has("team") {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_ = teamSelectionPage.Execute(w, code)
			return
		}
		team, err = h.devices.ResolveLoginTeam(r.Context(), r.URL.Query().Get("team"))
		if err != nil {
			h.deviceError(w, err)
			return
		}
	}
	state, err := deviceRandom()
	if err != nil {
		h.deviceError(w, err)
		return
	}
	nonce, err := deviceRandom()
	if err != nil {
		h.deviceError(w, err)
		return
	}
	bindingText, err := deviceRandom()
	if err != nil {
		h.deviceError(w, err)
		return
	}
	verifier := oauth2.GenerateVerifier()
	binding, _ := base64.RawURLEncoding.DecodeString(bindingText)
	intent, err := h.devices.PrepareCompanyBrowser(r.Context(), team, h.config.OIDCIssuer, h.config.OIDCClientID, h.config.ControlURL+deviceCallbackPath, time.Now())
	if err != nil {
		h.deviceError(w, err)
		return
	}
	var authorization string
	if intent != nil {
		nonce = intent.Nonce
		authorization, err = h.oidc.CompanyAuthorizationURL(r.Context(), state, nonce, verifier, intent.ID, intent.BindingToken)
	} else {
		authorization, err = h.oidc.AuthorizationURL(r.Context(), state, nonce, verifier)
	}
	if err != nil {
		h.deviceError(w, err)
		return
	}
	if err := h.devices.BeginDeviceBrowser(r.Context(), code, state, nonce, verifier, binding, team, intent, time.Now()); err != nil {
		h.deviceError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Value: bindingText, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600})
	http.Redirect(w, r, authorization, http.StatusFound)
}

func deviceBinding(r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(deviceCookie)
	if err != nil {
		return nil, controlstate.ErrDeviceLogin
	}
	binding, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil || len(binding) != 32 {
		return nil, controlstate.ErrDeviceLogin
	}
	return binding, nil
}

var approvalPage = template.Must(template.New("approval").Parse(`<!doctype html><html><head><title>approve tnl login</title></head><body><h1>approve tnl login</h1><p>signed in as {{.Name}}</p><p>only approve if your terminal shows this code: <strong>{{.Code}}</strong></p><form method="post" action="/v1/auth/device/approve"><input type="hidden" name="code" value="{{.Code}}"><input type="hidden" name="binding" value="{{.Binding}}"><button>approve login</button></form></body></html>`))

var teamSelectionPage = template.Must(template.New("team").Parse(`<!doctype html><html><head><title>tnl sign-in</title></head><body><h1>choose a team</h1><form method="get" action="/v1/auth/device/approve"><input type="hidden" name="code" value="{{.}}"><label>team name (leave empty for personal sign-in)<input name="team" maxlength="63"></label><button>continue</button></form></body></html>`))

func (h *handler) CompleteDeviceBrowser(w http.ResponseWriter, r *http.Request, _ authorityv1.CompleteDeviceBrowserParams) {
	if !h.deviceAvailable(w) {
		return
	}
	binding, err := deviceBinding(r)
	if err != nil {
		h.deviceError(w, err)
		return
	}
	if len(r.URL.RawQuery) > 8192 {
		h.deviceError(w, controlstate.ErrDeviceLogin)
		return
	}
	query, parseErr := url.ParseQuery(r.URL.RawQuery)
	if parseErr != nil || len(query["state"]) != 1 || len(query["code"]) > 1 || len(query["error"]) > 1 || query.Get("code") != "" && query.Get("error") != "" || query.Get("iss") != "" && query.Get("iss") != h.config.OIDCIssuer {
		h.deviceError(w, controlstate.ErrDeviceLogin)
		return
	}
	l, err := h.devices.ConsumeDeviceBrowser(r.Context(), query.Get("state"), binding, time.Now())
	if err != nil {
		h.deviceError(w, err)
		return
	}
	if r.URL.Query().Get("error") == "access_denied" {
		if err := h.devices.DenyDeviceBrowser(r.Context(), l.UserCode, binding, time.Now()); err != nil {
			h.deviceError(w, err)
			return
		}
		h.deviceError(w, oidcauth.ErrUnauthenticated)
		return
	}
	identity, err := h.oidc.Redeem(r.Context(), r.URL.Query().Get("code"), l.Nonce, l.Verifier)
	if err != nil {
		if errors.Is(err, oidcauth.ErrUnauthenticated) {
			if denyErr := h.devices.DenyDeviceBrowser(r.Context(), l.UserCode, binding, time.Now()); denyErr != nil {
				h.deviceError(w, denyErr)
				return
			}
		}
		h.deviceError(w, err)
		return
	}
	err = h.devices.VerifyDeviceBrowser(r.Context(), l.UserCode, binding, companyOIDCIdentity(identity), time.Now())
	if err != nil {
		h.deviceError(w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = approvalPage.Execute(w, struct{ Name, Code, Binding string }{identity.DisplayName, l.UserCode, base64.RawURLEncoding.EncodeToString(binding)})
}

func (h *handler) ApproveDeviceBrowser(w http.ResponseWriter, r *http.Request) {
	if !h.deviceAvailable(w) {
		return
	}
	binding, err := deviceBinding(r)
	if err != nil {
		h.deviceError(w, err)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil || r.PostForm.Get("binding") != base64.RawURLEncoding.EncodeToString(binding) {
		h.deviceError(w, controlstate.ErrDeviceLogin)
		return
	}
	if err := h.devices.ApproveDeviceLogin(r.Context(), r.PostForm.Get("code"), binding, h.config.ManagedDomain, h.config.AccessTokenLifetime, h.config.RefreshTokenLifetime, time.Now()); err != nil {
		if errors.Is(err, controlstate.ErrControlAuthentication) || errors.Is(err, controlstate.ErrOIDCAssertionReplay) {
			if denyErr := h.devices.DenyDeviceBrowser(r.Context(), r.PostForm.Get("code"), binding, time.Now()); denyErr != nil {
				h.deviceError(w, denyErr)
				return
			}
		}
		h.deviceError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: deviceCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = w.Write([]byte("login approved. return to your terminal.\n"))
}
