package public

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/control/turnstile"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const challengeBrowserCookie = "__Host-tnl-challenge-browser"

type httpChallengeStore interface {
	BeginHTTPChallenge(context.Context, visitorscope.Scope, []byte, []byte, time.Time) (controlstate.HTTPChallengeAttempt, error)
	ReadHTTPChallenge(context.Context, string, []byte, time.Time) (controlstate.HTTPChallengeAttempt, error)
	ClaimHTTPChallenge(context.Context, string, []byte, time.Time) error
	CompleteHTTPChallenge(context.Context, turnstile.VerifiedAttempt, time.Time) (controlstate.HTTPChallengeHandoff, error)
	RedeemHTTPChallenge(context.Context, visitorscope.Scope, string, int64, string, string, string, string, time.Time) (visitortoken.ClearanceToken, time.Time, error)
}

func (h *handler) challengeRequest(w http.ResponseWriter, r *http.Request) (context.Context, func(), bool) {
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	call, finish, ok := admitHTTPProtection(w, r)
	if !ok {
		return nil, nil, false
	}
	if h.challengeVerifier == nil || h.dependencies.HTTPChallenges == nil {
		finish()
		w.Header().Set("Retry-After", "1")
		writeProblem(w, 503, controlv1.Unavailable, "HTTP challenges are not available on this server")
		return nil, nil, false
	}
	return call, finish, true
}

func challengeCookieHash(r *http.Request) ([]byte, bool) {
	cookies := r.CookiesNamed(challengeBrowserCookie)
	if len(cookies) != 1 || len(cookies[0].Value) != 43 {
		return nil, false
	}
	secret, err := base64.RawURLEncoding.Strict().DecodeString(cookies[0].Value)
	if err != nil || len(secret) != 32 {
		return nil, false
	}
	hash := sha256.Sum256(secret)
	return hash[:], true
}

func (h *handler) BeginHTTPChallenge(w http.ResponseWriter, r *http.Request, params controlv1.BeginHTTPChallengeParams) {
	ctx, finish, ok := h.challengeRequest(w, r)
	if !ok {
		return
	}
	defer finish()
	scope := visitorscope.Scope{Kind: visitorscope.Kind(params.ResourceKind), ID: params.ResourceId}
	if len(params.Binding) != 43 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid challenge browser binding")
		return
	}
	publisherHash, err := base64.RawURLEncoding.Strict().DecodeString(params.Binding)
	if !scope.Valid() || len(params.Binding) != 43 || err != nil || len(publisherHash) != 32 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid challenge resource or browser binding")
		return
	}
	var browser [32]byte
	if _, err := rand.Read(browser[:]); err != nil {
		writeProblem(w, 503, controlv1.Unavailable, "challenge preparation is unavailable")
		return
	}
	hash := sha256.Sum256(browser[:])
	now := time.Now()
	attempt, err := h.dependencies.HTTPChallenges.BeginHTTPChallenge(ctx, scope, hash[:], publisherHash, now)
	if err != nil {
		writeHTTPChallengeProblem(ctx, w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: challengeBrowserCookie, Value: base64.RawURLEncoding.EncodeToString(browser[:]), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: now.Add(httpprotection.ChallengeAttemptLifetime)})
	http.Redirect(w, r, "/v1/browser/challenge/"+attempt.ID, http.StatusSeeOther)
}

var challengePage = template.Must(template.New("challenge").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>tnl challenge</title><script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script></head>
<body><main><h1>Complete the challenge</h1><p>Continue to {{.Origin}}. This does not sign you in or grant access.</p>
<form method="post"><div class="cf-turnstile" data-sitekey="{{.SiteKey}}" data-action="{{.Action}}" data-cdata="{{.ID}}" data-response-field-name="response"></div>
<button type="submit">Continue</button></form></main></body></html>`))

func (h *handler) GetHTTPChallenge(w http.ResponseWriter, r *http.Request, attempt string) {
	ctx, finish, ok := h.challengeRequest(w, r)
	if !ok {
		return
	}
	defer finish()
	hash, ok := challengeCookieHash(r)
	if !ok {
		writeHTTPChallengeProblem(ctx, w, controlstate.ErrHTTPChallenge)
		return
	}
	record, err := h.dependencies.HTTPChallenges.ReadHTTPChallenge(ctx, attempt, hash, time.Now())
	if err != nil {
		writeHTTPChallengeProblem(ctx, w, err)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	origin := visitortoken.ClearanceOrigin(record.Hostname, record.Port)
	// preserve the same-origin form's Origin header without sending the attempt
	// path to third parties. form-action also covers the publisher redirect.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self' "+origin+"; script-src https://challenges.cloudflare.com; frame-src https://challenges.cloudflare.com; connect-src https://challenges.cloudflare.com; style-src 'unsafe-inline'")
	_ = challengePage.Execute(w, struct{ Origin, SiteKey, ID, Action string }{origin, h.challengeVerifier.SiteKey, record.ID, turnstile.Action})
}

func (h *handler) VerifyHTTPChallenge(w http.ResponseWriter, r *http.Request, attempt string) {
	ctx, finish, ok := h.challengeRequest(w, r)
	if !ok {
		return
	}
	defer finish()
	hash, bound := challengeCookieHash(r)
	if !bound || r.Header.Get("Origin") != h.config.ControlURL || r.URL.RawQuery != "" {
		writeHTTPChallengeProblem(ctx, w, controlstate.ErrHTTPChallenge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 8192)
	if r.ParseForm() != nil || len(r.PostForm) != 1 || len(r.PostForm["response"]) != 1 || len(r.PostForm.Get("response")) == 0 || len(r.PostForm.Get("response")) > 2048 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid challenge response")
		return
	}
	if err := h.dependencies.HTTPChallenges.ClaimHTTPChallenge(ctx, attempt, hash, time.Now()); err != nil {
		writeHTTPChallengeProblem(ctx, w, err)
		return
	}
	proof, err := h.challengeVerifier.Verify(ctx, r.PostForm.Get("response"), attempt, time.Now())
	if err != nil {
		writeHTTPChallengeProblem(ctx, w, err)
		return
	}
	handoff, err := h.dependencies.HTTPChallenges.CompleteHTTPChallenge(ctx, proof, time.Now())
	if err != nil {
		writeHTTPChallengeProblem(ctx, w, err)
		return
	}
	observability.HTTPChallenge(ctx, "verified")
	next := handoff.Origin + "/__tnl/challenge?" + url.Values{"handoff": {handoff.Secret}}.Encode()
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (h *handler) RedeemHTTPChallenge(w http.ResponseWriter, r *http.Request) {
	ctx, finish, ok := h.challengeRequest(w, r)
	if !ok {
		return
	}
	defer finish()
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.RedeemHTTPChallengeRequest
	if decodeJSONLimited(w, r, &body, 8192) != nil || len(body.RunId) == 0 || len(body.RunId) > 64 || body.RunNumber < 1 || len(body.Handoff) > 128 || len(body.Binding) != 43 {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid challenge handoff")
		return
	}
	scope := visitorscope.Scope{Kind: visitorscope.Kind(body.Resource.Kind), ID: body.Resource.Id}
	if !scope.Valid() {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid challenge resource")
		return
	}
	clearance, expires, err := h.dependencies.HTTPChallenges.RedeemHTTPChallenge(ctx, scope, body.RunId, body.RunNumber, token, body.Handoff, body.Binding, h.config.ControlURL, time.Now())
	if err != nil {
		writeHTTPChallengeProblem(ctx, w, err)
		return
	}
	writeJSON(w, 200, controlv1.HTTPChallengeClearance{Clearance: clearance.Reveal(), ExpiresAt: expires})
}

func writeHTTPChallengeProblem(ctx context.Context, w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, controlstate.ErrHTTPChallenge), errors.Is(err, turnstile.ErrRejected):
		observability.HTTPChallenge(ctx, "rejected")
		writeProblem(w, 403, controlv1.Forbidden, "challenge expired or was rejected; open the app again to retry")
	case errors.Is(err, turnstile.ErrUnavailable), errors.Is(err, controlstate.ErrHTTPChallengeCapacity), errors.Is(err, controlstate.ErrVisitorSigningKey), errors.Is(err, context.DeadlineExceeded):
		observability.HTTPChallenge(ctx, "unavailable")
		w.Header().Set("Retry-After", "1")
		writeProblem(w, 503, controlv1.Unavailable, "challenge verification is unavailable; open the app again to retry")
	default:
		writeVisitorTokenProblem(ctx, w, err)
	}
}
