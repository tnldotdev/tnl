package httpaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	protectionpolicy "github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	ChallengePath          = "/__tnl/challenge"
	ChallengeBindingCookie = "__Host-tnl-challenge-binding"
	ClearanceCookie        = "__Host-tnl-clearance"
)

var ErrChallengePreparation = diagnostic.Wrap(diagnostic.HttpChallengeUnavailable, errors.New("HTTP challenge preparation requires a current run, policy, and control client"))
var ErrChallengeUnsupported = diagnostic.Wrap(diagnostic.HttpChallengeUnavailable, errors.New("challenge requires Turnstile, which is not configured on this server; disable http.protection.challenge or configure both control keys"))

type ChallengeClient interface {
	Discovery(context.Context) (controlv1.ControlDiscovery, error)
	RedeemHTTPChallenge(context.Context, controlv1.RedeemHTTPChallengeRequest, string) (controlv1.HTTPChallengeClearance, error)
}

// Challenge prepares one run's explicit handoff authority. it owns no workers
// or clearance registry; normal requests use only the current local key view.
type Challenge struct {
	client  ChallengeClient
	policy  *visitorlease.Lease
	control string
	request controlv1.RedeemHTTPChallengeRequest
	token   string
}

func (*Challenge) String() string   { return "HTTP challenge authority" }
func (*Challenge) GoString() string { return "HTTP challenge authority" }

func (c *Challenge) Binds(policy *visitorlease.Lease, scope visitorscope.Scope, run string, number int64) bool {
	return c != nil && c.policy == policy && c.request.Resource.Kind == controlv1.VisitorResourceScopeKind(scope.Kind) &&
		c.request.Resource.Id == scope.ID && c.request.RunId == run && c.request.RunNumber == number
}

// handoffs share four process-wide slots and a two-second budget, with no queue.
// ordinary clearance verification never acquires a slot or makes a remote call.
var challengeHandoffs = make(chan struct{}, 4)

func PrepareChallenge(ctx context.Context, client ChallengeClient, policy *visitorlease.Lease, control string, scope visitorscope.Scope, run string, number int64, token string) (*Challenge, error) {
	if client == nil || policy == nil || !scope.Valid() || run == "" || number < 1 || token == "" {
		return nil, ErrChallengePreparation
	}
	canonical, err := naming.CanonicalControlURL(control)
	view, enabled, _ := policy.Current()
	if err != nil || canonical != control || !enabled || view.Scope != scope || view.Issuer != control {
		return nil, ErrChallengePreparation
	}
	call, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	discovery, err := client.Discovery(call)
	if err != nil {
		return nil, err
	}
	if err := refreshContextError(call); err != nil {
		return nil, err
	}
	if !discovery.Turnstile {
		return nil, ErrChallengeUnsupported
	}
	return &Challenge{client: client, policy: policy, control: control, token: token,
		request: controlv1.RedeemHTTPChallengeRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKind(scope.Kind), Id: scope.ID}, RunId: run, RunNumber: number}}, nil
}

// Allow runs after ordinary visitor authorization and admission, but before
// inspection or application forwarding. only explicit top-level GET navigation
// can start the browser flow; no Accept, user-agent, or credential is a bypass.
func (c *Challenge) Allow(w http.ResponseWriter, r *http.Request) bool {
	if c == nil {
		return true
	}
	view, enabled, _ := c.policy.Current()
	if !enabled {
		challengeUnavailable(w, r)
		return false
	}
	cookies := r.CookiesNamed(ClearanceCookie)
	if SuppliedCookieCount(r, ClearanceCookie) == 1 && len(cookies) == 1 {
		if _, err := visitortoken.VerifyClearance(visitortoken.ClearanceToken(cookies[0].Value), view, time.Now()); err == nil {
			observability.HTTPChallenge(r.Context(), "cleared")
			return true
		}
	}
	if r.Method != http.MethodGet || r.ContentLength != 0 || len(r.TransferEncoding) != 0 ||
		r.Header.Get("Sec-Fetch-Mode") != "navigate" || r.Header.Get("Sec-Fetch-Dest") != "document" || r.Header.Get("Upgrade") != "" {
		challengeRequired(w, r)
		return false
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		challengeUnavailable(w, r)
		return false
	}
	digest := sha256.Sum256(secret[:])
	// control receives only the binding digest, never the publisher cookie,
	// application body, requested path, or return query.
	query := url.Values{"resource_kind": {string(c.request.Resource.Kind)}, "resource_id": {c.request.Resource.Id}, "binding": {base64.RawURLEncoding.EncodeToString(digest[:])}}
	http.SetCookie(w, &http.Cookie{Name: ChallengeBindingCookie, Value: base64.RawURLEncoding.EncodeToString(secret[:]), Path: "/", Secure: true,
		HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Now().Add(protectionpolicy.ChallengeAttemptLifetime + protectionpolicy.ChallengeHandoffLifetime)})
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	observability.HTTPChallenge(r.Context(), "redirected")
	http.Redirect(w, r, c.control+"/v1/browser/challenge/start?"+query.Encode(), http.StatusSeeOther)
	return false
}

// Handle consumes only the reserved endpoint. it grants no visitor permission;
// the next request still passes current authorization, limits, and inspection.
func (c *Challenge) Handle(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != ChallengePath {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if c == nil {
		http.NotFound(w, r)
		return true
	}
	cookies := r.CookiesNamed(ChallengeBindingCookie)
	query, err := url.ParseQuery(r.URL.RawQuery)
	if r.URL.EscapedPath() != ChallengePath || r.Method != http.MethodGet || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" ||
		err != nil || len(query) != 1 || len(query["handoff"]) != 1 || len(query.Get("handoff")) == 0 || len(query.Get("handoff")) > 128 ||
		SuppliedCookieCount(r, ChallengeBindingCookie) != 1 || len(cookies) != 1 || len(cookies[0].Value) != 43 {
		challengeRequired(w, r)
		return true
	}
	binding, err := base64.RawURLEncoding.Strict().DecodeString(cookies[0].Value)
	if err != nil || len(binding) != 32 {
		challengeRequired(w, r)
		return true
	}
	select {
	case challengeHandoffs <- struct{}{}:
		defer func() { <-challengeHandoffs }()
	default:
		challengeUnavailable(w, r)
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	_, enabled, _ := c.policy.Current()
	if !enabled {
		challengeUnavailable(w, r)
		return true
	}
	request := c.request
	request.Handoff, request.Binding = query.Get("handoff"), cookies[0].Value
	result, err := c.client.RedeemHTTPChallenge(ctx, request, c.token)
	if err != nil || refreshContextError(ctx) != nil {
		if classified, ok := failure.Of(err); ok && (classified.Reason() == failure.ServerDenied || classified.Reason() == failure.Authentication) {
			challengeRequired(w, r)
			return true
		}
		challengeUnavailable(w, r)
		return true
	}
	// never install an unverified control response or silently accept another
	// origin, purpose, or expiry. the existing policy owner supplies fresh keys.
	view, enabled, _ := c.policy.Current()
	if !enabled {
		challengeUnavailable(w, r)
		return true
	}
	expires, err := visitortoken.VerifyClearance(visitortoken.ClearanceToken(result.Clearance), view, time.Now())
	if err != nil || !expires.Equal(view.LocalDeadline(result.ExpiresAt)) {
		challengeUnavailable(w, r)
		return true
	}
	http.SetCookie(w, &http.Cookie{Name: ClearanceCookie, Value: result.Clearance, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Expires: expires})
	http.SetCookie(w, &http.Cookie{Name: ChallengeBindingCookie, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: -1})
	observability.HTTPChallenge(r.Context(), "redeemed")
	http.Redirect(w, r, "/", http.StatusSeeOther)
	return true
}

func challengeRequired(w http.ResponseWriter, r *http.Request) {
	observability.HTTPChallenge(r.Context(), "required")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if r.ProtoMajor == 1 {
		w.Header().Set("Connection", "close")
	}
	w.WriteHeader(http.StatusForbidden)
	if r.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(struct {
			Code string `json:"code"`
		}{Code: "challenge_required"})
	}
}

func challengeUnavailable(w http.ResponseWriter, r *http.Request) {
	observability.HTTPChallenge(r.Context(), "unavailable")
	w.Header().Set("Retry-After", "1")
	diagnostic.WriteHTTP(w, r, diagnostic.HttpChallengeUnavailable, "")
}
