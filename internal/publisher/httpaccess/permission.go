package httpaccess

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const VisitorTokenHeader = "Tnl-Visitor-Token"
const VisitorTokenCookie = "__Host-tnl-visitor"

// Authorization retains verified permission and the selected HTTP bearer proof.
// certificate possession and anonymous access never expose a bearer credential.
type Authorization struct {
	permission visitortoken.VerifiedPermission
	bearer     visitortoken.Token
}

func (a Authorization) Permission() visitortoken.VerifiedPermission { return a.permission }
func (a Authorization) BearerToken() (visitortoken.Token, bool)     { return a.bearer, a.bearer != "" }
func (Authorization) String() string                                { return "HTTP authorization" }
func (Authorization) GoString() string                              { return "HTTP authorization" }

// authorization observes local verification and guard binding. the request keeps
// its HTTP parent and cancellation after this finite operation ends.
func authorizeHTTPRequest(w http.ResponseWriter, r *http.Request, policy *visitorlease.Lease, tokens *Tokens) (permission httpPermission, guard *Guard, guarded *http.Request, err error) {
	check, finish := observability.PublisherOperation(r.Context(), "visitor_authorization")
	defer func() {
		observed := err
		switch {
		case errors.Is(err, visitortoken.ErrToken), errors.Is(err, visitortoken.ErrBinding), errors.Is(err, visitortoken.ErrPolicy):
			observed = diagnostic.Wrap(diagnostic.VisitorAccessDenied, err)
		case errors.Is(err, visitortoken.ErrKey):
			observed = diagnostic.Wrap(diagnostic.ServerUnavailable, err)
		}
		observability.PublisherAuthorization(check, err == nil, err == nil, observed)
		finish(observed)
	}()
	permission, err = localHTTPPermission(r, policy, tokens)
	if err != nil {
		return permission, nil, nil, err
	}
	guard, guarded, err = guardLocalHTTPRequest(w, r, policy, permission)
	return permission, guard, guarded, err
}

func PermissionCookie(w http.ResponseWriter, permission controlv1.VisitorTokenResponse) error {
	if permission.VisitorToken == "" || len(permission.VisitorToken) > visitortoken.MaxTokenBytes || permission.ExpiresAt.IsZero() {
		return visitortoken.ErrToken
	}
	http.SetCookie(w, &http.Cookie{Name: VisitorTokenCookie, Value: permission.VisitorToken, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: permission.ExpiresAt})
	return nil
}

type httpPermission struct {
	permission visitortoken.VerifiedPermission
	token      visitortoken.Token
	renewed    bool
	source     netip.Addr
	anonymous  bool
	bearer     bool
}

// localHTTPPermission verifies exactly one supplied visitor credential. it has
// no control client, credential renewal, membership rule, or decision cache.
func localHTTPPermission(request *http.Request, policy *visitorlease.Lease, renewal *Tokens) (httpPermission, error) {
	if policy == nil {
		return httpPermission{}, visitortoken.ErrPolicy
	}
	view, enabled, anonymous := policy.Current()
	if !enabled {
		return httpPermission{}, visitortoken.ErrPolicy
	}
	validHost := serviceendpoint.MatchesHTTPAuthority(view.Hostname, view.Port, request.Host) && request.Method != http.MethodConnect && !request.URL.IsAbs() && request.URL.Host == "" && request.TLS != nil && request.TLS.ServerName == view.Hostname
	if !validHost {
		return httpPermission{}, visitortoken.ErrBinding
	}
	source, err := netip.ParseAddrPort(request.RemoteAddr)
	if err != nil || !source.IsValid() || source.Addr().Zone() != "" {
		return httpPermission{}, visitortoken.ErrBinding
	}
	result := httpPermission{source: source.Addr().Unmap()}
	var supplied []string
	for key, values := range request.Header {
		if strings.EqualFold(key, VisitorTokenHeader) {
			supplied = append(supplied, values...)
			if len(values) == 0 {
				return httpPermission{}, visitortoken.ErrToken
			}
		}
		if strings.EqualFold(key, ShareHeaderName) || strings.EqualFold(key, "Tnl-Access-Token") {
			return httpPermission{}, visitortoken.ErrToken
		}
	}
	cookies := request.CookiesNamed(VisitorTokenCookie)
	if SuppliedCookieCount(request, VisitorTokenCookie) != len(cookies) {
		return httpPermission{}, visitortoken.ErrToken
	}
	for _, cookie := range cookies {
		supplied = append(supplied, cookie.Value)
	}
	// a TLS credential is final for this connection. an HTTP credential cannot
	// replace its subject, including after a workload session is revoked.
	if request.TLS != nil && len(request.TLS.PeerCertificates) != 0 {
		if len(supplied) != 0 || SuppliedCookieCount(request, BrowserCookieName) != 0 || SuppliedCookieCount(request, ShareCookieName) != 0 {
			return httpPermission{}, visitortoken.ErrToken
		}
		token, err := visitortoken.CertificateToken(request.TLS.PeerCertificates[0])
		if err != nil {
			return httpPermission{}, err
		}
		permission, err := visitortoken.VerifyCertificate(token, view, *request.TLS, time.Now())
		if err != nil {
			return httpPermission{}, err
		}
		result.permission, result.token = permission, token
		return result, nil
	}
	if len(supplied) == 0 {
		if !anonymous || SuppliedCookieCount(request, ShareCookieName) != 0 {
			return httpPermission{}, visitortoken.ErrToken
		}
		// sign-in identity is not visitor permission. a well-formed identity
		// cookie does not block independent anonymous access. a supplied share
		// still requires its visitor permission instead of anonymous fallback.
		if SuppliedCookieCount(request, BrowserCookieName) != 0 {
			if _, err := browserSessionSecret(request); err != nil {
				return httpPermission{}, err
			}
		}
		result.anonymous = true
		return result, nil
	}
	if len(supplied) != 1 {
		return httpPermission{}, visitortoken.ErrToken
	}
	token := visitortoken.Token(supplied[0])
	if renewal != nil && renewal.rejects(token) {
		return httpPermission{}, visitortoken.ErrToken
	}
	permission, err := visitortoken.VerifyBearer(token, view, time.Now())
	if err != nil && renewal != nil {
		proof, proofErr := visitortoken.VerifyBearerRenewalProof(token, view, time.Now())
		if proofErr == nil {
			token, permission, err = renewal.replacement(token, proof)
			result.renewed = err == nil
		}
	}
	if err != nil {
		return httpPermission{}, err
	}
	result.permission = permission
	result.token = token
	result.bearer = true
	return result, nil
}

func (p httpPermission) bind(policy *visitorlease.Lease, stop func()) (*visitorlease.Guard, error) {
	if p.anonymous {
		return policy.BindAnonymous(p.source, stop)
	}
	return policy.Bind(p.permission, p.source, stop)
}

// AuthorizeRequest binds local permission to this request and registers renewal
// use only after verification succeeds. ordinary requests never fetch authority.
func AuthorizeRequest(w http.ResponseWriter, r *http.Request, policy *visitorlease.Lease, tokens *Tokens) (Authorization, *Guard, *http.Request, error) {
	permission, guard, guarded, err := authorizeHTTPRequest(w, r, policy, tokens)
	if err != nil {
		return Authorization{permission: permission.permission}, nil, nil, err
	}
	result := Authorization{permission: permission.permission}
	if permission.bearer {
		result.bearer = permission.token
		if tokens != nil {
			prepared, accepted, release, found := tokens.use(permission.token, guard.local)
			guard.release = release
			if found {
				result.permission, result.bearer = accepted, visitortoken.Token(prepared.VisitorToken)
				if permission.renewed || prepared.VisitorToken != permission.token.Reveal() {
					_ = PermissionCookie(w, prepared)
				}
			}
		}
	}
	return result, guard, guarded, nil
}
