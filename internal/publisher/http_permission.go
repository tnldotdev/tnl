package publisher

import (
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const visitorTokenHeader = "Tnl-Visitor-Token"
const visitorTokenCookie = "__Host-tnl-visitor"

// authorization observes local verification and guard binding. the request keeps
// its HTTP parent and cancellation after this finite operation ends.
func authorizeHTTPRequest(w http.ResponseWriter, r *http.Request, policy *visitorlease.Lease, tokens *browserTokens) (permission httpPermission, guard *publicHTTPGuard, guarded *http.Request, err error) {
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

func visitorPermissionCookie(w http.ResponseWriter, permission controlv1.VisitorTokenResponse) error {
	if permission.VisitorToken == "" || len(permission.VisitorToken) > visitortoken.MaxTokenBytes || permission.ExpiresAt.IsZero() {
		return visitortoken.ErrToken
	}
	http.SetCookie(w, &http.Cookie{Name: visitorTokenCookie, Value: permission.VisitorToken, Path: "/", HttpOnly: true,
		Secure: true, SameSite: http.SameSiteLaxMode, Expires: permission.ExpiresAt})
	return nil
}

type httpPermission struct {
	permission visitortoken.VerifiedPermission
	token      visitortoken.Token
	renewed    bool
	source     netip.Addr
	anonymous  bool
}

// localHTTPPermission verifies exactly one supplied visitor credential. it has
// no control client, credential renewal, membership rule, or decision cache.
func localHTTPPermission(request *http.Request, policy *visitorlease.Lease, renewal *browserTokens) (httpPermission, error) {
	if policy == nil {
		return httpPermission{}, visitortoken.ErrPolicy
	}
	view, enabled, anonymous := policy.Current()
	if !enabled {
		return httpPermission{}, visitortoken.ErrPolicy
	}
	validHost := publisherproxy.ValidateRequest(request, view.Hostname) == ""
	if view.Scope.Kind == visitorscope.Service {
		validHost = request.Host == net.JoinHostPort(view.Hostname, strconv.Itoa(int(view.Port))) && request.Method != http.MethodConnect && !request.URL.IsAbs() && request.URL.Host == "" && request.TLS != nil && request.TLS.ServerName == view.Hostname
	}
	if !validHost {
		return httpPermission{}, visitortoken.ErrBinding
	}
	source, err := netip.ParseAddrPort(request.RemoteAddr)
	if session, ok := request.Context().Value(visitorSessionKey{}).(*visitorSession); ok {
		source, err = session.visitor.Source, nil
	}
	if err != nil || !source.IsValid() || source.Addr().Zone() != "" {
		return httpPermission{}, visitortoken.ErrBinding
	}
	result := httpPermission{source: source.Addr().Unmap()}
	var supplied []string
	for key, values := range request.Header {
		if strings.EqualFold(key, visitorTokenHeader) {
			supplied = append(supplied, values...)
			if len(values) == 0 {
				return httpPermission{}, visitortoken.ErrToken
			}
		}
		if strings.EqualFold(key, shareAccessHeaderName) || strings.EqualFold(key, "Tnl-Access-Token") {
			return httpPermission{}, visitortoken.ErrToken
		}
	}
	cookies := request.CookiesNamed(visitorTokenCookie)
	if suppliedCookieCount(request, visitorTokenCookie) != len(cookies) {
		return httpPermission{}, visitortoken.ErrToken
	}
	for _, cookie := range cookies {
		supplied = append(supplied, cookie.Value)
	}
	// a TLS credential is final for this connection. an HTTP credential cannot
	// replace its subject, including after a workload session is revoked.
	if request.TLS != nil && len(request.TLS.PeerCertificates) != 0 {
		if len(supplied) != 0 || suppliedCookieCount(request, browserAccessCookieName) != 0 || suppliedCookieCount(request, shareCookieName) != 0 {
			return httpPermission{}, visitortoken.ErrToken
		}
		if view.Scope.Kind != visitorscope.Service {
			return httpPermission{}, visitortoken.ErrBinding
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
		if suppliedCookieCount(request, browserAccessCookieName) != 0 || suppliedCookieCount(request, shareCookieName) != 0 {
			return httpPermission{}, visitortoken.ErrToken
		}
		if !anonymous {
			return httpPermission{}, visitortoken.ErrToken
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
	return result, nil
}

func (p httpPermission) bind(policy *visitorlease.Lease, stop func()) (*visitorlease.Guard, error) {
	if p.anonymous {
		return policy.BindAnonymous(p.source, stop)
	}
	return policy.Bind(p.permission, p.source, stop)
}
