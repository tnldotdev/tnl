package publisher

import (
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const visitorTokenHeader = "Tnl-Visitor-Token"
const visitorTokenCookie = "__Host-tnl-visitor"

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
	if publisherproxy.ValidateRequest(request, view.Hostname) != "" {
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
		if strings.EqualFold(key, shareAccessHeaderName) {
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
