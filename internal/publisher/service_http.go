package publisher

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ServiceHTTPControl interface {
	visitorPolicyClient
	browserTokenClient
	ControlURL() string
	RedeemServiceBrowserHandoff(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) error
}

// ServiceHTTP binds each request to one trusted forwarding header. policy and
// browser credential renewal are prepared once by the service run owner.
type ServiceHTTP struct {
	Control  ServiceHTTPControl
	Subject  visitorscope.Scope
	RunID    string
	Number   int64
	Token    credentials.ServiceRunToken
	Hostname string
	Port     uint16
	Header   tunnelv1.ServiceForwardingHeader
	Requests *ServiceHTTPRequestLimits
	Policy   *visitorlease.Lease
	browser  *browserAccess
}

func PrepareServiceHTTP(ctx context.Context, f ServiceHTTP) (ServiceHTTP, func(), error) {
	if f.Control == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() {
		return ServiceHTTP{}, nil, ErrEndpoint
	}
	policy, err := prepareVisitorPolicy(ctx, f.Control, f.Subject, f.RunID, f.Number, f.Token.String(), nil)
	if err != nil {
		return ServiceHTTP{}, nil, err
	}
	tokens, err := startBrowserTokens(ctx, f.Control, policy.lease, nil)
	if err != nil {
		policy.Close()
		return ServiceHTTP{}, nil, err
	}
	f.Policy = policy.lease
	f.browser = &browserAccess{subject: f.Subject, client: serviceBrowserClient{f}, runID: f.RunID, version: uint64(f.Number), controlURL: strings.TrimSuffix(f.Control.ControlURL(), "/"), policy: policy, tokens: tokens}
	return f, func() { tokens.Close(); policy.Close() }, nil
}

func (f ServiceHTTP) Forward(ctx context.Context, client *tls.Conn, target ServiceHTTPTarget) error {
	h := f.Header
	if f.Policy == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || h.Direct == nil || h.Connector != nil || h.ServiceID != f.Subject.ID || h.ServiceRunID != f.RunID || h.RunNumber != uint64(f.Number) || h.Direct.DestinationPort != f.Port || f.Port < 1024 || h.Validate() != nil {
		return ErrEndpoint
	}
	source, err := netip.ParseAddr(h.SourceIP)
	if err != nil || source.Zone() != "" {
		return ErrEndpoint
	}
	view, enabled, _ := f.Policy.Current()
	if !enabled || view.Scope != f.Subject || view.Hostname != f.Hostname || view.Port != f.Port {
		return ErrEndpoint
	}
	authority := net.JoinHostPort(f.Hostname, strconv.Itoa(int(f.Port)))
	scheme := "http"
	if target.Transport.TLS != nil {
		scheme = "https"
	}
	return httpstream.Serve(ctx, client, &url.URL{Scheme: scheme, Host: target.Address}, target.dial, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			if r.Host != authority || r.Method == http.MethodConnect || r.URL.IsAbs() || r.URL.Host != "" || client.ConnectionState().ServerName != f.Hostname {
				serviceHTTPDenied(w, http.StatusMisdirectedRequest)
				return
			}
			// explicit preparation endpoints never send application bytes. TLS
			// certificate holders cannot switch identity through browser endpoints.
			if strings.HasPrefix(r.URL.Path, "/__tnl/") {
				if len(client.ConnectionState().PeerCertificates) != 0 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" {
					serviceHTTPDenied(w, http.StatusForbidden)
					return
				}
				if f.browser != nil && f.browser.handle(w, r) {
					return
				}
				if f.browser != nil && sharePath(r.URL.Path) && r.Method == http.MethodGet {
					f.share(w, r)
					return
				}
				http.NotFound(w, r)
				return
			}
			// PROXY metadata supplies the source, never an HTTP forwarding header.
			r.RemoteAddr = netip.AddrPortFrom(source.Unmap(), 1).String()
			state := client.ConnectionState()
			r.TLS = &state
			var tokens *browserTokens
			if f.browser != nil {
				tokens = f.browser.tokens
			}
			permission, guard, guarded, err := authorizeHTTPRequest(w, r, f.Policy, tokens)
			if err != nil {
				if f.browser != nil && f.browser.redirectRestricted(w, r) {
					return
				}
				serviceHTTPDenied(w, serviceHTTPDecisionStatus(err))
				return
			}
			defer guard.finish()
			if tokens != nil {
				prepared, release, found := tokens.use(permission.token, guard.local)
				guard.release = release
				if found && (permission.renewed || prepared.VisitorToken != permission.token.Reveal()) {
					_ = visitorPermissionCookie(w, prepared)
				}
			}
			w, r = guard, guarded
			release, ok := f.Requests.admit(w, r)
			if !ok {
				return
			}
			defer release()
			r = stripTnlCookies(r)
			r.Header.Del("Tnl-Access-Token")
			r.Header.Del("Forwarded")
			r.Header.Del("X-Real-IP")
			for key := range r.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
					r.Header.Del(key)
				}
			}
			next.ServeHTTP(w, r)
		})
	})
}

func (f ServiceHTTP) share(w http.ResponseWriter, r *http.Request) {
	source, err := json.Marshal(controlv1.VisitorTokenGrantSource{Kind: controlv1.VisitorTokenGrant, Credential: strings.TrimPrefix(r.URL.Path, "/__tnl/share/")})
	if err != nil {
		serviceHTTPDenied(w, 403)
		return
	}
	permission, err := f.Control.IssueVisitorToken(r.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: f.Subject.ID}, Source: source})
	if err != nil {
		serviceHTTPDenied(w, serviceHTTPDecisionStatus(err))
		return
	}
	// control rechecks the grant's parent on every renewal. the first short
	// permission is not the grant deadline.
	if err := f.browser.prepareSessionToken(r.Context(), source, permission); err != nil {
		serviceHTTPDenied(w, 503)
		return
	}
	if err := visitorPermissionCookie(w, permission); err != nil {
		serviceHTTPDenied(w, 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: shareCookieName, Value: strings.TrimPrefix(r.URL.Path, "/__tnl/share/"), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: permission.ExpiresAt})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func serviceHTTPDenied(w http.ResponseWriter, status int) {
	w.Header().Set("Connection", "close")
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
	message := "service HTTP access denied"
	if status == http.StatusServiceUnavailable {
		message = "service HTTP authorization is unavailable; retry"
	}
	http.Error(w, message, status)
}

func serviceHTTPDecisionStatus(err error) int {
	if err == nil || errors.Is(err, visitortoken.ErrToken) || errors.Is(err, visitortoken.ErrBinding) || errors.Is(err, clientcontrol.ErrNotFound) || errors.Is(err, clientcontrol.ErrUnauthenticated) || errors.Is(err, clientcontrol.ErrStatusConflict) {
		return http.StatusForbidden
	}
	var problem *clientcontrol.ProblemError
	if errors.As(err, &problem) && problem != nil && (problem.Status == 401 || problem.Status == 403 || problem.Status == 404 || problem.Status == 409) {
		return http.StatusForbidden
	}
	return http.StatusServiceUnavailable
}

// net/http omits malformed cookies. their presence must still fail closed.
func suppliedCookieCount(r *http.Request, name string) int {
	count := 0
	for _, header := range r.Header.Values("Cookie") {
		for _, pair := range strings.Split(header, ";") {
			key, _, _ := strings.Cut(strings.TrimSpace(pair), "=")
			if strings.TrimSpace(key) == name {
				count++
			}
		}
	}
	return count
}

type serviceBrowserClient struct{ frontend ServiceHTTP }

func (a serviceBrowserClient) request(run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.ServiceBrowserRequest, error) {
	f := a.frontend
	if run != f.RunID || number != uint64(f.Number) || token != "" {
		return controlv1.ServiceBrowserRequest{}, ErrEndpoint
	}
	return controlv1.ServiceBrowserRequest{RunNumber: f.Number, Secret: secret}, nil
}
func (a serviceBrowserClient) RedeemBrowserHandoff(ctx context.Context, run string, number uint64, secret, share, shareSecret string, token credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	input, err := a.request(run, number, secret, token)
	if err != nil || share != "" || shareSecret != "" {
		return controlv1.BrowserHandoffResponse{}, ErrEndpoint
	}
	f := a.frontend
	return f.Control.RedeemServiceBrowserHandoff(ctx, f.Subject.ID, f.RunID, f.Token, input)
}
func (a serviceBrowserClient) CheckBrowserAccess(ctx context.Context, run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.BrowserAccessResponse, error) {
	input, err := a.request(run, number, secret, token)
	if err != nil {
		return controlv1.BrowserAccessResponse{}, err
	}
	f := a.frontend
	return f.Control.CheckServiceBrowserSession(ctx, f.Subject.ID, f.RunID, f.Token, input)
}
func (a serviceBrowserClient) RevokeBrowserAccess(ctx context.Context, run string, number uint64, secret string, token credentials.PublishRunToken) error {
	input, err := a.request(run, number, secret, token)
	if err != nil {
		return err
	}
	f := a.frontend
	return f.Control.RevokeServiceBrowserSession(ctx, f.Subject.ID, f.RunID, f.Token, input)
}

var _ ServiceHTTPFrontend = ServiceHTTP{}
