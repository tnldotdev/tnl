package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/visitorpolicy"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type ServiceHTTPControl interface {
	browserTokenClient
	ControlURL() string
	RedeemServiceBrowserHandoff(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) error
}

// ServiceHTTP is built for each trusted forwarding header, never from HTTP
// headers. requests stay on the selected run; HTTP/2 streams use separate
// target connections so canceling one cannot close another.
type ServiceHTTP struct {
	Control          ServiceHTTPControl
	Subject          visitorscope.Scope
	RunID            string
	Number           int64
	Token            credentials.ServiceRunToken
	Hostname         string
	Port             uint16
	Header           tunnelv1.ServiceForwardingHeader
	Requests         *ServiceHTTPRequestLimits
	Runtime          *ServiceHTTPRuntime
	Promote          func(tunnelv1.ServiceVisitorReference) error
	MetadataRevision int64
}

// ServiceHTTPRuntime owns run-scoped browser permission renewal. forwarding
// requests read its prepared state; only redemption and background work fetch.
type ServiceHTTPRuntime struct {
	policy *visitorpolicy.Policy
	tokens *browserTokens
}

func NewServiceHTTPRuntime(ctx context.Context, control ServiceHTTPControl, policy *visitorpolicy.Policy) (*ServiceHTTPRuntime, error) {
	if policy == nil || policy.Lease == nil {
		return nil, ErrEndpoint
	}
	view, enabled, _ := policy.Lease.Current()
	if !enabled || view.Scope.Kind != visitorscope.Service {
		return nil, ErrEndpoint
	}
	tokens, err := startBrowserTokens(ctx, control, policy.Lease, nil)
	if err != nil {
		return nil, err
	}
	return &ServiceHTTPRuntime{policy: policy, tokens: tokens}, nil
}

func (r *ServiceHTTPRuntime) Close() { r.tokens.Close() }

func (f ServiceHTTP) Forward(ctx context.Context, client *tls.Conn, target ServiceHTTPTarget) error {
	h := f.Header
	if f.Control == nil || f.Runtime == nil || f.Runtime.policy == nil || f.Promote == nil || f.MetadataRevision < 1 || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || h.Direct == nil || h.Connector != nil || h.ServiceID != f.Subject.ID || h.ServiceRunID != f.RunID || h.RunNumber != uint64(f.Number) || h.Direct.DestinationPort != f.Port || f.Port < 1024 || h.Validate() != nil {
		return ErrEndpoint
	}
	controlURL, err := url.Parse(f.Control.ControlURL())
	if err != nil || controlURL.Scheme != "https" || controlURL.Host == "" || controlURL.User != nil || controlURL.RawQuery != "" || controlURL.Fragment != "" {
		return ErrEndpoint
	}
	authority := net.JoinHostPort(f.Hostname, strconv.Itoa(int(f.Port)))
	// the browser UI's public-run credential is unused; the adapter retains the
	// managed authority and never converts it to a public URL publish run token.
	browser := &browserAccess{subject: f.Subject, client: serviceBrowserClient{f}, runID: f.RunID, version: uint64(f.Number), controlURL: strings.TrimSuffix(f.Control.ControlURL(), "/"), policy: f.Runtime.policy, tokens: f.Runtime.tokens}
	scheme := "http"
	if target.Transport.TLS != nil {
		scheme = "https"
	}
	return httpstream.Serve(ctx, client, &url.URL{Scheme: scheme, Host: target.Address}, target.dial, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state := client.ConnectionState()
			r.TLS = &state
			if r.ProtoMajor == 1 && (r.ContentLength != 0 || len(r.TransferEncoding) != 0) {
				w.Header().Set("Connection", "close")
			}
			w.Header().Set("Cache-Control", "no-store")
			if r.Host != authority || r.URL.IsAbs() || r.URL.Host != "" || r.TLS == nil || r.TLS.ServerName != f.Hostname || r.Method == http.MethodConnect {
				serviceHTTPDenied(w, http.StatusMisdirectedRequest)
				return
			}
			// authentication endpoints cannot consume unbounded bodies or promote
			// application capacity. ingress bounds their bytes and total lifetime.
			if strings.HasPrefix(r.URL.Path, "/__tnl/") {
				_, workload, certificateErr := f.certificatePermission(client.ConnectionState())
				if certificateErr != nil || workload {
					serviceHTTPDenied(w, http.StatusForbidden)
					return
				}
				if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" {
					serviceHTTPDenied(w, http.StatusBadRequest)
					return
				}
				if browser.handle(w, r) {
					return
				}
				if sharePath(r.URL.Path) && r.Method == http.MethodGet {
					f.share(w, r)
					return
				}
				http.NotFound(w, r)
				return
			}
			permission, supplied, err := f.localPermission(r, client.ConnectionState())
			if err != nil {
				if !supplied && browser.redirectRestricted(w, r) {
					return
				}
				serviceHTTPDenied(w, serviceHTTPDecisionStatus(err))
				return
			}
			guard, guarded, err := guardLocalHTTPRequest(w, r, f.Runtime.policy.Lease, permission)
			if err != nil {
				serviceHTTPDenied(w, http.StatusForbidden)
				return
			}
			defer guard.finish()
			if permission.token != "" {
				prepared, release, found := f.Runtime.tokens.use(permission.token, guard.local)
				guard.release = release
				if found && (permission.renewed || prepared.VisitorToken != permission.token.Reveal()) {
					_ = visitorPermissionCookie(guard, prepared)
				}
			}
			w, r = guard, guarded
			// internal credentials and spoofed forwarding identity never reach the
			// application. the selected target transport owns target TLS trust.
			release, ok := f.Requests.admit(w, r)
			if !ok {
				return
			}
			defer release()
			reference, err := visitortoken.ServiceAuditReference(permission.permission, state)
			if err != nil {
				serviceHTTPDenied(w, http.StatusForbidden)
				return
			}
			if err := f.Promote(reference); err != nil {
				serviceHTTPDenied(w, http.StatusServiceUnavailable)
				return
			}
			w.Header().Del("Connection")
			r = stripTnlCookies(r)
			r.Header.Del(shareAccessHeaderName)
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

func (f ServiceHTTP) certificatePermission(state tls.ConnectionState) (visitortoken.Permission, bool, error) {
	if len(state.PeerCertificates) == 0 {
		return visitortoken.Permission{}, false, nil
	}
	view, enabled, _ := f.Runtime.policy.Lease.Current()
	if !enabled {
		return visitortoken.Permission{}, false, visitortoken.ErrPolicy
	}
	if len(state.VerifiedChains) == 0 {
		roots := f.Runtime.policy.Lease.ClientAuthorities()
		if roots == nil {
			return visitortoken.Permission{}, false, visitortoken.ErrPolicy
		}
		chains, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{Roots: roots, CurrentTime: view.AuthorityTime(time.Now()), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
		if err != nil {
			return visitortoken.Permission{}, false, visitortoken.ErrBinding
		}
		state.VerifiedChains = chains
	}
	token, err := visitortoken.CertificateToken(state.PeerCertificates[0])
	if err != nil {
		return visitortoken.Permission{}, false, err
	}
	permission, err := visitortoken.VerifyCertificateRenewalProof(token, view, state, time.Now())
	if err != nil {
		return visitortoken.Permission{}, false, err
	}
	certificate, ok := permission.Subject.(visitortoken.Certificate)
	if !ok {
		return visitortoken.Permission{}, false, visitortoken.ErrBinding
	}
	_, workload := certificate.Source.(visitortoken.Workload)
	return permission, workload, nil
}

func (f ServiceHTTP) localPermission(r *http.Request, state tls.ConnectionState) (httpPermission, bool, error) {
	view, enabled, _ := f.Runtime.policy.Lease.Current()
	if !enabled || !view.Public || view.Scope != f.Subject || view.MetadataRevision != f.MetadataRevision {
		return httpPermission{}, true, visitortoken.ErrPolicy
	}
	supplied := suppliedCookieCount(r, visitorTokenCookie) != 0 || suppliedCookieCount(r, browserAccessCookieName) != 0 || suppliedCookieCount(r, shareCookieName) != 0
	for _, name := range []string{visitorTokenHeader, "Tnl-Access-Token", shareAccessHeaderName} {
		_, present := r.Header[http.CanonicalHeaderKey(name)]
		supplied = supplied || present
	}
	// an explicit HTTP proof takes precedence over an unrelated TLS certificate.
	// a supplied tnl certificate remains final when malformed or workload-bound.
	tnlCertificate := false
	if len(state.PeerCertificates) > 0 {
		for _, uri := range state.PeerCertificates[0].URIs {
			if uri != nil && uri.Scheme == "tnl" {
				tnlCertificate = true
			}
		}
	}
	certificateState := state
	if supplied && !tnlCertificate {
		certificateState.PeerCertificates = nil
		certificateState.VerifiedChains = nil
	}
	certificate, workload, certificateErr := f.certificatePermission(certificateState)
	if certificateErr != nil {
		return httpPermission{}, true, certificateErr
	}
	source, err := netip.ParseAddr(f.Header.SourceIP)
	if err != nil {
		return httpPermission{}, true, visitortoken.ErrBinding
	}
	if len(state.PeerCertificates) > 0 && (workload || !supplied) {
		if err := visitortoken.CheckCurrent(certificate, view, time.Now()); err != nil {
			return httpPermission{}, true, err
		}
		return httpPermission{permission: certificate, source: source, metadataRevision: f.MetadataRevision}, true, nil
	}
	if _, retired := r.Header["Tnl-Access-Token"]; retired {
		return httpPermission{}, true, visitortoken.ErrToken
	}
	request := r.Clone(r.Context())
	request.RemoteAddr = net.JoinHostPort(source.String(), "0")
	permission, err := localHTTPPermission(request, f.Runtime.policy.Lease, f.Runtime.tokens)
	if err == nil {
		if grant, ok := permission.permission.Subject.(visitortoken.Grant); ok && grant.Kind == "share" {
			if _, header := request.Header[http.CanonicalHeaderKey(visitorTokenHeader)]; header {
				return httpPermission{}, true, visitortoken.ErrBinding
			}
		}
	}
	permission.metadataRevision = f.MetadataRevision
	return permission, supplied, err
}

func serviceHTTPDenied(w http.ResponseWriter, status int) {
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
	if errors.As(err, &problem) && (problem.Status == 401 || problem.Status == 403 || problem.Status == 404 || problem.Status == 409) {
		return http.StatusForbidden
	}
	return http.StatusServiceUnavailable
}

// net/http omits malformed cookies during parsing. a supplied tnl credential
// must still fail closed instead of falling through to certificate admission.
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

func (f ServiceHTTP) share(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimPrefix(r.URL.Path, "/__tnl/share/")
	view, enabled, _ := f.Runtime.policy.Lease.Current()
	permission, err := visitortoken.VerifyBearer(visitortoken.Token(secret), view, time.Now())
	grant, ok := permission.Subject.(visitortoken.Grant)
	if !enabled || err != nil || !ok || grant.Kind != "share" {
		serviceHTTPDenied(w, 403)
		return
	}
	response := controlv1.VisitorTokenResponse{VisitorToken: secret, ExpiresAt: permission.ExpiresAt}
	if err := visitorPermissionCookie(w, response); err != nil {
		serviceHTTPDenied(w, http.StatusForbidden)
		return
	}
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// adapt the shared browser UI without treating a managed ID as a public URL ID.
type serviceBrowserClient struct{ frontend ServiceHTTP }

func (a serviceBrowserClient) request(run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.ServiceBrowserRequest, error) {
	f := a.frontend
	if run != f.RunID || number != uint64(f.Number) || token != "" {
		return controlv1.ServiceBrowserRequest{}, ErrEndpoint
	}
	return controlv1.ServiceBrowserRequest{RunNumber: f.Number, Secret: secret}, nil
}
func (a serviceBrowserClient) RedeemBrowserHandoff(ctx context.Context, run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	input, err := a.request(run, number, secret, token)
	if err != nil {
		return controlv1.BrowserHandoffResponse{}, err
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
