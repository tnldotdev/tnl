package service

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/netip"
	"net/url"
	"strings"

	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type HTTPControl interface {
	httpaccess.PolicyClient
	httpaccess.TokenClient
	ControlURL() string
	RedeemServiceBrowserHandoff(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserHandoffResponse, error)
	CheckServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) (controlv1.BrowserAccessResponse, error)
	RevokeServiceBrowserSession(context.Context, string, string, credentials.ServiceRunToken, controlv1.ServiceBrowserRequest) error
}

// http binds each request to one trusted forwarding header. policy and
// browser credential renewal are prepared once by the service run owner.
type HTTP struct {
	AuditSink      serviceaudit.Sink
	InspectionMode inspection.Mode
	ObserveSummary inspection.Observer
	Control        HTTPControl
	Subject        visitorscope.Scope
	RunID          string
	Number         int64
	Token          credentials.ServiceRunToken
	Hostname       string
	Port           uint16
	Header         tunnelv1.ServiceForwardingHeader
	Requests       *requestlimit.HTTP
	Policy         *visitorlease.Lease
	browser        *httpaccess.Browser
}

func PrepareHTTP(ctx context.Context, f HTTP) (HTTP, func(), error) {
	if f.Control == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || !f.InspectionMode.Valid() {
		return HTTP{}, nil, servicestream.ErrEndpoint
	}
	policy, err := httpaccess.PreparePolicy(ctx, f.Control, f.Subject, f.RunID, f.Number, f.Token.String(), nil)
	if err != nil {
		return HTTP{}, nil, err
	}
	tokens, err := httpaccess.StartTokens(ctx, f.Control, policy.Lease(), nil)
	if err != nil {
		policy.Close()
		return HTTP{}, nil, err
	}
	f.Policy = policy.Lease()
	f.browser = &httpaccess.Browser{Subject: f.Subject, Client: serviceBrowserClient{f}, RunID: f.RunID, Number: uint64(f.Number), ControlURL: strings.TrimSuffix(f.Control.ControlURL(), "/"), Policy: policy, Tokens: tokens}
	return f, func() { tokens.Close(); policy.Close() }, nil
}

func (f HTTP) Forward(ctx context.Context, client *tls.Conn, target servicestream.HTTPTarget) error {
	h := f.Header
	if f.Policy == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || h.PublicService == nil || h.ServiceID != f.Subject.ID || h.ServiceRunID != f.RunID || h.RunNumber != uint64(f.Number) || h.PublicService.DestinationPort != f.Port || f.Port != 443 || h.Validate() != nil {
		return servicestream.ErrEndpoint
	}
	source, err := netip.ParseAddr(h.SourceIP)
	if err != nil || source.Zone() != "" {
		return servicestream.ErrEndpoint
	}
	view, enabled, _ := f.Policy.Current()
	if !enabled || view.Scope != f.Subject || view.Hostname != f.Hostname || view.Port != f.Port {
		return servicestream.ErrEndpoint
	}
	scheme := "http"
	if target.Transport.TLS != nil {
		scheme = "https"
	}
	wrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w, r, finishInspection := inspection.BeginHTTP(w, r, f.InspectionMode, f.ObserveSummary)
			defer finishInspection()
			w.Header().Set("Cache-Control", "no-store")
			outcome, reason := "denied", "invalid_request"
			reported := false
			report := func() {
				if reported {
					return
				}
				reported = true
				serviceaudit.Emit(f.AuditSink, serviceaudit.Observation{ServiceID: f.Subject.ID, ServiceKind: "service",
					RunID: f.RunID, RunNumber: f.Number, VisitorConnectionID: h.VisitorConnectionID,
					SourceIP: source.Unmap().String(), EventType: "http.decision", Outcome: outcome, Reason: reason})
			}
			defer report()
			if !serviceendpoint.MatchesHTTPAuthority(f.Hostname, f.Port, r.Host) || r.Method == http.MethodConnect || r.URL.IsAbs() || r.URL.Host != "" || client.ConnectionState().ServerName != f.Hostname {
				servicestream.DenyHTTP(w, http.StatusMisdirectedRequest)
				return
			}
			// explicit preparation endpoints never send application bytes. TLS
			// certificate holders cannot switch identity through browser endpoints.
			if strings.HasPrefix(r.URL.Path, "/__tnl/") {
				// browser preparation does not claim application access.
				reported = true
				if len(client.ConnectionState().PeerCertificates) != 0 || r.ContentLength != 0 || len(r.TransferEncoding) != 0 || r.Header.Get("Upgrade") != "" {
					servicestream.DenyHTTP(w, http.StatusForbidden)
					return
				}
				if f.browser != nil && f.browser.Handle(w, r) {
					return
				}
				if f.browser != nil && httpaccess.SharePath(r.URL.Path) && r.Method == http.MethodGet {
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
			var tokens *httpaccess.Tokens
			if f.browser != nil {
				tokens = f.browser.Tokens
			}
			_, guard, guarded, err := httpaccess.AuthorizeRequest(w, r, f.Policy, tokens)
			if err != nil {
				reason = "authorization"
				if f.browser.RedirectRestricted(w, r, true) {
					return
				}
				servicestream.DenyHTTP(w, servicestream.HTTPDecisionStatus(err))
				return
			}
			defer guard.Finish()
			w, r = guard, guarded
			release, ok := f.Requests.Admit(w, r)
			if !ok {
				reason = "capacity"
				return
			}
			defer release()
			r = httpaccess.StripCookies(r)
			r.Header.Del("Tnl-Access-Token")
			r.Header.Del("Forwarded")
			r.Header.Del("X-Real-IP")
			for key := range r.Header {
				if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
					r.Header.Del(key)
				}
			}
			// report the decision before an upgrade or long-lived response.
			outcome, reason = "allowed", ""
			report()
			next.ServeHTTP(w, r)
		})
	}
	if target.Handler != nil {
		return httpstream.ServeHandler(ctx, client, wrap(target.Handler))
	}
	return httpstream.Serve(ctx, client, &url.URL{Scheme: scheme, Host: target.Address}, target.Dial, wrap)
}

func (f HTTP) share(w http.ResponseWriter, r *http.Request) {
	source, err := json.Marshal(controlv1.VisitorTokenGrantSource{Kind: controlv1.VisitorTokenGrant, Credential: strings.TrimPrefix(r.URL.Path, "/__tnl/share/")})
	if err != nil {
		servicestream.DenyHTTP(w, 403)
		return
	}
	permission, err := f.Control.IssueVisitorToken(r.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: f.Subject.ID}, Source: source})
	if err != nil {
		servicestream.DenyHTTP(w, servicestream.HTTPDecisionStatus(err))
		return
	}
	// control rechecks the grant's parent on every renewal. the first short
	// permission is not the grant deadline.
	permission, err = f.browser.PrepareSessionToken(r.Context(), source, permission)
	if err != nil {
		servicestream.DenyHTTP(w, 503)
		return
	}
	if err := httpaccess.PermissionCookie(w, permission); err != nil {
		servicestream.DenyHTTP(w, 503)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: httpaccess.ShareCookieName, Value: strings.TrimPrefix(r.URL.Path, "/__tnl/share/"), Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	w.Header().Set("Referrer-Policy", "no-referrer")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

type serviceBrowserClient struct{ frontend HTTP }

func (a serviceBrowserClient) request(run string, number uint64, secret string, token credentials.PublishRunToken) (controlv1.ServiceBrowserRequest, error) {
	f := a.frontend
	if run != f.RunID || number != uint64(f.Number) || token != "" {
		return controlv1.ServiceBrowserRequest{}, servicestream.ErrEndpoint
	}
	return controlv1.ServiceBrowserRequest{RunNumber: f.Number, Secret: secret}, nil
}
func (a serviceBrowserClient) RedeemBrowserHandoff(ctx context.Context, run string, number uint64, secret, share, shareSecret string, token credentials.PublishRunToken) (controlv1.BrowserHandoffResponse, error) {
	input, err := a.request(run, number, secret, token)
	if err != nil || share != "" || shareSecret != "" {
		return controlv1.BrowserHandoffResponse{}, servicestream.ErrEndpoint
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

var _ servicestream.HTTPFrontend = HTTP{}
