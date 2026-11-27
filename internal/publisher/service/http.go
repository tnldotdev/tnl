package service

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

type HTTPControl interface {
	Discovery(context.Context) (controlv1.ControlDiscovery, error)
	httpaccess.PolicyClient
	httpaccess.TokenClient
	httpaccess.BrowserClient
	httpaccess.ShareClient
	nativeHTTPControl
	ControlURL() string
}

// HTTPRun contains the validated publication facts used by HTTP feature hooks.
// it contains no publisher, browser, or run credentials.
type HTTPRun struct {
	ServiceID, RunID, Hostname string
	Number                     int64
}

// http binds each request to one trusted forwarding header. policy and
// browser credential renewal are prepared once by the service run owner.
type HTTP struct {
	State                 LocalState
	AuditSink             serviceaudit.Sink
	InspectionMode        inspection.Mode
	ObserveSummary        inspection.Observer
	AdmitRequest          func(*http.Request) error
	PrepareRequest        func(*http.Request) (func(context.Context) error, error)
	ReadinessProof        *httpaccess.ReadinessProof
	ResponseHooks         httpstream.ResponseHooks
	Feedback              bool
	PreviewID             string
	ProjectService        string
	ProjectRoot           string
	FeedbackProjectID     string
	Demo                  bool
	PublicEndpoint        bool
	BrowserLoginAvailable *bool
	Control               HTTPControl
	Subject               visitorscope.Scope
	RunID                 string
	Number                int64
	Token                 credentials.ServiceRunToken
	Hostname              string
	RunHostname           string
	Port                  uint16
	Header                tunnelv1.ServiceForwardingHeader
	Source                netip.AddrPort
	Requests              *requestlimit.HTTP
	Policy                *visitorlease.Lease
	ReserveCapacity       func(context.Context) error
	browser               *httpaccess.Browser
	nativeHTTP
	probes       *requestlimit.HTTP
	preparations chan struct{}
	alias        *HTTP
}

func PrepareHTTP(ctx context.Context, f HTTP) (HTTP, func() error, error) {
	return prepareHTTP(ctx, f, nil)
}

func prepareHTTP(ctx context.Context, f HTTP, primary *HTTP) (HTTP, func() error, error) {
	baseHooks := f.ResponseHooks
	if f.RunHostname != "" {
		canonical, err := naming.CanonicalizeHostname(f.RunHostname)
		if err != nil || canonical != f.RunHostname || f.RunHostname == f.Hostname {
			return HTTP{}, nil, servicestream.ErrEndpoint
		}
	}
	if err := validateFeedbackPlatform(f.Feedback, f.Demo, f.PreviewID); err != nil {
		return HTTP{}, nil, err
	}
	if f.Control == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || !f.InspectionMode.Valid() ||
		!opaqueid.Valid(f.RunID, opaqueid.ServiceRunPrefix) || f.Number < 1 || f.Token == "" {
		return HTTP{}, nil, servicestream.ErrEndpoint
	}
	controlURL, err := naming.CanonicalControlURL(f.Control.ControlURL())
	if err != nil {
		return HTTP{}, nil, servicestream.ErrEndpoint
	}
	if f.PublicEndpoint {
		if f.BrowserLoginAvailable == nil {
			discovery, err := f.Control.Discovery(ctx)
			if err != nil {
				return HTTP{}, nil, err
			}
			f.BrowserLoginAvailable = new(discovery.BrowserLoginAvailable != nil && *discovery.BrowserLoginAvailable)
		} else {
			f.BrowserLoginAvailable = new(*f.BrowserLoginAvailable)
		}
	}
	if primary == nil {
		if err := f.prepareNativeHTTP(ctx); err != nil {
			return HTTP{}, nil, err
		}
		f.probes, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(4)})
		if err != nil {
			return HTTP{}, nil, err
		}
		f.preparations = make(chan struct{}, 16)
	} else {
		f.probes, f.preparations = primary.probes, primary.preparations
	}
	policy, err := httpaccess.PreparePolicy(ctx, f.Control, f.Subject, f.RunID, f.Number, f.Token.String(), nil, f.Hostname)
	if err != nil {
		return HTTP{}, nil, err
	}
	tokens, err := httpaccess.StartTokens(ctx, f.Control, policy.Lease(), nil)
	if err != nil {
		policy.Close()
		return HTTP{}, nil, err
	}
	f.Policy = policy.Lease()
	f.browser = &httpaccess.Browser{Subject: f.Subject, Client: f.Control, RunID: f.RunID, Number: f.Number, Token: f.Token, Hostname: f.Hostname, ControlURL: controlURL, Policy: policy, Tokens: tokens}
	if err := f.startNativeHTTP(); err != nil {
		tokens.Close()
		policy.Close()
		return HTTP{}, nil, err
	}
	closePrimary := func() error {
		tokens.Close()
		policy.Close()
		return f.closeNativeHTTP(ctx)
	}
	if f.PublicEndpoint && f.RunHostname != "" {
		// the alias has its own host-bound visitor credentials, but shares this
		// run's request budget and target proxy. both policy owners are joined.
		binding := f
		binding.Hostname, binding.RunHostname = f.RunHostname, ""
		binding.ReadinessProof, binding.ResponseHooks, binding.alias = nil, baseHooks, nil
		binding.nativeHTTP = nativeHTTP{}
		alias, closeAlias, err := prepareHTTP(ctx, binding, &f)
		if err != nil {
			return HTTP{}, nil, errors.Join(err, closePrimary())
		}
		f.alias = &alias
		return f, func() error { return errors.Join(closeAlias(), closePrimary()) }, nil
	}
	return f, closePrimary, nil
}

func (f HTTP) Forward(ctx context.Context, client *tls.Conn, target servicestream.HTTPTarget) error {
	hostname, hostnameErr := naming.CanonicalizeHostname(client.ConnectionState().ServerName)
	if f.alias != nil && hostnameErr == nil && hostname == f.RunHostname {
		alias := *f.alias
		alias.Header, alias.Source, alias.ReserveCapacity = f.Header, f.Source, f.ReserveCapacity
		return alias.Forward(ctx, client, target)
	}
	h := f.Header
	if f.ReserveCapacity == nil || f.Policy == nil || f.ReadinessProof != nil && f.probes == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || h.PublicService == nil || h.ServiceID != f.Subject.ID || h.ServiceRunID != f.RunID || h.RunNumber != uint64(f.Number) || h.PublicService.DestinationPort != f.Port || f.Port != 443 || h.Validate() != nil {
		return servicestream.ErrEndpoint
	}
	source, err := netip.ParseAddr(h.SourceIP)
	if err != nil || source.Zone() != "" || !f.Source.IsValid() || f.Source.Port() == 0 ||
		f.Source.Addr().Zone() != "" || f.Source.Addr().Unmap() != source.Unmap() {
		return servicestream.ErrEndpoint
	}
	view, enabled, _ := f.Policy.Current()
	if !enabled || view.Scope != f.Subject || view.Hostname != f.Hostname || view.Port != f.Port {
		return servicestream.ErrEndpoint
	}
	// ingress reserves capacity for this connection. every request still needs
	// its own local access check before it can use that capacity.
	var capacityReserved atomic.Bool
	reserveCapacity := func(ctx context.Context) error {
		if capacityReserved.Load() {
			return ctx.Err()
		}
		ctx, cancel := context.WithDeadline(ctx, h.ExpiresAt)
		defer cancel()
		if err := f.ReserveCapacity(ctx); err != nil {
			return err
		}
		capacityReserved.Store(true)
		return ctx.Err()
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
			state := client.ConnectionState()
			hostname, nameErr := naming.CanonicalizeHostname(state.ServerName)
			if !serviceendpoint.MatchesHTTPAuthority(f.Hostname, f.Port, r.Host) || nameErr != nil || hostname != f.Hostname {
				servicestream.DenyHTTP(w, r, http.StatusMisdirectedRequest)
				return
			}
			// set the verified source and TLS state before dispatching reserved
			// paths or applying visitor policy to application requests.
			r.RemoteAddr = f.Source.String()
			r.TLS = &state
			if code := proxy.ValidateRequest(r, f.Hostname); code != "" {
				diagnostic.WriteHTTP(w, r, code, "")
				return
			}
			if f.reserved(w, r, nil) {
				// browser preparation does not claim application access.
				reported = true
				return
			}
			proof := len(state.PeerCertificates) == 0 && f.ReadinessProof.Consume(r, httpaccess.ReadinessRun{Subject: f.Subject, ID: f.RunID, Number: uint64(f.Number), Hostname: f.Hostname})
			r.Header.Del(httpstream.ReadinessProbeHeader)
			if f.AdmitRequest != nil {
				if err := f.AdmitRequest(r); err != nil {
					outcome, reason = "failed", "unavailable"
					servicestream.DenyHTTP(w, r, http.StatusServiceUnavailable)
					return
				}
			}
			if proof {
				// an owner probe bypasses visitor login, not current run authority.
				// its separate bounded budget cannot spend application requests.
				reported = true
				if _, enabled, _ := f.Policy.Current(); !enabled {
					servicestream.DenyHTTP(w, r, http.StatusServiceUnavailable)
					return
				}
				r = httpstream.WithReadinessProbe(r)
				release, ok := f.probes.Admit(w, r)
				if !ok {
					return
				}
				defer release()
				probe, cancel := context.WithTimeout(r.Context(), 5*time.Second)
				defer cancel()
				r = r.WithContext(probe)
				if _, enabled, _ := f.Policy.Current(); !enabled {
					servicestream.DenyHTTP(w, r, http.StatusServiceUnavailable)
					return
				}
				r = httpstream.WithVisitorHost(serviceApplicationRequest(r), f.Hostname)
				next.ServeHTTP(w, r)
				return
			}
			var commit func(context.Context) error
			if f.PrepareRequest != nil {
				var err error
				commit, err = f.PrepareRequest(r)
				if err != nil {
					outcome, reason = "failed", "unavailable"
					servicestream.DenyHTTP(w, r, http.StatusServiceUnavailable)
					return
				}
			}
			var tokens *httpaccess.Tokens
			if f.browser != nil {
				tokens = f.browser.Tokens
			}
			_, guard, guarded, err := httpaccess.AuthorizeRequest(w, r, f.Policy, tokens)
			if err != nil {
				reason = "authorization"
				if f.browser.RedirectRestricted(w, r, f.BrowserLoginAvailable != nil && *f.BrowserLoginAvailable) {
					return
				}
				servicestream.DenyHTTP(w, r, servicestream.HTTPDecisionStatus(err))
				return
			}
			defer guard.Finish()
			w, r = guard, guarded
			reservation, ok := f.Requests.Reserve(w, r)
			if !ok {
				reason = "capacity"
				return
			}
			defer reservation.Finish()
			if err := reserveCapacity(r.Context()); err != nil {
				reservation.Refund()
				var capacity *tunnel.ProtocolError
				if errors.As(err, &capacity) && capacity != nil && capacity.Code == tunnelv1.CapacityExceeded && failure.Only(err, capacity) {
					reason = "capacity"
					if r.ProtoMajor == 1 {
						w.Header().Set("Connection", "close")
					}
					_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(5 * time.Second))
					w.Header().Set("Retry-After", "1")
					diagnostic.WriteHTTP(w, r, diagnostic.RequestLimitReached, "saturated")
					return
				}
				outcome, reason = "failed", "unavailable"
				servicestream.DenyHTTP(w, r, http.StatusServiceUnavailable)
				return
			}
			if commit != nil {
				if err := commit(r.Context()); err != nil {
					reservation.Refund()
					outcome, reason = "failed", "unavailable"
					servicestream.DenyHTTP(w, r, http.StatusServiceUnavailable)
					return
				}
			}
			r = httpstream.WithVisitorHost(f.ConnectorApplication(w, r), f.Hostname)
			// report the decision before an upgrade or long-lived response.
			outcome, reason = "allowed", ""
			report()
			observability.PublisherHTTPApplicationEntered(r.Context())
			next.ServeHTTP(w, r)
		})
	}
	return target.Serve(ctx, client, f.Hostname, wrap, f.ResponseHooks)
}

// reserved handles /__tnl/ paths without forwarding them to the application.
// connector is nil on the public path; otherwise it carries the verified
// admission from the connector stream, not from an HTTP header.
func (f HTTP) reserved(w http.ResponseWriter, r *http.Request, connector *servicestream.ConnectorHTTPAuthorization) bool {
	if !strings.HasPrefix(r.URL.Path, "/__tnl/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodConnect || r.URL.IsAbs() || r.URL.Host != "" || r.Header.Get("Upgrade") != "" ||
		r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
		servicestream.DenyHTTP(w, r, http.StatusForbidden)
		return true
	}
	if f.handleNativeReserved(w, r, connector) {
		return true
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		servicestream.DenyHTTP(w, r, http.StatusForbidden)
		return true
	}
	if f.browser != nil && (strings.HasPrefix(r.URL.Path, "/__tnl/team/") || httpaccess.SharePath(r.URL.Path)) {
		select {
		case f.preparations <- struct{}{}:
			// cancellation requests a stop; the slot remains held through the
			// actual return of browser/share work, including its cleanup.
			defer func() { <-f.preparations }()
		default:
			w.Header().Set("Retry-After", "1")
			diagnostic.WriteHTTP(w, r, diagnostic.RequestLimitReached, "")
			return true
		}
		preparation, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		r = r.WithContext(preparation)
	}
	if f.browser != nil && f.browser.Handle(w, r) {
		return true
	}
	if f.browser != nil && httpaccess.SharePath(r.URL.Path) && r.Method == http.MethodGet {
		f.share(w, r)
		return true
	}
	http.NotFound(w, r)
	return true
}

func (f HTTP) ConnectorReserved(w http.ResponseWriter, r *http.Request, authorization servicestream.ConnectorHTTPAuthorization) bool {
	if !strings.HasPrefix(r.URL.Path, "/__tnl/") {
		return false
	}
	facts := authorization.Permission.Facts()
	if authorization.ServiceID != f.Subject.ID || authorization.RunID != f.RunID || authorization.RunNumber != uint64(f.Number) ||
		!opaqueid.Valid(authorization.PairID, "cpp_") || authorization.DeliveryGeneration < 1 ||
		!authorization.Source.IsValid() || authorization.Source.IsUnspecified() || authorization.Source.Zone() != "" ||
		!authorization.ValidUntil.After(time.Now()) || !authorization.Permission.Valid() || facts.Scope != f.Subject ||
		facts.Hostname != f.Hostname || authorization.PermissionToken == "" {
		servicestream.DenyHTTP(w, r, http.StatusForbidden)
		return true
	}
	if _, err := visitortoken.ConnectorSubject(facts.Subject); err != nil {
		servicestream.DenyHTTP(w, r, http.StatusForbidden)
		return true
	}
	// HTTP cannot replace the connector's admitted subject with a bearer.
	for key := range r.Header {
		if strings.EqualFold(key, httpaccess.VisitorTokenHeader) || strings.EqualFold(key, "Tnl-Access-Token") {
			servicestream.DenyHTTP(w, r, http.StatusForbidden)
			return true
		}
	}
	if httpaccess.SuppliedCookieCount(r, httpaccess.VisitorTokenCookie) != 0 {
		servicestream.DenyHTTP(w, r, http.StatusForbidden)
		return true
	}
	r.RemoteAddr = netip.AddrPortFrom(authorization.Source.Unmap(), 1).String()
	return f.reserved(w, r, &authorization)
}

func (f HTTP) ConnectorApplication(w http.ResponseWriter, r *http.Request) *http.Request {
	return serviceApplicationRequest(f.prepareNativeApplication(w, r))
}

func serviceApplicationRequest(r *http.Request) *http.Request {
	r = httpaccess.StripCookies(r)
	r.Header.Del(httpaccess.VisitorTokenHeader)
	r.Header.Del("Tnl-Access-Token")
	r.Header.Del("Forwarded")
	r.Header.Del("X-Real-IP")
	for key := range r.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-forwarded-") {
			r.Header.Del(key)
		}
	}
	return r
}

func (f HTTP) share(w http.ResponseWriter, r *http.Request) {
	access := httpaccess.Shares{Client: f.Control, Browser: f.browser}
	redemption, err := access.Redeem(r.Context(), r.URL.Path)
	if err != nil {
		servicestream.DenyHTTP(w, r, servicestream.HTTPDecisionStatus(err))
		return
	}
	httpaccess.ShareRedirect(w, r, redemption)
}

var _ servicestream.HTTPFrontend = HTTP{}
var _ servicestream.ConnectorHTTPFrontend = HTTP{}
