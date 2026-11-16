package service

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
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
	httpaccess.PolicyClient
	httpaccess.TokenClient
	httpaccess.BrowserClient
	httpaccess.ShareClient
	FeedbackClient
	ControlURL() string
	CreateServiceRunPreview(context.Context, string, string, int64, credentials.ServiceRunToken) (controlv1.Preview, error)
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
	AuditSink       serviceaudit.Sink
	InspectionMode  inspection.Mode
	ObserveSummary  inspection.Observer
	AdmitRequest    func(*http.Request) error
	ReadinessProof  *httpaccess.ReadinessProof
	ResponseHooks   httpstream.ResponseHooks
	Feedback        bool
	PreviewID       string
	ProjectService  string
	ProjectRoot     string
	Demo            bool
	Control         HTTPControl
	Subject         visitorscope.Scope
	RunID           string
	Number          int64
	Token           credentials.ServiceRunToken
	Hostname        string
	Port            uint16
	Header          tunnelv1.ServiceForwardingHeader
	Source          netip.AddrPort
	Requests        *requestlimit.HTTP
	Policy          *visitorlease.Lease
	ReserveCapacity func(context.Context) error
	browser         *httpaccess.Browser
	feedback        *feedbackRuntime
	probes          *requestlimit.HTTP
	preparations    chan struct{}
}

func PrepareHTTP(ctx context.Context, f HTTP) (HTTP, func(), error) {
	if f.Control == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || !f.InspectionMode.Valid() ||
		!opaqueid.Valid(f.RunID, opaqueid.ServiceRunPrefix) || f.Number < 1 || f.Token == "" {
		return HTTP{}, nil, servicestream.ErrEndpoint
	}
	controlURL, err := naming.CanonicalControlURL(f.Control.ControlURL())
	if err != nil {
		return HTTP{}, nil, servicestream.ErrEndpoint
	}
	if f.Demo {
		// control creates or recovers this exact run's preview. never substitute
		// caller metadata or start browser/feedback work before validating it.
		preview, err := f.Control.CreateServiceRunPreview(ctx, f.Subject.ID, f.RunID, f.Number, f.Token)
		if err != nil {
			return HTTP{}, nil, fmt.Errorf("service: create demo feedback preview: %w", err)
		}
		if !opaqueid.Valid(preview.Id, opaqueid.PreviewPrefix) || preview.SchemaVersion != 1 ||
			len(preview.ServiceIds) != 1 || preview.ServiceIds[0] != f.Subject.ID {
			return HTTP{}, nil, failure.Wrap("create demo feedback preview", failure.ServerResponseInvalid,
				errors.New("preview has an invalid ID, schema, or service membership"))
		}
		f.PreviewID = preview.Id
	}
	f.probes, err = requestlimit.NewHTTP(&controlv1.ProjectHTTPApplicationLimits{Concurrency: new(4)})
	if err != nil {
		return HTTP{}, nil, err
	}
	f.preparations = make(chan struct{}, 16)
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
	f.browser = &httpaccess.Browser{Subject: f.Subject, Client: f.Control, PreviewID: f.PreviewID, RunID: f.RunID, Number: f.Number, Token: f.Token, ControlURL: controlURL, Policy: policy, Tokens: tokens}
	f.feedback, err = newFeedbackRuntime(f)
	if err != nil {
		tokens.Close()
		policy.Close()
		return HTTP{}, nil, err
	}
	if f.feedback != nil {
		f.ResponseHooks = f.feedback.responseHooks(f.ResponseHooks)
	}
	return f, func() { tokens.Close(); policy.Close() }, nil
}

func (f HTTP) Forward(ctx context.Context, client *tls.Conn, target servicestream.HTTPTarget) error {
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
			// only the validated forwarding metadata supplies the visitor source.
			// reserved feedback requests need these same TLS and source facts.
			r.RemoteAddr = f.Source.String()
			r.TLS = &state
			if code := proxy.ValidateRequest(r, f.Hostname); code != "" {
				diagnostic.WriteHTTP(w, r, code, "")
				return
			}
			if f.reserved(w, r, f.authorizeFeedback) {
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
			r = httpstream.WithVisitorHost(f.ConnectorApplication(w, r), f.Hostname)
			// report the decision before an upgrade or long-lived response.
			outcome, reason = "allowed", ""
			report()
			next.ServeHTTP(w, r)
		})
	}
	return target.Serve(ctx, client, f.Hostname, wrap, f.ResponseHooks)
}

func (f HTTP) authorizeFeedback(w http.ResponseWriter, r *http.Request) (feedbackAuthorization, *httpaccess.Guard, *http.Request, error) {
	var tokens *httpaccess.Tokens
	if f.browser != nil {
		tokens = f.browser.Tokens
	}
	authorization, guard, guarded, err := httpaccess.AuthorizeRequest(w, r, f.Policy, tokens)
	if err != nil {
		return feedbackAuthorization{permission: authorization.Permission()}, guard, guarded, err
	}
	access, err := bearerFeedbackAuthorization(authorization)
	return access, guard, guarded, err
}

// reserved composes the same service-owned handlers for public and connector
// HTTP. each path supplies its own admission; this code assumes no public header.
func (f HTTP) reserved(w http.ResponseWriter, r *http.Request, authorize func(http.ResponseWriter, *http.Request) (feedbackAuthorization, *httpaccess.Guard, *http.Request, error)) bool {
	if !strings.HasPrefix(r.URL.Path, "/__tnl/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodConnect || r.URL.IsAbs() || r.URL.Host != "" || r.Header.Get("Upgrade") != "" ||
		r.TLS != nil && len(r.TLS.PeerCertificates) != 0 {
		servicestream.DenyHTTP(w, r, http.StatusForbidden)
		return true
	}
	status := r.URL.Path == "/__tnl/access" && r.Method == http.MethodGet && f.PreviewID != ""
	if status || f.feedback != nil && strings.HasPrefix(r.URL.Path, "/__tnl/feedback") {
		authorization, guard, guarded, err := authorize(w, r)
		if guard != nil {
			defer guard.Finish()
		}
		if status {
			if err != nil && servicestream.HTTPDecisionStatus(err) != http.StatusForbidden {
				servicestream.DenyHTTP(w, r, servicestream.HTTPDecisionStatus(err))
				return true
			}
			writePreviewAccessStatus(w, previewAccessStatus(f, authorization.permission, err == nil))
			return true
		}
		if err != nil {
			servicestream.DenyHTTP(w, r, servicestream.HTTPDecisionStatus(err))
			return true
		}
		if guard != nil {
			w = guard
		}
		f.feedback.handle(w, guarded, authorization)
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
	return f.reserved(w, r, func(http.ResponseWriter, *http.Request) (feedbackAuthorization, *httpaccess.Guard, *http.Request, error) {
		access, err := connectorFeedbackAuthorization(authorization)
		return access, nil, r, err
	})
}

func (f HTTP) ConnectorApplication(w http.ResponseWriter, r *http.Request) *http.Request {
	if f.feedback != nil {
		r = f.feedback.prepareBrowser(w, r)
	}
	return serviceApplicationRequest(r)
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
	httpaccess.ShareRedirect(w, redemption)
}

var _ servicestream.HTTPFrontend = HTTP{}
var _ servicestream.ConnectorHTTPFrontend = HTTP{}
