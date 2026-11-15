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
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/serviceendpoint"
	"github.com/tnldotdev/tnl/internal/policy/visitorlease"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"

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
	AuthorizeServiceHTTPVisitor(context.Context, string, string, credentials.ServiceRunToken, controlv1.AuthorizeServiceHTTPVisitorRequest) (controlv1.ServiceClientCertificateDecision, error)
}

// HTTPRun contains the validated publication facts used by response observers.
// it contains no publisher, browser, or run credentials.
type HTTPRun struct {
	ServiceID, RunID, Hostname string
	Number                     int64
}

// http binds each request to one trusted forwarding header. policy and
// browser credential renewal are prepared once by the service run owner.
type HTTP struct {
	AuditSink      serviceaudit.Sink
	InspectionMode inspection.Mode
	ObserveSummary inspection.Observer
	AdmitRequest   func(*http.Request) error
	ReadinessProof *httpaccess.ReadinessProof
	ResponseHooks  httpstream.ResponseHooks
	Feedback       bool
	PreviewID      string
	ProjectService string
	ProjectRoot    string
	Demo           bool
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
	feedback       *feedbackRuntime
	probes         *requestlimit.HTTP
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
	if f.Control == nil || f.Policy == nil || f.ReadinessProof != nil && f.probes == nil || f.Subject.Kind != visitorscope.Service || !f.Subject.Valid() || h.PublicService == nil || h.ServiceID != f.Subject.ID || h.ServiceRunID != f.RunID || h.RunNumber != uint64(f.Number) || h.PublicService.DestinationPort != f.Port || f.Port != 443 || h.Validate() != nil {
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
	// ingress admission belongs to this exact visitor connection. each HTTP
	// request still needs its own local permission and policy guard.
	var admitted atomic.Bool
	admit := func(ctx context.Context) error {
		if admitted.Load() {
			return ctx.Err()
		}
		ctx, cancel := context.WithDeadline(ctx, h.ExpiresAt)
		defer cancel()
		result, err := awaitServiceVisitorAdmission(ctx, func(ctx context.Context) (controlv1.ServiceClientCertificateDecision, error) {
			return f.Control.AuthorizeServiceHTTPVisitor(ctx, f.Subject.ID, f.RunID, f.Token, controlv1.AuthorizeServiceHTTPVisitorRequest{
				RunNumber: f.Number, VisitorConnectionId: h.VisitorConnectionID, SourceIp: source.Unmap().String(), DestinationPort: 443,
			})
		})
		if err != nil {
			return err
		}
		if !result.Allowed || !result.Admitted {
			return servicestream.ErrEndpoint
		}
		admitted.Store(true)
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
			if !serviceendpoint.MatchesHTTPAuthority(f.Hostname, f.Port, r.Host) || r.Method == http.MethodConnect || r.URL.IsAbs() || r.URL.Host != "" || client.ConnectionState().ServerName != f.Hostname {
				servicestream.DenyHTTP(w, http.StatusMisdirectedRequest)
				return
			}
			// only the validated forwarding header supplies the visitor source.
			// reserved feedback requests need these same TLS and source facts.
			r.RemoteAddr = netip.AddrPortFrom(source.Unmap(), 1).String()
			state := client.ConnectionState()
			r.TLS = &state
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
					servicestream.DenyHTTP(w, http.StatusServiceUnavailable)
					return
				}
			}
			if proof {
				// an owner probe bypasses visitor login, not current run authority.
				// its separate bounded budget cannot spend application requests.
				reported = true
				if _, enabled, _ := f.Policy.Current(); !enabled {
					servicestream.DenyHTTP(w, http.StatusServiceUnavailable)
					return
				}
				r = httpstream.WithReadinessProbe(r)
				release, ok := f.probes.Admit(w, r)
				if !ok {
					return
				}
				defer release()
				if err := admit(r.Context()); err != nil {
					servicestream.DenyHTTP(w, http.StatusServiceUnavailable)
					return
				}
				if _, enabled, _ := f.Policy.Current(); !enabled {
					servicestream.DenyHTTP(w, http.StatusServiceUnavailable)
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
				servicestream.DenyHTTP(w, servicestream.HTTPDecisionStatus(err))
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
			if err := admit(r.Context()); err != nil {
				reservation.Refund()
				outcome, reason = "failed", "unavailable"
				servicestream.DenyHTTP(w, http.StatusServiceUnavailable)
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
		servicestream.DenyHTTP(w, http.StatusForbidden)
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
				servicestream.DenyHTTP(w, servicestream.HTTPDecisionStatus(err))
				return true
			}
			writePreviewAccessStatus(w, previewAccessStatus(f, authorization.permission, err == nil))
			return true
		}
		if err != nil {
			servicestream.DenyHTTP(w, servicestream.HTTPDecisionStatus(err))
			return true
		}
		if guard != nil {
			w = guard
		}
		f.feedback.handle(w, guarded, authorization)
		return true
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		servicestream.DenyHTTP(w, http.StatusForbidden)
		return true
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
		servicestream.DenyHTTP(w, http.StatusForbidden)
		return true
	}
	if _, err := visitortoken.ConnectorSubject(facts.Subject); err != nil {
		servicestream.DenyHTTP(w, http.StatusForbidden)
		return true
	}
	// HTTP cannot replace the connector's admitted subject with a bearer.
	for key := range r.Header {
		if strings.EqualFold(key, httpaccess.VisitorTokenHeader) || strings.EqualFold(key, "Tnl-Access-Token") {
			servicestream.DenyHTTP(w, http.StatusForbidden)
			return true
		}
	}
	if httpaccess.SuppliedCookieCount(r, httpaccess.VisitorTokenCookie) != 0 {
		servicestream.DenyHTTP(w, http.StatusForbidden)
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

// awaitServiceVisitorAdmission uses the same ingress acknowledgment for HTTP and
// certificate visitors. permission alone never allows target bytes.
func awaitServiceVisitorAdmission(ctx context.Context, authorize func(context.Context) (controlv1.ServiceClientCertificateDecision, error)) (controlv1.ServiceClientCertificateDecision, error) {
	for {
		if err := ctx.Err(); err != nil {
			return controlv1.ServiceClientCertificateDecision{}, context.Cause(ctx)
		}
		result, err := authorize(ctx)
		if err != nil || !result.Allowed {
			return result, err
		}
		if !result.ValidUntil.After(time.Now()) {
			return controlv1.ServiceClientCertificateDecision{}, servicestream.ErrEndpoint
		}
		if result.Admitted {
			return result, ctx.Err()
		}
		observability.PublisherAuthorization(ctx, true, false, nil)
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			return controlv1.ServiceClientCertificateDecision{}, context.Cause(ctx)
		case <-timer.C:
		}
	}
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
		servicestream.DenyHTTP(w, servicestream.HTTPDecisionStatus(err))
		return
	}
	httpaccess.ShareRedirect(w, redemption)
}

var _ servicestream.HTTPFrontend = HTTP{}
var _ servicestream.ConnectorHTTPFrontend = HTTP{}
