package publisher

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/publisher/requestlimit"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/tlspolicy"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"go.opentelemetry.io/otel/trace"
)

type denialContextKey struct{}
type shareConnectionKey struct{}

// NewPublicURLServer creates a public URL server served by publisher connections.
func NewPublicURLServer(config PublicURLServerConfig) (*PublicURLServer, error) {
	target, err := normalizeHTTPMode(config.Target, config.Handler, config.ResolveTarget, config.Mounts, config.TargetOptions, config.TargetTLSName, config.Purpose)
	if err != nil {
		return nil, err
	}
	config.Target = target
	if config.StreamCapacity == 0 {
		config.StreamCapacity = trafficlimits.Default().Connections
	}
	if config.StreamCapacity < 1 || config.StreamCapacity > 1<<20 {
		return nil, errors.New("public URL stream capacity must be between 1 and 1048576")
	}
	if config.ServiceProtocol == "" || config.ServiceProtocol == controlv1.Http {
		if config.TargetTLSName != "" {
			config.TargetOptions.ServerName = config.TargetTLSName
		}
	}
	hostname, err := naming.CanonicalizeHostname(config.Hostname)
	if err != nil || hostname != config.Hostname {
		return nil, errors.New("publisher: public URL hostname must be canonical")
	}
	if config.InspectionMode != "" && !config.InspectionMode.Valid() {
		return nil, errors.New("publisher: request inspection mode must be none or summary")
	}
	if config.ServiceProtocol != "" && config.ServiceProtocol != controlv1.Http {
		return nil, errors.New("publisher: public URL server requires HTTP; use a private stream for TCP")
	}
	admission, err := requestlimit.New(config.Limits)
	if err != nil {
		return nil, err
	}
	config.Limits = admission.Limits()
	if config.CertificatePlan.Identifiers != nil || config.CertificatePlan.CacheKey != "" || config.CertificatePlan.Scope != "" || config.CertificatePlan.ChallengeMethod != "" {
		config.CertificatePlan, err = certificateidentity.CanonicalPlan(config.CertificatePlan)
		if err != nil || !certificateidentity.Covers(config.CertificatePlan.Identifiers, hostname) {
			return nil, errors.New("publisher: certificate plan does not cover public URL")
		}
	}
	var modifyResponse func(*http.Response) error
	var observe func(*http.Request, int)
	if config.Feedback != nil {
		modifyResponse, observe = config.Feedback.modifyResponse, config.Feedback.observe
	}
	var handler http.Handler
	var proxy *publisherproxy.Proxy
	if config.Handler != nil {
		handler = config.Handler
	} else {
		hooks := publisherproxy.ResponseHooks{ModifyHTML: modifyResponse, Observe: config.ObserveResponse, ObserveStatus: observe, OnForwarded: func(request *http.Request) {
			inspection.ApplicationResponse(request)
		}}
		proxyConfig := publisherproxy.Config{
			Target: config.Target, Hostname: hostname, Mounts: config.Mounts,
			Hooks: hooks, TargetOptions: config.TargetOptions,
			MaxConnsPerHost: config.Limits.Concurrency, OnTargetFailure: config.OnTargetFailure,
		}
		if config.ResolveTarget != nil {
			proxyConfig.ResolveTarget = func(request *http.Request) (string, string, error) {
				return config.ResolveTarget(request.Context())
			}
		}
		proxy, err = publisherproxy.New(proxyConfig)
		if err != nil {
			return nil, err
		}
		handler = proxy
	}
	queue := newRouteListener()
	shareSlots := make(chan struct{}, 16)
	probeSlots := make(chan struct{}, 4)
	base := config.Context
	if base == nil {
		base = context.Background()
	}
	base = observability.NarrowIdentity(base, observability.Identity{PublicURLID: config.PublicURLID})
	base = observability.WithFields(base, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "public_endpoint", Exposure: "public"})
	base = observability.WithPublisherRecovery(base)
	life, cancelLife := context.WithCancel(context.WithoutCancel(base))
	route := &PublicURLServer{
		proxy:            proxy,
		hostname:         hostname,
		policy:           config.VisitorPolicy,
		visitorSourceKey: config.VisitorSourceKey,
		streamCapacity:   config.StreamCapacity,
		admission:        admission,
		run:              PublishRunIdentity{Hostname: hostname, PublicURLID: config.PublicURLID, PublishRunID: config.PublishRunID, Number: config.PublishRunNumber},
		promote:          config.PromoteVisitor,
		guard:            config.AdmitVisitor,
		life:             life, cancel: cancelLife,
		certificatePlan: config.CertificatePlan,
		queue:           queue,
		bodyTimeout:     httpstream.RequestBodyTimeout,
		tls: &tls.Config{
			MinVersion:             tls.VersionTLS13,
			NextProtos:             []string{"h2", "http/1.1"},
			SessionTicketsDisabled: true,
		},
		http: &http.Server{
			BaseContext: func(net.Listener) context.Context { return life },
			Handler: observability.PublisherHTTP(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				session, _ := request.Context().Value(visitorSessionKey{}).(*visitorSession)
				if session == nil || !session.beginRequest() {
					diagnostic.WriteHTTP(response, request, diagnostic.RequestRejected, "")
					return
				}
				defer session.requests.Done()
				auditOutcome, auditReason := "denied", "invalid_request"
				auditReport := true
				auditSent := false
				emitAudit := func() {
					if auditSent {
						return
					}
					auditSent = true
					if !auditReport || config.AuditSink == nil {
						return
					}
					session, _ := request.Context().Value(visitorSessionKey{}).(*visitorSession)
					if session == nil || session.visitor.Header.VisitorConnectionID == "" {
						return
					}
					serviceaudit.Emit(config.AuditSink, serviceaudit.Observation{ServiceID: config.PublicURLID, ServiceKind: "public_url", RunID: config.PublishRunID, RunNumber: int64(config.PublishRunNumber), VisitorConnectionID: session.visitor.Header.VisitorConnectionID, SourceIP: session.visitor.Source.Addr().Unmap().String(), EventType: "http.decision", Outcome: auditOutcome, Reason: auditReason})
				}
				defer emitAudit()
				response, request, finishInspection := inspection.BeginHTTP(response, request, config.InspectionMode, config.ObserveSummary)
				defer finishInspection()
				if code := publisherproxy.ValidateRequest(request, hostname); code != "" {
					diagnostic.WriteHTTP(response, request, code, "")
					return
				}
				proof := config.ReadinessProof.Consume(request, httpaccess.ReadinessRun{Subject: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: config.PublicURLID}, Hostname: hostname, ID: config.PublishRunID, Number: config.PublishRunNumber})
				request.Header.Del(publisherproxy.ReadinessProbeHeader)
				if proof {
					auditReport = false
					request = publisherproxy.WithReadinessProbe(request)
				}
				if config.AdmitRequest != nil {
					if err := config.AdmitRequest(request); err != nil {
						auditReason = "authorization"
						code, ok := diagnostic.CodeOf(err)
						if !ok {
							code = diagnostic.ServerUnavailable
						}
						diagnostic.WriteHTTP(response, request, code, "")
						return
					}
				}
				var shareExpiry time.Time
				sharePermitted := false
				if httpaccess.SharePath(request.URL.EscapedPath()) {
					response.Header().Set("Cache-Control", "no-store")
					response.Header().Set("Referrer-Policy", "no-referrer")
					select {
					case shareSlots <- struct{}{}:
						defer func() { <-shareSlots }()
					default:
						response.Header().Set("Retry-After", "1")
						diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "")
						return
					}
					if config.ShareAccess == nil {
						diagnostic.WriteHTTP(response, request, diagnostic.VisitorAccessDenied, "")
						return
					}
					if connection, ok := request.Context().Value(shareConnectionKey{}).(*tls.Conn); ok {
						_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
					}
					redemption, err := config.ShareAccess.Redeem(request.Context(), request.URL.EscapedPath())
					if err != nil {
						diagnostic.WriteHTTP(response, request, diagnostic.VisitorAccessDenied, "")
						return
					}
					if connection, ok := request.Context().Value(shareConnectionKey{}).(*tls.Conn); ok {
						_ = connection.SetDeadline(time.Time{})
					}
					auditOutcome, auditReason = "allowed", ""
					httpaccess.ShareRedirect(response, redemption)
					return
				}
				if config.BrowserAccess != nil {
					if strings.HasPrefix(request.URL.Path, "/__tnl/team/") {
						select {
						case shareSlots <- struct{}{}:
							defer func() { <-shareSlots }()
						default:
							response.Header().Set("Retry-After", "1")
							diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "")
							return
						}
						if connection, ok := request.Context().Value(shareConnectionKey{}).(*tls.Conn); ok {
							_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
							defer connection.SetDeadline(time.Time{})
						}
						if config.BrowserAccess.Handle(response, request) {
							return
						}
					}
				}
				// visitor credentials are checked here, after publisher TLS. this
				// request never asks control for a permission or refreshes a cache.
				serverPermitted := false
				var permission visitortoken.VerifiedPermission
				if !proof {
					var guard *httpaccess.Guard
					var guarded *http.Request
					var err error
					// the accepted visitor owns source metadata; HTTP forwarding
					// headers and socket defaults cannot replace it.
					request.RemoteAddr = session.visitor.Source.String()
					permission, guard, guarded, err = httpaccess.AuthorizeRequest(response, request, config.VisitorPolicy, config.VisitorTokens)
					serverPermitted = err == nil
					if serverPermitted {
						defer guard.Finish()
						response, request = guard, guarded
					}
				}
				if share, ok := permission.Facts().Subject.(visitortoken.Share); ok && share.ShareID != "" && serverPermitted {
					sharePermitted, shareExpiry = true, permission.Facts().ExpiresAt
				} else {
					sharePermitted = false
				}
				allowed := proof || serverPermitted
				if request.URL.Path == "/__tnl/access" {
					if request.Method != http.MethodGet || config.PreviewID == "" {
						http.NotFound(response, request)
						return
					}
					result := previewAccessStatus(config, serverPermitted, sharePermitted, false, shareExpiry)
					request = request.WithContext(context.WithValue(request.Context(), accessStatusContextKey{}, result))
					(&feedbackHTTP{}).GetBrowserAccessStatus(response, request)
					return
				}
				if !allowed {
					auditReason = "authorization"
					if config.BrowserAccess.RedirectRestricted(response, request, config.BrowserLoginAvailable) {
						return
					}
					diagnostic.WriteHTTP(response, request, diagnostic.VisitorAccessDenied, "")
					return
				}
				auditOutcome, auditReason = "allowed", ""
				if config.Feedback != nil {
					if config.Feedback.handle(response, request, !allowed) {
						return
					}
					request = config.Feedback.prepareBrowser(response, request)
				}
				request = httpaccess.StripCookies(request)
				request.Header.Del(httpaccess.ShareHeaderName)
				if proof {
					select {
					case probeSlots <- struct{}{}:
						defer func() { <-probeSlots }()
					default:
						diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "")
						return
					}
					probeCtx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
					defer cancel()
					request = request.WithContext(probeCtx)
					if err := session.admit(probeCtx, true); err != nil {
						diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "")
						return
					}
					handler.ServeHTTP(response, request)
					return
				}
				release, status, retryAfter := admission.Acquire(request.Context())
				if status != 0 {
					auditOutcome, auditReason = "failed", "capacity"
					if request.ProtoMajor == 1 {
						// avoid draining an unread body before sending the rejection.
						response.Header().Set("Connection", "close")
					}
					if retryAfter > 0 {
						response.Header().Set("Retry-After", strconv.FormatInt(requestlimit.RetryAfterSeconds(retryAfter), 10))
					}
					switch status {
					case http.StatusTooManyRequests:
						diagnostic.WriteHTTP(response, request, diagnostic.RequestRateLimited, "")
					case http.StatusServiceUnavailable:
						if retryAfter == 0 {
							diagnostic.WriteHTTP(response, request, diagnostic.RequestBudgetExhausted, "")
						} else {
							diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "saturated")
						}
					}
					return
				}
				if err := session.admit(request.Context(), proof); err != nil {
					auditOutcome, auditReason = "failed", "capacity"
					admission.Refund()
					diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "")
					return
				}
				if request.Context().Err() != nil {
					auditOutcome, auditReason = "failed", "cancelled"
					admission.Refund()
					return
				}
				defer release()
				emitAudit()
				handler.ServeHTTP(response, request)
			})),
			ConnContext: func(ctx context.Context, connection net.Conn) context.Context {
				if secured, ok := connection.(*tls.Conn); ok {
					if tracked, ok := secured.NetConn().(*doneConn); ok {
						if metadata, ok := tracked.Conn.(*metadataConn); ok {
							// retain net/http's server values and request cancellation;
							// only the visitor's span parent belongs on this context.
							ctx = trace.ContextWithSpan(ctx, trace.SpanFromContext(metadata.session.life))
							ctx = observability.WithVisitor(ctx, metadata.session.visitor.Header.VisitorConnectionID)
							ctx = context.WithValue(ctx, shareConnectionKey{}, secured)
							ctx = context.WithValue(ctx, visitorSessionKey{}, metadata.session)
							return context.WithValue(ctx, denialContextKey{}, metadata.denied)
						}
					}
				}
				// an unrecognized connection must never bypass visitor policy.
				return context.WithValue(ctx, denialContextKey{}, true)
			},
			ReadHeaderTimeout: 10 * time.Second,
			IdleTimeout:       2 * time.Minute,
			MaxHeaderBytes:    64 << 10,
			ErrorLog:          log.New(io.Discard, "", 0),
		},
		httpDone:           make(chan error, 1),
		certificateExpired: make(chan struct{}),
		streams:            make(map[net.Conn]*publicVisitorAdmission),
	}
	route.tls.GetCertificate = route.getCertificate
	if config.RequirePostQuantum {
		route.tls = tlspolicy.RequirePostQuantum(route.tls)
	}
	if len(config.Certificate.Certificate) != 0 || config.Certificate.PrivateKey != nil {
		if err := route.InstallCertificate(config.Certificate); err != nil {
			_ = route.Close()
			return nil, err
		}
	}
	return route, nil
}
