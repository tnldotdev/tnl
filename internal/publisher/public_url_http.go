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
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/failure/diagnostic"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/observability/serviceaudit"
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/certificateidentity"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"go.opentelemetry.io/otel/trace"
)

type denialContextKey struct{}
type shareConnectionKey struct{}

// NewPublicURLServer creates a public URL server served by publisher connections.
func NewPublicURLServer(config PublicURLServerConfig) (*PublicURLServer, error) {
	if config.StreamCapacity == 0 {
		config.StreamCapacity = trafficlimits.Default().Connections
	}
	if config.StreamCapacity < 1 || config.StreamCapacity > 1<<20 {
		return nil, errors.New("publisher stream capacity must be between 1 and 1048576")
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
	admission, err := newApplicationAdmission(config.Limits)
	if err != nil {
		return nil, err
	}
	config.Limits = admission.limits
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
	if config.Handler != nil {
		handler = config.Handler
	} else {
		hooks := publisherproxy.ResponseHooks{ModifyHTML: modifyResponse, Observe: config.ObserveResponse, ObserveStatus: observe, OnForwarded: func(request *http.Request) {
			if request != nil {
				if forwarded, ok := request.Context().Value(responseOriginKey{}).(*atomic.Bool); ok {
					forwarded.Store(true)
				}
			}
		}}
		if config.ResolveTarget != nil {
			handler, err = publisherproxy.NewWithMountsHooksOptionsAdmittedDynamic(config.Target, hostname, config.Limits.Concurrency, config.Mounts, hooks, config.TargetOptions,
				func(request *http.Request) (string, string, error) { return config.ResolveTarget(request.Context()) }, config.OnTargetFailure)
		} else {
			handler, err = publisherproxy.NewWithMountsHooksOptionsAdmitted(config.Target, hostname, config.Limits.Concurrency, config.Mounts, hooks, config.TargetOptions, config.OnTargetFailure)
		}
		if err != nil {
			return nil, err
		}
	}
	queue := newRouteListener()
	shareSlots := make(chan struct{}, 16)
	probeSlots := make(chan struct{}, 4)
	base := config.Context
	if base == nil {
		base = context.Background()
	}
	base = observability.NarrowIdentity(base, observability.Identity{PublicURLID: config.PublicURLID})
	base = observability.WithFields(base, observability.Fields{Component: "publisher", ServiceProtocol: observability.ProtocolHTTP, AccessPath: "direct", Exposure: "public"})
	base = observability.WithPublisherRecovery(base)
	life, cancelLife := context.WithCancel(context.WithoutCancel(base))
	route := &PublicURLServer{
		hostname:       hostname,
		admission:      admission,
		streamCapacity: config.StreamCapacity,
		policy:         config.VisitorPolicy,
		run:            PublishRunIdentity{Hostname: hostname, PublicURLID: config.PublicURLID, PublishRunID: config.PublishRunID, Number: config.PublishRunNumber},
		promote:        config.PromoteVisitor,
		guard:          config.AdmitVisitor,
		life:           life, cancel: cancelLife,
		certificatePlan: config.CertificatePlan,
		queue:           queue,
		bodyTimeout:     httpstream.RequestBodyTimeout,
		tls: &tls.Config{
			MinVersion:             tls.VersionTLS12,
			NextProtos:             []string{"h2", "http/1.1"},
			SessionTicketsDisabled: true,
		},
		http: &http.Server{
			BaseContext: func(net.Listener) context.Context { return life },
			Handler: observability.PublisherHTTP(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
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
				if config.ObserveSummary != nil && config.InspectionMode != inspection.None && !strings.HasPrefix(request.URL.Path, "/__tnl/") {
					started := time.Now()
					observationContext := request.Context()
					forwarded := &atomic.Bool{}
					request = request.WithContext(context.WithValue(request.Context(), responseOriginKey{}, forwarded))
					tracked := &observedResponseWriter{ResponseWriter: response}
					response = tracked
					defer func() {
						interrupted := recover()
						path := request.URL.EscapedPath()
						if len(path) > 512 {
							path = path[:512]
						}
						origin := "tnl"
						if forwarded.Load() {
							origin = "local_service"
						}
						status := tracked.status
						if status == 0 {
							status = http.StatusOK
						}
						result := inspection.HTTPResult(status)
						if interrupted != nil || tracked.err != nil || observationContext.Err() != nil {
							result = inspection.ResultError
						}
						config.ObserveSummary(inspection.Summary{Protocol: "http", ReceivedAt: started.UTC(), Method: request.Method,
							Path: path, Status: status, Result: result, Duration: time.Since(started), Origin: origin})
						if interrupted != nil {
							panic(interrupted)
						}
					}()
				}
				if code := publisherproxy.ValidateRequest(request, hostname); code != "" {
					diagnostic.WriteHTTP(response, request, code)
					return
				}
				proof := config.ReadinessProof.consume(request, PublishRunIdentity{Hostname: hostname, PublicURLID: config.PublicURLID, PublishRunID: config.PublishRunID, Number: config.PublishRunNumber})
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
						diagnostic.WriteHTTP(response, request, code)
						return
					}
				}
				var shareExpiry time.Time
				sharePermitted := false
				if sharePath(request.URL.EscapedPath()) {
					response.Header().Set("Cache-Control", "no-store")
					response.Header().Set("Referrer-Policy", "no-referrer")
					select {
					case shareSlots <- struct{}{}:
						defer func() { <-shareSlots }()
					default:
						response.Header().Set("Retry-After", "1")
						diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached)
						return
					}
					if config.ShareAccess == nil {
						diagnostic.WriteHTTP(response, request, diagnostic.VisitorAccessDenied)
						return
					}
					if connection, ok := request.Context().Value(shareConnectionKey{}).(*tls.Conn); ok {
						_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
					}
					redemption, err := config.ShareAccess.redeem(request.Context(), request.URL.EscapedPath())
					if err != nil {
						diagnostic.WriteHTTP(response, request, diagnostic.VisitorAccessDenied)
						return
					}
					if connection, ok := request.Context().Value(shareConnectionKey{}).(*tls.Conn); ok {
						_ = connection.SetDeadline(time.Time{})
					}
					auditOutcome, auditReason = "allowed", ""
					shareRedirect(response, redemption)
					return
				}
				if config.BrowserAccess != nil {
					if strings.HasPrefix(request.URL.Path, "/__tnl/team/") {
						select {
						case shareSlots <- struct{}{}:
							defer func() { <-shareSlots }()
						default:
							response.Header().Set("Retry-After", "1")
							diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached)
							return
						}
						if connection, ok := request.Context().Value(shareConnectionKey{}).(*tls.Conn); ok {
							_ = connection.SetDeadline(time.Now().Add(15 * time.Second))
							defer connection.SetDeadline(time.Time{})
						}
						if config.BrowserAccess.handle(response, request) {
							return
						}
					}
				}
				// visitor credentials are checked here, after publisher TLS. this
				// request never asks control for a permission or refreshes a cache.
				serverPermitted := false
				var permission httpPermission
				if !proof {
					var err error
					permission, err = localHTTPPermission(request, config.VisitorPolicy, config.VisitorTokens)
					serverPermitted = err == nil
					if serverPermitted {
						guard, guarded, err := guardLocalHTTPRequest(response, request, config.VisitorPolicy, permission)
						if err != nil {
							serverPermitted = false
						} else {
							defer guard.finish()
							if config.VisitorTokens != nil && !permission.anonymous {
								prepared, release, found := config.VisitorTokens.use(permission.token, guard.local)
								guard.release = release
								if found && (permission.renewed || prepared.VisitorToken != permission.token.Reveal()) {
									_ = visitorPermissionCookie(response, prepared)
								}
							}
							response, request = guard, guarded
						}
					}
				}
				if share, ok := permission.permission.Subject.(visitortoken.Share); ok && share.ShareID != "" && serverPermitted {
					sharePermitted, shareExpiry = true, permission.permission.ExpiresAt
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
					if config.BrowserLoginAvailable && config.BrowserAccess != nil && config.BrowserAccess.redirectRestricted(response, request) {
						return
					}
					diagnostic.WriteHTTP(response, request, diagnostic.VisitorAccessDenied)
					return
				}
				auditOutcome, auditReason = "allowed", ""
				if config.Feedback != nil {
					if config.Feedback.handle(response, request, !allowed) {
						return
					}
					request = config.Feedback.prepareBrowser(response, request)
				}
				request = stripTnlCookies(request)
				request.Header.Del(shareAccessHeaderName)
				if proof {
					select {
					case probeSlots <- struct{}{}:
						defer func() { <-probeSlots }()
					default:
						diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached)
						return
					}
					probeCtx, cancel := context.WithTimeout(request.Context(), 5*time.Second)
					defer cancel()
					request = request.WithContext(probeCtx)
					if session, _ := request.Context().Value(visitorSessionKey{}).(*visitorSession); session != nil {
						if err := session.admit(probeCtx, true); err != nil {
							diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached)
							return
						}
					}
					handler.ServeHTTP(response, request)
					return
				}
				release, status, retryAfter := admission.acquire(request.Context())
				if status != 0 {
					auditOutcome, auditReason = "failed", "capacity"
					if request.ProtoMajor == 1 {
						// avoid draining an unread body before sending the rejection.
						response.Header().Set("Connection", "close")
					}
					if retryAfter > 0 {
						response.Header().Set("Retry-After", strconv.FormatInt(retryAfterSeconds(retryAfter), 10))
					}
					switch status {
					case http.StatusTooManyRequests:
						diagnostic.WriteHTTP(response, request, diagnostic.RequestRateLimited)
					case http.StatusServiceUnavailable:
						if retryAfter == 0 {
							diagnostic.WriteHTTP(response, request, diagnostic.RequestBudgetExhausted)
						} else {
							diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached, "saturated")
						}
					}
					return
				}
				if session, _ := request.Context().Value(visitorSessionKey{}).(*visitorSession); session != nil {
					if err := session.admit(request.Context(), proof); err != nil {
						auditOutcome, auditReason = "failed", "capacity"
						admission.refund()
						diagnostic.WriteHTTP(response, request, diagnostic.RequestLimitReached)
						return
					}
				}
				if request.Context().Err() != nil {
					auditOutcome, auditReason = "failed", "cancelled"
					admission.refund()
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
		streams:            make(map[net.Conn]struct{}),
	}
	route.tls.GetCertificate = route.getCertificate
	if len(config.Certificate.Certificate) != 0 || config.Certificate.PrivateKey != nil {
		if err := route.InstallCertificate(config.Certificate); err != nil {
			_ = route.Close()
			return nil, err
		}
	}
	return route, nil
}
