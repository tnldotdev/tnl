package publisher

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/serviceaudit"
	"github.com/tnldotdev/tnl/internal/tunnel"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"go.opentelemetry.io/otel/trace"
)

// PublicURLServerConfig configures publisher TLS termination and local HTTP forwarding.
type PublicURLServerConfig struct {
	Context               context.Context
	AuditSink             serviceaudit.Sink
	Hostname              string
	PreviewID             string
	PublicURLID           string
	PublishRunNumber      uint64
	PublishRunID          string
	Target                string
	ResolveTarget         func(context.Context) (string, string, error)
	ServiceProtocol       controlv1.PublicURLServiceProtocol
	Purpose               controlv1.PublicURLPurpose
	AccessMode            controlv1.VisitorAccessMode
	TargetTLSName         string
	TargetOptions         localproxy.TargetOptions
	Handler               http.Handler
	AdmitRequest          func(*http.Request) error
	ObserveResponse       func(*http.Response) error
	Mounts                []localproxy.Mount
	ShareAccess           *shareAccess
	BrowserAccess         *browserAccess
	BrowserLoginAvailable bool
	Feedback              *feedbackRuntime
	Limits                ApplicationLimits
	OnTargetFailure       func()
	ObserveSummary        inspection.Observer
	PromoteVisitor        PromoteVisitor
	AdmitVisitor          AdmitVisitor
	ReadinessProof        *ReadinessProof
	OnWarning             func(string)
	InspectionMode        inspection.Mode
	Certificate           tls.Certificate
	CertificatePlan       controlv1.CertificatePlan
}

type PublicURLServer struct {
	hostname              string
	certificatePlan       controlv1.CertificatePlan
	tls                   *tls.Config
	certificate           atomic.Pointer[tls.Certificate]
	certificateTimer      *time.Timer
	certificateExpired    chan struct{}
	queue                 *publicURLListener
	http                  *http.Server
	mu                    sync.Mutex
	started               bool
	closed                bool
	draining              bool
	streams               map[net.Conn]struct{}
	visitorPolicyRevision int64
	handlers              sync.WaitGroup
	httpDone              chan error
	closeOnce             sync.Once
	closeErr              error
	admission             *applicationAdmission
	run                   PublishRunIdentity
	promote               PromoteVisitor
	defaultPromote        PromoteVisitor
	guard                 AdmitVisitor
	life                  context.Context
	cancel                context.CancelFunc
	sessions              [publisherConnectionCount]*livePublisherSession
}

type denialContextKey struct{}
type shareConnectionKey struct{}
type responseOriginKey struct{}

// Unwrap lets net/http's response controller retain flushing and upgrades.
type observedResponseWriter struct {
	http.ResponseWriter
	status int
}

func (w *observedResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *observedResponseWriter) WriteHeader(status int) {
	if w.status == 0 && (status >= http.StatusOK || status == http.StatusSwitchingProtocols) {
		w.status = status
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponseWriter) Write(data []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	n, err := w.ResponseWriter.Write(data)
	return n, err
}

// NewPublicURLServer creates a public URL server served by publisher connections.
func NewPublicURLServer(config PublicURLServerConfig) (*PublicURLServer, error) {
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
		hooks := localproxy.ResponseHooks{ModifyHTML: modifyResponse, Observe: config.ObserveResponse, ObserveStatus: observe, OnForwarded: func(request *http.Request) {
			if request != nil {
				if forwarded, ok := request.Context().Value(responseOriginKey{}).(*atomic.Bool); ok {
					forwarded.Store(true)
				}
			}
		}}
		if config.ResolveTarget != nil {
			handler, err = localproxy.NewWithMountsHooksOptionsAdmittedDynamic(config.Target, hostname, config.Limits.Concurrency, config.Mounts, hooks, config.TargetOptions,
				func(request *http.Request) (string, string, error) { return config.ResolveTarget(request.Context()) }, config.OnTargetFailure)
		} else {
			handler, err = localproxy.NewWithMountsHooksOptionsAdmitted(config.Target, hostname, config.Limits.Concurrency, config.Mounts, hooks, config.TargetOptions, config.OnTargetFailure)
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
	base = observability.WithFields(base, observability.Fields{Component: "publisher", ServiceProtocol: "http", AccessPath: "direct", Exposure: "public"})
	base = observability.WithPublisherRecovery(base)
	life, cancelLife := context.WithCancel(context.WithoutCancel(base))
	route := &PublicURLServer{
		hostname:  hostname,
		admission: admission,
		run:       PublishRunIdentity{Hostname: hostname, PublicURLID: config.PublicURLID, PublishRunID: config.PublishRunID, Number: config.PublishRunNumber},
		promote:   config.PromoteVisitor,
		guard:     config.AdmitVisitor,
		life:      life, cancel: cancelLife,
		certificatePlan: config.CertificatePlan,
		queue:           queue,
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
					forwarded := &atomic.Bool{}
					request = request.WithContext(context.WithValue(request.Context(), responseOriginKey{}, forwarded))
					tracked := &observedResponseWriter{ResponseWriter: response}
					response = tracked
					defer func() {
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
						config.ObserveSummary(inspection.Summary{Protocol: "http", ReceivedAt: started.UTC(), Method: request.Method,
							Path: path, Status: status, Result: inspection.HTTPResult(status), Duration: time.Since(started), Origin: origin})
					}()
				}
				if code := localproxy.ValidateRequest(request, hostname); code != "" {
					diagnostic.WriteHTTP(response, request, code)
					return
				}
				proof := config.ReadinessProof.consume(request, PublishRunIdentity{Hostname: hostname, PublicURLID: config.PublicURLID, PublishRunID: config.PublishRunID, Number: config.PublishRunNumber})
				request.Header.Del(localproxy.ReadinessProbeHeader)
				if proof {
					auditReport = false
					request = localproxy.WithReadinessProbe(request)
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
				denied := request.Context().Value(denialContextKey{}) == true
				var shareExpiry time.Time
				sharePermitted := false
				if config.ShareAccess != nil {
					shareExpiry, sharePermitted = config.ShareAccess.permission(request)
				}
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
						if config.BrowserAccess.handle(response, request, !denied || sharePermitted) {
							return
						}
					}
				}
				// the publisher can inspect browser credentials that ingress cannot.
				// check each request against the bounded, run-scoped decision,
				// including requests on an already-promoted visitor connection.
				serverPermitted := false
				browser := controlv1.BrowserAccessResponse{}
				if !proof && config.BrowserAccess != nil {
					decision, err := config.BrowserAccess.decision(request)
					if err == nil {
						serverPermitted = decision.VisitAllowed
						if decision.IdentityId != nil && decision.DisplayName != nil {
							browser = controlv1.BrowserAccessResponse{IdentityId: *decision.IdentityId, DisplayName: *decision.DisplayName,
								TeamMember: decision.TeamMember && decision.VisitAllowed, VisitAllowed: decision.VisitAllowed}
							request = request.WithContext(context.WithValue(request.Context(), browserIdentityKey{}, browser))
						}
					}
				}
				// cached share state is only a hint for the browser UI. the bounded
				// control decision, including its revocation deadline, owns admission.
				sharePermitted = sharePermitted && serverPermitted
				integrationRequest := (config.Purpose == controlv1.Oauth || config.Purpose == controlv1.Webhooks) && config.AccessMode == controlv1.Anonymous && !denied
				allowed := proof || serverPermitted || integrationRequest
				if request.URL.Path == "/__tnl/access" {
					if request.Method != http.MethodGet || config.PreviewID == "" {
						http.NotFound(response, request)
						return
					}
					result := previewAccessStatus(config, serverPermitted, sharePermitted, serverPermitted && browser.TeamMember, shareExpiry)
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
			// bound incomplete bodies with a real read deadline. for HTTP/2,
			// net/http enforces this independently on each request stream.
			ReadTimeout:    30 * time.Second,
			IdleTimeout:    2 * time.Minute,
			MaxHeaderBytes: 64 << 10,
			ErrorLog:       log.New(io.Discard, "", 0),
		},
		httpDone:           make(chan error, 1),
		certificateExpired: make(chan struct{}),
		streams:            make(map[net.Conn]struct{}),
	}
	transportPromote := tunnel.NewVisitorPromoter(func(v Visitor) tunnelv1.VisitorStreamHeader { return v.Header }, route.resolvePublisherSession)
	route.defaultPromote = func(ctx context.Context, visitor Visitor) error {
		if route.resolvePublisherSession(visitor.Header.PublisherConnectionID) == nil {
			return &tunnel.ProtocolError{Code: tunnelv1.Unavailable}
		}
		return transportPromote(ctx, visitor)
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

func (r *PublicURLServer) InstallCertificate(certificate tls.Certificate) error {
	copy := certificate
	if len(copy.Certificate) == 0 || copy.PrivateKey == nil {
		return errors.New("publisher: application certificate and private key are required")
	}
	var err error
	if len(r.certificatePlan.Identifiers) != 0 {
		copy.Leaf, err = certificateidentity.ValidateCertificate(copy, r.hostname, r.certificatePlan.Identifiers)
	} else {
		copy.Leaf, err = x509.ParseCertificate(copy.Certificate[0])
		if err == nil {
			err = copy.Leaf.VerifyHostname(r.hostname)
		}
	}
	if err != nil {
		return fmt.Errorf("publisher: invalid application certificate: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return net.ErrClosed
	}
	select {
	case <-r.certificateExpired:
		return errCertificateExpired
	default:
	}
	if r.certificateTimer != nil {
		r.certificateTimer.Stop()
	}
	installed := &copy
	r.certificate.Store(installed)
	r.certificateTimer = time.AfterFunc(max(time.Until(copy.Leaf.NotAfter), 0), func() {
		r.mu.Lock()
		r.expireCertificateLocked(installed)
		r.mu.Unlock()
	})
	return nil
}

func (r *PublicURLServer) certificateExpiration() <-chan struct{} { return r.certificateExpired }

func (r *PublicURLServer) withValidCertificate(call func() error) error {
	r.mu.Lock()
	certificate := r.certificate.Load()
	if certificate == nil {
		r.mu.Unlock()
		return errors.New("publisher: application certificate is not installed")
	}
	select {
	case <-r.certificateExpired:
		r.mu.Unlock()
		return errCertificateExpired
	default:
	}
	if !certificate.Leaf.NotAfter.After(time.Now()) {
		if r.certificateTimer != nil {
			r.certificateTimer.Stop()
		}
		r.expireCertificateLocked(certificate)
		r.mu.Unlock()
		return errCertificateExpired
	}
	r.mu.Unlock()
	return call()
}

func (r *PublicURLServer) expireCertificateLocked(certificate *tls.Certificate) {
	if r.closed || r.certificate.Load() != certificate {
		return
	}
	select {
	case <-r.certificateExpired:
		return
	default:
		r.certificateTimer = nil
		close(r.certificateExpired)
	}
}

func (r *PublicURLServer) getCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	if hello == nil {
		return nil, errors.New("publisher: TLS SNI does not match public URL")
	}
	if hello.ServerName == "" {
		return nil, errors.New("publisher: TLS SNI does not match public URL")
	} else {
		hostname, err := naming.CanonicalizeHostname(hello.ServerName)
		if err != nil || hostname != r.hostname {
			return nil, errors.New("publisher: TLS SNI does not match public URL")
		}
	}
	certificate := r.certificate.Load()
	if certificate == nil {
		return nil, errors.New("publisher: application certificate is not installed")
	}
	if !certificate.Leaf.NotAfter.After(time.Now()) {
		return nil, errCertificateExpired
	}
	return certificate, nil
}

// Start starts publisher TLS termination and local HTTP forwarding.
func (r *PublicURLServer) Start() error {
	return r.start()
}

func (r *PublicURLServer) start() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return net.ErrClosed
	}
	if r.started {
		r.mu.Unlock()
		return errors.New("publisher: public URL already started")
	}
	r.started = true
	r.mu.Unlock()
	r.startHTTP()
	return nil
}

// ServePublisherConnection accepts visitor streams for one exact publisher
// connection. on exit it closes the session to stop pending header reads;
// callers may also close it to interrupt active streams.
func (r *PublicURLServer) ServePublisherConnection(
	ctx context.Context,
	session *tunnel.Session,
	ref tunnelv1.PublisherConnectionRef,
) error {
	if session == nil {
		return errors.New("publisher: tunnel session is required")
	}
	if err := ref.Validate(); err != nil {
		return err
	}
	live, err := r.registerPublisherSession(ctx, session, ref)
	if err != nil {
		return err
	}
	defer r.unregisterPublisherSession(live)
	ctx = live.ctx
	// bound header parsing while letting a slow or invalid stream coexist with
	// healthy streams on the same publisher connection.
	const headerReaders = 4
	acceptCtx, cancel := context.WithCancel(ctx)
	var readers sync.WaitGroup
	defer func() {
		cancel()
		_ = session.Close()
		readers.Wait()
	}()
	results := make(chan error, headerReaders)
	for range headerReaders {
		readers.Go(func() {
			for {
				incoming, err := session.AcceptVisitorStream(acceptCtx)
				if err != nil {
					var headerErr *tunnel.StreamHeaderError
					if errors.As(err, &headerErr) {
						continue
					}
					results <- err
					return
				}
				if acceptCtx.Err() != nil {
					_ = incoming.Stream.Close()
					return
				}
				if err := r.acceptVisitorContext(acceptCtx, incoming, ref); err != nil {
					results <- err
					return
				}
			}
		})
	}
	select {
	case <-ctx.Done():
		return nil
	case err := <-results:
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
}

func (r *PublicURLServer) acceptVisitorContext(ctx context.Context, incoming *tunnel.IncomingVisitorStream, ref tunnelv1.PublisherConnectionRef) error {
	code := r.validateIncomingPublicURL(incoming.Header, ref)
	r.mu.Lock()
	if r.closed || r.draining {
		code = tunnelv1.Unavailable
	}
	if code != "" {
		r.mu.Unlock()
		_ = incoming.Reject(code)
		return nil
	}
	r.streams[incoming.Stream] = struct{}{}
	r.handlers.Add(1)
	r.mu.Unlock()
	if err := incoming.Accept(); err != nil {
		r.mu.Lock()
		delete(r.streams, incoming.Stream)
		r.mu.Unlock()
		r.handlers.Done()
		return err
	}
	go func() {
		defer r.handlers.Done()
		defer func() {
			r.mu.Lock()
			delete(r.streams, incoming.Stream)
			r.mu.Unlock()
		}()
		r.handleVisitorHeaderContext(incoming.Context(), incoming.Stream, incoming.Header.AccessPending, incoming.Header)
	}()
	return nil
}

func (r *PublicURLServer) validateIncomingPublicURL(
	header tunnelv1.VisitorStreamHeader,
	ref tunnelv1.PublisherConnectionRef,
) tunnelv1.ErrorCode {
	if header.PublicURLID != ref.PublicURLID || header.PublishRunID != ref.PublishRunID ||
		header.PublishRunNumber != ref.PublishRunNumber {
		return tunnelv1.StalePublishRunNumber
	}
	if header.PublisherConnectionID != ref.PublisherConnectionID ||
		header.ConnectionAssignmentRevision != ref.ConnectionAssignmentRevision {
		return tunnelv1.StaleConnectionAssignment
	}
	return ""
}

func (r *PublicURLServer) Drain(ctx context.Context) error {
	r.stopAdmissions()
	return r.http.Shutdown(ctx)
}

func (r *PublicURLServer) stopAdmissions() {
	r.mu.Lock()
	r.draining = true
	r.mu.Unlock()
	r.http.SetKeepAlivesEnabled(false)
}

// invalidateVisitorPolicy closes existing application streams, including HTTP
// upgrades. the run and publisher connections continue admitting fresh visitors.
func (r *PublicURLServer) invalidateVisitorPolicy(revision int64) {
	r.mu.Lock()
	if revision <= r.visitorPolicyRevision {
		r.mu.Unlock()
		return
	}
	previous := r.visitorPolicyRevision
	r.visitorPolicyRevision = revision
	var streams []net.Conn
	if previous > 0 {
		for stream := range r.streams {
			streams = append(streams, stream)
		}
	}
	r.mu.Unlock()
	for _, stream := range streams {
		_ = stream.Close()
	}
}

func (r *PublicURLServer) Close() error {
	r.closeOnce.Do(func() {
		if r.cancel != nil {
			r.cancel()
		}
		r.mu.Lock()
		r.closed = true
		if r.certificateTimer != nil {
			r.certificateTimer.Stop()
			r.certificateTimer = nil
		}
		started := r.started
		streams := make([]net.Conn, 0, len(r.streams))
		for stream := range r.streams {
			streams = append(streams, stream)
		}
		r.mu.Unlock()
		result := errors.Join(r.http.Close(), r.queue.Close())
		for _, stream := range streams {
			_ = stream.Close()
		}
		r.handlers.Wait()
		if started {
			result = errors.Join(result, <-r.httpDone)
		}
		r.closeErr = result
	})
	return r.closeErr
}

func (r *PublicURLServer) startHTTP() {
	go func() {
		err := r.http.Serve(r.queue)
		if errors.Is(err, http.ErrServerClosed) || errors.Is(err, net.ErrClosed) {
			err = nil
		}
		r.httpDone <- err
		close(r.httpDone)
	}()
}

func (r *PublicURLServer) handle(connection net.Conn) {
	r.handleVisitor(connection, false)
}

func (r *PublicURLServer) handleVisitor(connection net.Conn, denied bool) {
	r.handleVisitorHeader(connection, denied, tunnelv1.VisitorStreamHeader{})
}

func (r *PublicURLServer) handleVisitorHeader(connection net.Conn, denied bool, streamHeader tunnelv1.VisitorStreamHeader) {
	r.handleVisitorHeaderContext(r.life, connection, denied, streamHeader)
}

func (r *PublicURLServer) handleVisitorHeaderContext(parent context.Context, connection net.Conn, denied bool, streamHeader tunnelv1.VisitorStreamHeader) {
	defer connection.Close()
	if parent == nil {
		parent = context.Background()
	}
	parent = observability.NarrowIdentity(parent, observability.Identity{PublicURLID: r.run.PublicURLID})
	parent = observability.WithFields(parent, observability.Fields{Component: "publisher", ServiceProtocol: "http", AccessPath: "direct", Exposure: "public"})
	parent = observability.WithVisitor(parent, streamHeader.VisitorConnectionID)
	life, cancel := context.WithCancel(parent)
	defer cancel()
	life, endVisitor := observability.Start(life, "publisher.visitor")
	var visitorErr error
	defer func() { endVisitor(visitorErr) }()
	stopClose := context.AfterFunc(life, func() { _ = connection.Close() })
	defer stopClose()
	_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
	header, replay, err := proxyproto.Decode(connection)
	if err != nil {
		visitorErr = err
		return
	}
	promote := r.promote
	if promote == nil && streamHeader.PublisherConnectionID != "" {
		promote = r.defaultPromote
	}
	streamHeader.AccessPending = denied
	session := &visitorSession{visitor: Visitor{Run: r.run, Header: streamHeader, Source: header.Source, Destination: header.Destination}, promote: promote, guard: r.guard, life: life, cancel: cancel}
	defer session.close()
	var pendingTimer *time.Timer
	if denied {
		pendingTimer = time.AfterFunc(visitorPromotionTimeout, cancel)
		defer pendingTimer.Stop()
	}
	session.onPromoted = func() {
		if pendingTimer != nil {
			pendingTimer.Stop()
		}
		// net/http owns request-body read deadlines. clearing both deadlines
		// here would let incomplete bodies hold application slots indefinitely.
		_ = connection.SetWriteDeadline(time.Time{})
	}
	metadata := &metadataConn{Conn: &publicURLReaderConn{Conn: connection, reader: replay}, header: header, denied: denied, session: session}
	tracked := newDoneConn(metadata)
	secured := tls.Server(tracked, r.tls)
	ctx, cancelHandshake := context.WithTimeout(life, 10*time.Second)
	ctx = observability.WithVisitor(ctx, streamHeader.VisitorConnectionID)
	ctx, finish := observability.PublisherOperation(ctx, "visitor_tls")
	err = secured.HandshakeContext(ctx)
	visitorErr = err
	observability.PublisherTLS(ctx, "visitor", secured.ConnectionState(), err)
	finish(err)
	cancelHandshake()
	if err != nil {
		_ = secured.Close()
		return
	}
	if denied {
		_ = secured.SetDeadline(time.Now().Add(visitorPromotionTimeout))
	} else {
		_ = secured.SetDeadline(time.Time{})
	}
	if !r.queue.enqueue(secured) {
		_ = secured.Close()
		return
	}
	<-tracked.done
}

type publicURLListener struct {
	connections chan net.Conn
	closed      chan struct{}
	mu          sync.Mutex
	isClosed    bool
	once        sync.Once
}

func newRouteListener() *publicURLListener {
	return &publicURLListener{connections: make(chan net.Conn, 64), closed: make(chan struct{})}
}

func (l *publicURLListener) Accept() (net.Conn, error) {
	select {
	case connection := <-l.connections:
		return connection, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *publicURLListener) Close() error {
	l.once.Do(func() {
		l.mu.Lock()
		l.isClosed = true
		close(l.closed)
		for {
			select {
			case connection := <-l.connections:
				_ = connection.Close()
			default:
				l.mu.Unlock()
				return
			}
		}
	})
	return nil
}

func (*publicURLListener) Addr() net.Addr { return publicURLAddress("tnl-route") }

func (l *publicURLListener) enqueue(connection net.Conn) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.isClosed {
		return false
	}
	select {
	case l.connections <- connection:
		return true
	default:
		return false
	}
}

type publicURLAddress string

func (publicURLAddress) Network() string  { return "tnl" }
func (a publicURLAddress) String() string { return string(a) }

type publicURLReaderConn struct {
	net.Conn
	reader io.Reader
}

func (c *publicURLReaderConn) Read(destination []byte) (int, error) {
	return c.reader.Read(destination)
}

type metadataConn struct {
	net.Conn
	header  proxyproto.Header
	denied  bool
	session *visitorSession
}

func (c *metadataConn) Close() error {
	if c.session != nil && c.session.cancel != nil {
		c.session.cancel()
	}
	return c.Conn.Close()
}

func (c *publicURLReaderConn) CloseWrite() error { return closeWrite(c.Conn) }
func (c *metadataConn) CloseWrite() error        { return closeWrite(c.Conn) }

func closeWrite(conn net.Conn) error {
	if half, ok := conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return nil
}

func (c *metadataConn) RemoteAddr() net.Addr { return tcpAddress(c.header.Source) }
func (c *metadataConn) LocalAddr() net.Addr  { return tcpAddress(c.header.Destination) }

func tcpAddress(endpoint netip.AddrPort) net.Addr {
	return &net.TCPAddr{IP: net.IP(endpoint.Addr().AsSlice()), Port: int(endpoint.Port())}
}

type doneConn struct {
	net.Conn
	done chan struct{}
	once sync.Once
}

func newDoneConn(connection net.Conn) *doneConn {
	return &doneConn{Conn: connection, done: make(chan struct{})}
}

func (c *doneConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(func() { close(c.done) })
	return err
}
