package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	coreadmin "github.com/tnldotdev/tnl/internal/admin"
	"github.com/tnldotdev/tnl/internal/auth"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificates"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/routes"
	"github.com/tnldotdev/tnl/internal/sourcelimiter"
	"github.com/tnldotdev/tnl/internal/state"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"tailscale.com/types/key"
)

const (
	healthPath                = "/v1/health"
	readinessPath             = "/v1/ready"
	clientIPPath              = "/v1/client-ip"
	capabilitiesPath          = "/v1/capabilities"
	relayMapPath              = "/v1/transport/relay-map"
	tokenExchangePath         = "/v1/auth/token"
	oidcExchangePath          = "/v1/auth/oidc"
	refreshPath               = "/v1/auth/refresh"
	logoutPath                = "/v1/auth/logout"
	certificateIssuancesPath  = "/v1/certificate-issuances"
	certificateIssuancePrefix = "/v1/certificate-issuances/"
	hostnamesPath             = "/v1/hostnames"
	hostnamePrefix            = "/v1/hostnames/"
	domainVerificationsPath   = "/v1/domain-verifications"
	domainVerificationPrefix  = "/v1/domain-verifications/"
	routesPath                = "/v1/routes"
	routePathPrefix           = "/v1/routes/"
	authorizationHeader       = "Authorization"
	idempotencyKeyHeader      = "Idempotency-Key"
	requestIDHeader           = "X-Request-ID"
	maxCredentialBytes        = 128
	maxJSONRequestBytes       = 20 << 10
	maxJSONResponseBytes      = 64 << 10
	jsonReadTimeout           = 10 * time.Second
	readinessTimeout          = time.Second
)

var (
	errInvalidJSON          = errors.New("api: invalid JSON request")
	errResponseTooLarge     = errors.New("api: JSON response exceeds limit")
	errUnsupportedMediaType = errors.New("api: unsupported media type")
	errAuthServiceMissing   = errors.New("api: auth service is not configured")
	errRouteServiceMissing  = errors.New("api: route service is not configured")
	errCertServiceMissing   = errors.New("api: certificate service is not configured")
)

// Operation is a stable, low-cardinality API operation.
type Operation string

const (
	OperationUnknown                     Operation = "unknown"
	OperationHealthGet                   Operation = "health.get"
	OperationReadinessGet                Operation = "readiness.get"
	OperationClientIPGet                 Operation = "client_ip.get"
	OperationCapabilitiesGet             Operation = "capabilities.get"
	OperationRelayMapGet                 Operation = "transport.relay_map.get"
	OperationTokenExchange               Operation = "auth.token.exchange"
	OperationOIDCTokenExchange           Operation = "auth.oidc.exchange"
	OperationControlSessionRefresh       Operation = "auth.session.refresh"
	OperationControlSessionLogout        Operation = "auth.session.logout"
	OperationHostnamesList               Operation = "hostnames.list"
	OperationHostnameAdd                 Operation = "hostnames.add"
	OperationHostnameRemove              Operation = "hostnames.remove"
	OperationDomainVerificationCreate    Operation = "domain_verifications.create"
	OperationDomainVerificationGet       Operation = "domain_verifications.get"
	OperationDomainVerificationComplete  Operation = "domain_verifications.complete"
	OperationRoutesList                  Operation = "routes.list"
	OperationRouteCreate                 Operation = "routes.create"
	OperationRouteDelete                 Operation = "routes.delete"
	OperationRouteSessionCreate          Operation = "routes.session.create"
	OperationRouteTransportRegister      Operation = "routes.transport.register"
	OperationRouteHeartbeat              Operation = "routes.heartbeat"
	OperationRouteReady                  Operation = "routes.ready"
	OperationCertificateIssuanceCreate   Operation = "certificate_issuances.create"
	OperationCertificateIssuanceGet      Operation = "certificate_issuances.get"
	OperationCertificateChallengeReady   Operation = "certificate_issuances.challenge_ready"
	OperationCertificateChallengeRemoved Operation = "certificate_issuances.challenge_removed"
	OperationCertificateInstalled        Operation = "certificate_issuances.installed"
	OperationAdminServerStatus           Operation = "admin.server.status"
	OperationAdminRoutesList             Operation = "admin.routes.list"
	OperationAdminRouteShow              Operation = "admin.route.show"
	OperationAdminRouteSuspend           Operation = "admin.route.suspend"
	OperationAdminRouteResume            Operation = "admin.route.resume"
	OperationAdminHostnamesList          Operation = "admin.hostnames.list"
	OperationAdminHostnameShow           Operation = "admin.hostname.show"
	OperationAdminHostnameRemove         Operation = "admin.hostname.remove"
	OperationAdminHostnameQuarantine     Operation = "admin.hostname.quarantine"
	OperationAdminCredentialsList        Operation = "admin.credentials.list"
	OperationAdminCredentialRevoke       Operation = "admin.credential.revoke"
	OperationAdminControlSessionsList    Operation = "admin.control_sessions.list"
	OperationAdminControlSessionRevoke   Operation = "admin.control_session.revoke"
	OperationAdminSwitchesList           Operation = "admin.switches.list"
	OperationAdminSwitchSet              Operation = "admin.switch.set"
)

// RequestResult classifies an API response by its final HTTP status.
type RequestResult string

const (
	RequestSuccess     RequestResult = "success"
	RequestClientError RequestResult = "client_error"
	RequestServerError RequestResult = "server_error"
)

// Observer receives one completed observation for every API request.
// Implementations must be safe for concurrent use.
type Observer interface {
	ObserveRequest(operation Operation, result RequestResult, duration time.Duration)
}

// ErrorReporter receives unexpected internal errors without request credentials or bodies.
// Implementations must be safe for concurrent use.
type ErrorReporter interface {
	ReportError(err error, requestID string, operation Operation)
}

// HandlerConfig configures production request observation and error reporting.
type HandlerConfig struct {
	Observer            Observer
	ErrorReporter       ErrorReporter
	RelayMap            []byte
	DNSReady            func() bool
	IngressAddresses    func() []string
	Readiness           func(context.Context) error
	SignedAuthorization bool
	Admin               AdminService
}

// AuthService implements authentication flows without exposing storage to HTTP.
type AuthService interface {
	Exchange(context.Context, credentials.LoginToken) (auth.IssuedControlSession, error)
	Refresh(context.Context, credentials.RefreshToken) (auth.IssuedControlSession, error)
	Authenticate(context.Context, credentials.AccessToken) (auth.Principal, error)
	Logout(context.Context, auth.Principal) error
}

type OIDCAuthService interface {
	ExchangeOIDC(context.Context, string) (auth.IssuedControlSession, error)
}

// RouteService implements hostnames and fenced route transitions.
type RouteService interface {
	AddHostname(context.Context, string, string, string, string) (routes.Hostname, error)
	CreateDomainVerification(context.Context, string, string, string) (routes.DomainVerification, error)
	GetDomainVerification(context.Context, string, string) (routes.DomainVerification, error)
	CompleteDomainVerification(context.Context, string, string) (routes.Hostname, error)
	ListHostnamesPage(context.Context, string, string) ([]routes.Hostname, string, error)
	RemoveHostname(context.Context, string, string) error
	Create(context.Context, string, string, string, credentials.RouteToken, []string) (routes.SessionSetup, error)
	CreateSession(context.Context, string, string, credentials.RouteToken, []string) (routes.SessionSetup, error)
	RegisterTransport(context.Context, string, uint64, credentials.SessionToken, string, string) error
	Ready(context.Context, string, uint64, credentials.SessionToken) error
	Heartbeat(context.Context, string, uint64, credentials.SessionToken) (time.Time, error)
	AuthorizeSession(context.Context, string, uint64, credentials.SessionToken) error
	List(context.Context, string) ([]routes.Route, error)
	Delete(context.Context, string, string) error
}

type SignedRouteService interface {
	CreateSigned(context.Context, string, string, credentials.RouteToken, routes.SignedRequest) (routes.SessionSetup, error)
	CreateSignedSession(context.Context, string, credentials.RouteToken, routes.SignedRequest) (routes.SessionSetup, error)
	HeartbeatSigned(context.Context, string, uint64, credentials.SessionToken, string, authorization.Digest) (time.Time, error)
	DeleteSigned(context.Context, string, credentials.RouteToken) error
}

// CertificateService implements durable certificate transitions without exposing storage to HTTP.
type CertificateService interface {
	Create(context.Context, string, uint64, string, []byte) (certificates.Issuance, error)
	Get(context.Context, string) (certificates.Issuance, error)
	ChallengeReady(context.Context, string) (certificates.Issuance, error)
	ChallengeRemoved(context.Context, string) (certificates.Issuance, error)
	Installed(context.Context, string, string, uint64) (certificates.Issuance, error)
}

type AdminService interface {
	Status(context.Context) (coreadmin.ServerStatus, error)
	ListRoutes(context.Context, string) ([]routes.Route, string, error)
	Route(context.Context, string) (routes.Route, error)
	SuspendRoute(context.Context, string, uint64, string, string, string) (routes.Route, error)
	ResumeRoute(context.Context, string, uint64, string, string) (routes.Route, error)
	ListHostnames(context.Context, string) ([]routes.Hostname, string, error)
	Hostname(context.Context, string) (routes.Hostname, error)
	RemoveHostname(context.Context, string, string, string) error
	QuarantineHostname(context.Context, string, string, string, string) error
	ListCredentials(context.Context, string) ([]coreadmin.Credential, string, error)
	RevokeCredential(context.Context, string, string, string) error
	ListControlSessions(context.Context, string) ([]coreadmin.ControlSession, string, error)
	RevokeControlSession(context.Context, string, string, string) error
	Switches(context.Context) ([]coreadmin.OperationalSwitch, error)
	SetSwitch(context.Context, coreadmin.SwitchName, bool, string, string) (coreadmin.OperationalSwitch, error)
	RequireEnabled(context.Context, coreadmin.SwitchName) error
}

type handler struct {
	capabilities        serverv1.Capabilities
	auth                AuthService
	routes              RouteService
	certificates        CertificateService
	observer            Observer
	errorReporter       ErrorReporter
	relayMap            []byte
	dnsReady            func() bool
	ingressAddresses    func() []string
	readiness           func(context.Context) error
	oidcLimit           *sourcelimiter.Limiter
	refreshLimit        *sourcelimiter.Limiter
	clientIPLimit       *sourcelimiter.Limiter
	signedAuthorization bool
	admin               AdminService
}

// NewHandler creates the server API handler without binding a listener.
func NewHandler(capabilities serverv1.Capabilities, auth AuthService) http.Handler {
	return NewHandlerWithRoutes(capabilities, auth, nil)
}

// NewHandlerWithRoutes enables hostname and route endpoints.
func NewHandlerWithRoutes(capabilities serverv1.Capabilities, auth AuthService, routeService RouteService) http.Handler {
	return NewHandlerWithServices(capabilities, auth, routeService, nil)
}

// NewHandlerWithServices enables hostname, route, and certificate endpoints.
func NewHandlerWithServices(
	capabilities serverv1.Capabilities,
	auth AuthService,
	routeService RouteService,
	certificateService CertificateService,
) http.Handler {
	return NewHandlerWithServicesAndConfig(capabilities, auth, routeService, certificateService, HandlerConfig{})
}

// NewHandlerWithServicesAndConfig enables all API services and production observability hooks.
func NewHandlerWithServicesAndConfig(
	capabilities serverv1.Capabilities,
	auth AuthService,
	routeService RouteService,
	certificateService CertificateService,
	config HandlerConfig,
) http.Handler {
	var oidcLimit *sourcelimiter.Limiter
	if _, ok := auth.(OIDCAuthService); ok {
		oidcLimit = newSourceLimiter(5, 20)
	}
	return &handler{
		capabilities:        capabilities,
		auth:                auth,
		routes:              routeService,
		certificates:        certificateService,
		observer:            config.Observer,
		errorReporter:       config.ErrorReporter,
		relayMap:            append([]byte(nil), config.RelayMap...),
		dnsReady:            config.DNSReady,
		ingressAddresses:    config.IngressAddresses,
		readiness:           config.Readiness,
		oidcLimit:           oidcLimit,
		refreshLimit:        newSourceLimiter(5, 20),
		clientIPLimit:       newSourceLimiter(1, 4),
		signedAuthorization: config.SignedAuthorization,
		admin:               config.Admin,
	}
}

func newSourceLimiter(requestsPerSecond float64, burst int) *sourcelimiter.Limiter {
	limiter, err := sourcelimiter.New(sourcelimiter.Config{Rate: requestsPerSecond, Burst: burst})
	if err != nil {
		panic("api: invalid source limiter configuration")
	}
	return limiter
}

func allowRequestSource(limiter *sourcelimiter.Limiter, request *http.Request) bool {
	remote, err := netip.ParseAddrPort(request.RemoteAddr)
	return err == nil && limiter.Allow(remote.Addr())
}

func (h *handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	started := time.Now()
	requestID := requestID(r)
	w.Header().Set(requestIDHeader, requestID)
	if h.observer == nil && h.errorReporter == nil {
		h.serveHTTP(w, r, requestID)
		return
	}

	wrapper := &observedResponseWriter{
		ResponseWriter: w,
		reporter:       h.errorReporter,
		requestID:      requestID,
		operation:      operationForRequest(r.Method, r.URL.Path),
	}
	if h.observer != nil {
		defer func() {
			h.observer.ObserveRequest(wrapper.operation, resultForStatus(wrapper.status), time.Since(started))
		}()
	}
	h.serveHTTP(wrapper, r, requestID)
}

func (h *handler) serveHTTP(w http.ResponseWriter, r *http.Request, requestID string) {
	switch r.URL.Path {
	case healthPath:
		h.serveHealth(w, r, requestID)
	case readinessPath:
		h.serveReadiness(w, r, requestID)
	case clientIPPath:
		h.serveClientIP(w, r, requestID)
	case capabilitiesPath:
		h.serveCapabilities(w, r, requestID)
	case relayMapPath:
		h.serveRelayMap(w, r, requestID)
	case tokenExchangePath:
		h.serveTokenExchange(w, r, requestID)
	case oidcExchangePath:
		h.serveOIDCExchange(w, r, requestID)
	case refreshPath:
		h.serveRefresh(w, r, requestID)
	case logoutPath:
		h.serveLogout(w, r, requestID)
	case hostnamesPath:
		h.serveHostnames(w, r, requestID)
	case domainVerificationsPath:
		h.serveDomainVerifications(w, r, requestID)
	case routesPath:
		h.serveRoutes(w, r, requestID)
	case certificateIssuancesPath:
		h.serveCertificateIssuances(w, r, requestID)
	default:
		if strings.HasPrefix(r.URL.Path, "/v1/admin/") {
			h.serveAdmin(w, r, requestID)
			return
		}
		if verificationID, operation, ok := domainVerificationPath(r.URL.Path); ok {
			h.serveDomainVerification(w, r, requestID, verificationID, operation)
			return
		}
		hostnameID, ok := strings.CutPrefix(r.URL.Path, hostnamePrefix)
		if ok && validHostnameID(hostnameID) {
			h.serveHostname(w, r, requestID, hostnameID)
			return
		}
		if routeID, operation, ok := routePath(r.URL.Path); ok {
			h.serveRoute(w, r, requestID, routeID, operation)
			return
		}
		if issuanceID, operation, ok := certificateIssuancePath(r.URL.Path); ok {
			h.serveCertificateIssuance(w, r, requestID, issuanceID, operation)
			return
		}
		writeNotFound(w, requestID)
	}
}

type observedResponseWriter struct {
	http.ResponseWriter
	reporter  ErrorReporter
	requestID string
	operation Operation
	status    int
	reported  bool
}

func (w *observedResponseWriter) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *observedResponseWriter) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func (w *observedResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *observedResponseWriter) report(err error) {
	if err == nil || w.reporter == nil || w.reported {
		return
	}
	w.reported = true
	w.reporter.ReportError(err, w.requestID, w.operation)
}

func operationForRequest(method, path string) Operation {
	if operation := adminOperationForRequest(method, path); operation != OperationUnknown {
		return operation
	}
	switch path {
	case healthPath:
		if method == http.MethodGet {
			return OperationHealthGet
		}
	case readinessPath:
		if method == http.MethodGet {
			return OperationReadinessGet
		}
	case clientIPPath:
		if method == http.MethodGet {
			return OperationClientIPGet
		}
	case capabilitiesPath:
		if method == http.MethodGet {
			return OperationCapabilitiesGet
		}
	case relayMapPath:
		if method == http.MethodGet {
			return OperationRelayMapGet
		}
	case tokenExchangePath:
		if method == http.MethodPost {
			return OperationTokenExchange
		}
	case oidcExchangePath:
		if method == http.MethodPost {
			return OperationOIDCTokenExchange
		}
	case refreshPath:
		if method == http.MethodPost {
			return OperationControlSessionRefresh
		}
	case logoutPath:
		if method == http.MethodPost {
			return OperationControlSessionLogout
		}
	case hostnamesPath:
		switch method {
		case http.MethodGet:
			return OperationHostnamesList
		case http.MethodPost:
			return OperationHostnameAdd
		}
	case domainVerificationsPath:
		if method == http.MethodPost {
			return OperationDomainVerificationCreate
		}
	case routesPath:
		switch method {
		case http.MethodGet:
			return OperationRoutesList
		case http.MethodPost:
			return OperationRouteCreate
		}
	case certificateIssuancesPath:
		if method == http.MethodPost {
			return OperationCertificateIssuanceCreate
		}
	}

	if hostnameID, ok := strings.CutPrefix(path, hostnamePrefix); ok &&
		validHostnameID(hostnameID) && method == http.MethodDelete {
		return OperationHostnameRemove
	}
	if _, domainOperation, ok := domainVerificationPath(path); ok {
		if domainOperation == "" {
			if method == http.MethodGet {
				return OperationDomainVerificationGet
			}
		}
		if domainOperation == "complete" && method == http.MethodPost {
			return OperationDomainVerificationComplete
		}
	}
	if _, routeOperation, ok := routePath(path); ok {
		switch {
		case routeOperation == "" && method == http.MethodDelete:
			return OperationRouteDelete
		case routeOperation == "sessions" && method == http.MethodPost:
			return OperationRouteSessionCreate
		case routeOperation == "transport" && method == http.MethodPost:
			return OperationRouteTransportRegister
		case routeOperation == "heartbeat" && method == http.MethodPost:
			return OperationRouteHeartbeat
		case routeOperation == "ready" && method == http.MethodPost:
			return OperationRouteReady
		case routeOperation == "certificate-installed" && method == http.MethodPost:
			return OperationCertificateInstalled
		}
	}
	if _, certificateOperation, ok := certificateIssuancePath(path); ok {
		switch {
		case certificateOperation == "" && method == http.MethodGet:
			return OperationCertificateIssuanceGet
		case certificateOperation == "challenge-ready" && method == http.MethodPost:
			return OperationCertificateChallengeReady
		case certificateOperation == "challenge-removed" && method == http.MethodPost:
			return OperationCertificateChallengeRemoved
		}
	}
	return OperationUnknown
}

func resultForStatus(status int) RequestResult {
	switch {
	case status >= http.StatusInternalServerError:
		return RequestServerError
	case status >= http.StatusBadRequest:
		return RequestClientError
	default:
		return RequestSuccess
	}
}

func (h *handler) serveHealth(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, requestID, http.MethodGet)
		return
	}
	body, err := marshalJSON(serverv1.HealthResponse{Status: serverv1.HealthResponseStatusOk})
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func (h *handler) serveReadiness(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, requestID, http.MethodGet)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()
	status := http.StatusOK
	response := serverv1.ReadinessResponse{
		Status: serverv1.ReadinessResponseStatusReady,
		Checks: serverv1.ReadinessChecks{Status: serverv1.ReadinessChecksStatusOk},
	}
	if h.readiness == nil || h.readiness(ctx) != nil {
		status = http.StatusServiceUnavailable
		response.Status = serverv1.ReadinessResponseStatusNotReady
		response.Checks.Status = serverv1.ReadinessChecksStatusFailed
	}
	body, err := marshalJSON(response)
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeJSON(w, status, "application/json", body)
}

func (h *handler) serveClientIP(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, requestID, http.MethodGet)
		return
	}
	remote, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		writeProblem(
			w, requestID, http.StatusServiceUnavailable, serverv1.TemporarilyUnavailable,
			"Temporarily unavailable", "client-ip-unavailable",
		)
		return
	}
	if !h.clientIPLimit.Allow(remote.Addr()) {
		w.Header().Set("Retry-After", "1")
		writeProblem(w, requestID, http.StatusTooManyRequests, serverv1.RateLimited, "Rate limited", "rate-limited")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeModel(w, requestID, http.StatusOK, serverv1.ClientIPResponse{Ip: remote.Addr().Unmap().String()})
}

func (h *handler) serveHostnames(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodGet+", "+http.MethodPost)
		return
	}
	identity, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if r.Method == http.MethodGet {
		query := r.URL.Query()
		cursor := ""
		if len(query) != 0 {
			values, ok := query["cursor"]
			if !ok || len(query) != 1 || len(values) != 1 || !validHostnameID(values[0]) {
				writeInvalidRequest(w, requestID)
				return
			}
			cursor = values[0]
		}
		hostnames, next, err := h.routes.ListHostnamesPage(r.Context(), identity.ID, cursor)
		if err != nil {
			writeRouteError(w, requestID, err)
			return
		}
		response := serverv1.HostnamePage{Hostnames: make([]serverv1.Hostname, 0, len(hostnames))}
		for _, hostname := range hostnames {
			response.Hostnames = append(response.Hostnames, hostnameResponse(hostname))
		}
		if next != "" {
			response.NextCursor = &next
		}
		writeModel(w, requestID, http.StatusOK, response)
		return
	}
	requestKey := r.Header.Get(idempotencyKeyHeader)
	if requestKey == "" || strings.TrimSpace(requestKey) != requestKey || len(requestKey) > 128 {
		writeInvalidRequest(w, requestID)
		return
	}
	var request serverv1.AddHostnameRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	name := ""
	if request.Name != nil {
		name = *request.Name
	}
	hostname, err := h.routes.AddHostname(r.Context(), identity.ID, string(request.Kind), name, requestKey)
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, hostnameResponse(hostname))
}

func (h *handler) serveHostname(w http.ResponseWriter, r *http.Request, requestID, hostnameID string) {
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, requestID, http.MethodDelete)
		return
	}
	identity, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if err := h.routes.RemoveHostname(r.Context(), identity.ID, hostnameID); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveDomainVerifications(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	identity, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	requestKey := r.Header.Get(idempotencyKeyHeader)
	if requestKey == "" || strings.TrimSpace(requestKey) != requestKey || len(requestKey) > 128 {
		writeInvalidRequest(w, requestID)
		return
	}
	var request serverv1.CreateDomainVerificationRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	challenge, err := h.routes.CreateDomainVerification(r.Context(), identity.ID, request.Domain, requestKey)
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, domainVerificationResponse(challenge))
}

func (h *handler) serveDomainVerification(
	w http.ResponseWriter,
	r *http.Request,
	requestID, id, operation string,
) {
	wantMethod := r.Method
	switch operation {
	case "":
		if r.Method != http.MethodGet {
			writeMethodNotAllowed(w, requestID, http.MethodGet)
			return
		}
	case "complete":
		wantMethod = http.MethodPost
	default:
		writeNotFound(w, requestID)
		return
	}
	if r.Method != wantMethod {
		writeMethodNotAllowed(w, requestID, wantMethod)
		return
	}
	if !validDomainVerificationID(id) {
		writeNotFound(w, requestID)
		return
	}
	identity, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if operation == "" {
		challenge, err := h.routes.GetDomainVerification(r.Context(), identity.ID, id)
		if err != nil {
			writeRouteError(w, requestID, err)
			return
		}
		writeModel(w, requestID, http.StatusOK, domainVerificationResponse(challenge))
		return
	}
	hostname, err := h.routes.CompleteDomainVerification(r.Context(), identity.ID, id)
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, hostnameResponse(hostname))
}

func (h *handler) serveCapabilities(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, requestID, http.MethodGet)
		return
	}

	capabilities := h.capabilities
	if h.dnsReady != nil {
		capabilities.DnsReady = h.dnsReady()
	}
	if h.ingressAddresses != nil {
		capabilities.IngressIpv4 = []string{}
		capabilities.IngressIpv6 = []string{}
		for _, value := range h.ingressAddresses() {
			address := net.ParseIP(value)
			if address == nil {
				continue
			}
			if address.To4() != nil {
				capabilities.IngressIpv4 = append(capabilities.IngressIpv4, address.String())
			} else {
				capabilities.IngressIpv6 = append(capabilities.IngressIpv6, address.String())
			}
		}
	}
	body, err := marshalJSON(capabilities)
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func (h *handler) serveRelayMap(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, requestID, http.MethodGet)
		return
	}
	if len(h.relayMap) == 0 {
		writeInternalError(w, requestID, errors.New("api: relay map is not configured"))
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, "application/json", h.relayMap)
}

func (h *handler) serveTokenExchange(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	var request serverv1.TokenExchangeRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.LoginToken == "" || len(request.LoginToken) > maxCredentialBytes {
		writeProblem(
			w, requestID, http.StatusBadRequest, serverv1.InvalidArgument,
			"Invalid request", "invalid-request",
		)
		return
	}
	if h.auth == nil {
		writeInternalError(w, requestID, errAuthServiceMissing)
		return
	}
	issued, err := h.auth.Exchange(r.Context(), credentials.LoginToken(request.LoginToken))
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeProblem(
			w, requestID, http.StatusUnauthorized, serverv1.Unauthenticated,
			"Unauthenticated", "unauthenticated",
		)
		return
	}
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	h.writeControlSession(w, requestID, issued)
}

func (h *handler) serveOIDCExchange(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if h.oidcLimit != nil && !allowRequestSource(h.oidcLimit, r) {
		writeProblem(
			w, requestID, http.StatusTooManyRequests, serverv1.RateLimited,
			"Rate limited", "rate-limited",
		)
		return
	}
	var request serverv1.OIDCTokenExchangeRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.IdToken == "" || len(request.IdToken) > 16384 {
		writeProblem(
			w, requestID, http.StatusBadRequest, serverv1.InvalidArgument,
			"Invalid request", "invalid-request",
		)
		return
	}
	oidcService, ok := h.auth.(OIDCAuthService)
	if !ok {
		writeInternalError(w, requestID, errAuthServiceMissing)
		return
	}
	issued, err := oidcService.ExchangeOIDC(r.Context(), request.IdToken)
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeProblem(
			w, requestID, http.StatusUnauthorized, serverv1.Unauthenticated,
			"Unauthenticated", "unauthenticated",
		)
		return
	}
	if errors.Is(err, auth.ErrOIDCUnavailable) {
		writeProblem(
			w, requestID, http.StatusServiceUnavailable, serverv1.TemporarilyUnavailable,
			"Temporarily unavailable", "oidc-unavailable",
		)
		return
	}
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	h.writeControlSession(w, requestID, issued)
}

func (h *handler) serveRefresh(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if !allowRequestSource(h.refreshLimit, r) {
		writeProblem(
			w, requestID, http.StatusTooManyRequests, serverv1.RateLimited,
			"Rate limited", "rate-limited",
		)
		return
	}
	var request serverv1.RefreshControlSessionRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.RefreshToken == "" || len(request.RefreshToken) > maxCredentialBytes {
		writeInvalidRequest(w, requestID)
		return
	}
	if h.auth == nil {
		writeInternalError(w, requestID, errAuthServiceMissing)
		return
	}
	issued, err := h.auth.Refresh(r.Context(), credentials.RefreshToken(request.RefreshToken))
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeUnauthenticated(w, requestID)
		return
	}
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	h.writeControlSession(w, requestID, issued)
}

func (h *handler) serveLogout(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	principal, ok := h.authenticatePrincipal(w, r, requestID)
	if !ok {
		return
	}
	if err := h.auth.Logout(r.Context(), principal); errors.Is(err, auth.ErrUnauthenticated) {
		writeUnauthenticated(w, requestID)
		return
	} else if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) writeControlSession(
	w http.ResponseWriter,
	requestID string,
	issued auth.IssuedControlSession,
) {
	grants := make([]serverv1.Grant, len(issued.Grants))
	for index, grant := range issued.Grants {
		grants[index] = serverv1.Grant(grant)
	}
	body, err := marshalJSON(serverv1.ControlSessionResponse{
		SessionId: issued.SessionID, AccessToken: issued.AccessToken.String(), AccessExpiresAt: issued.AccessExpiresAt,
		RefreshToken: issued.RefreshToken.String(), RefreshExpiresAt: issued.RefreshExpiresAt, Grants: grants,
	})
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func (h *handler) serveRoutes(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodGet+", "+http.MethodPost)
		return
	}
	var identity state.Identity
	if r.Method == http.MethodGet || !h.signedAuthorization {
		var ok bool
		identity, ok = h.authenticate(w, r, requestID)
		if !ok {
			return
		}
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if r.Method == http.MethodGet {
		stored, err := h.routes.List(r.Context(), identity.ID)
		if err != nil {
			writeRouteError(w, requestID, err)
			return
		}
		response := make([]serverv1.Route, 0, len(stored))
		for _, route := range stored {
			response = append(response, routeResponse(route))
		}
		writeModel(w, requestID, http.StatusOK, response)
		return
	}
	if !h.requireOperationalSwitch(w, r, requestID, coreadmin.SwitchNewRoutes) {
		return
	}
	var request serverv1.CreateRouteRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	routeToken := credentials.RouteToken(request.RouteToken)
	if strings.TrimSpace(request.LocalTarget) == "" || len(request.LocalTarget) > 256 ||
		len(request.RouteToken) > maxCredentialBytes {
		writeInvalidRequest(w, requestID)
		return
	}
	if _, _, err := credentials.ParseRouteToken(routeToken); err != nil {
		writeInvalidRequest(w, requestID)
		return
	}
	allowedIPPrefixes, requestErr := routeAllowedIPPrefixes(request.AllowedIpPrefixes)
	if requestErr != nil {
		writeInvalidRequest(w, requestID)
		return
	}
	var setup routes.SessionSetup
	var err error
	if h.signedAuthorization {
		signedService, ok := h.routes.(SignedRouteService)
		if !ok {
			writeInternalError(w, requestID, errRouteServiceMissing)
			return
		}
		signedRequest, requestErr := signedRouteRequest(
			authorization.OperationRouteCreate, request.Hostname, request.LocalTarget,
			routeToken, 0, request.AllowedIpPrefixes, request.SignedAuthorization,
		)
		if requestErr != nil {
			writeInvalidRequest(w, requestID)
			return
		}
		setup, err = signedService.CreateSigned(r.Context(), request.Hostname, request.LocalTarget, routeToken, signedRequest)
	} else {
		setup, err = h.routes.Create(
			r.Context(), identity.ID, request.Hostname, request.LocalTarget, routeToken, allowedIPPrefixes,
		)
	}
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, sessionSetupResponse(setup))
}

func (h *handler) serveRoute(
	w http.ResponseWriter,
	r *http.Request,
	requestID, routeID, operation string,
) {
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	switch operation {
	case "":
		if r.Method != http.MethodDelete {
			writeMethodNotAllowed(w, requestID, http.MethodDelete)
			return
		}
		var err error
		if h.signedAuthorization {
			signedService, ok := h.routes.(SignedRouteService)
			if !ok {
				writeInternalError(w, requestID, errRouteServiceMissing)
				return
			}
			token, ok := routeBearer(r.Header)
			if !ok {
				writeUnauthenticated(w, requestID)
				return
			}
			err = signedService.DeleteSigned(r.Context(), routeID, token)
		} else {
			identity, ok := h.authenticate(w, r, requestID)
			if !ok {
				return
			}
			err = h.routes.Delete(r.Context(), identity.ID, routeID)
		}
		if err != nil {
			writeRouteError(w, requestID, err)
			return
		}
		writeNoContent(w)
	case "sessions":
		h.serveSessionAcquisition(w, r, requestID, routeID)
	case "transport":
		h.serveTransport(w, r, requestID, routeID)
	case "heartbeat":
		h.serveHeartbeat(w, r, requestID, routeID)
	case "ready":
		h.serveReady(w, r, requestID, routeID)
	case "certificate-installed":
		h.serveCertificateInstalled(w, r, requestID, routeID)
	default:
		writeNotFound(w, requestID)
	}
}

func (h *handler) serveCertificateIssuances(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if h.certificates == nil {
		writeInternalError(w, requestID, errCertServiceMissing)
		return
	}
	if !h.requireOperationalSwitch(w, r, requestID, coreadmin.SwitchCertificateIssuance) {
		return
	}
	token, ok := sessionBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request serverv1.CreateCertificateIssuanceRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(request.Csr)
	if request.RouteId == "" || request.Version <= 0 || request.AcmeProfile == "" || err != nil ||
		base64.RawURLEncoding.EncodeToString(csrDER) != request.Csr {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.routes.AuthorizeSession(
		r.Context(), request.RouteId, uint64(request.Version), token,
	); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	issuance, err := h.certificates.Create(
		r.Context(), request.RouteId, uint64(request.Version), request.AcmeProfile, csrDER,
	)
	if err != nil {
		writeCertificateError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, certificateIssuanceResponse(issuance))
}

func (h *handler) serveCertificateIssuance(
	w http.ResponseWriter,
	r *http.Request,
	requestID, issuanceID, operation string,
) {
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if h.certificates == nil {
		writeInternalError(w, requestID, errCertServiceMissing)
		return
	}
	wantMethod := http.MethodPost
	if operation == "" {
		wantMethod = http.MethodGet
	} else if operation != "challenge-ready" && operation != "challenge-removed" {
		writeNotFound(w, requestID)
		return
	}
	if r.Method != wantMethod {
		writeMethodNotAllowed(w, requestID, wantMethod)
		return
	}
	token, ok := sessionBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	issuance, err := h.certificates.Get(r.Context(), issuanceID)
	if err != nil {
		writeCertificateError(w, requestID, err)
		return
	}
	if err := h.routes.AuthorizeSession(r.Context(), issuance.RouteID, issuance.Version, token); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	switch operation {
	case "":
		writeModel(w, requestID, http.StatusOK, certificateIssuanceResponse(issuance))
	case "challenge-ready":
		issuance, err = h.certificates.ChallengeReady(r.Context(), issuanceID)
		if err != nil {
			writeCertificateError(w, requestID, err)
			return
		}
		writeModel(w, requestID, http.StatusOK, certificateIssuanceResponse(issuance))
	case "challenge-removed":
		if _, err := h.certificates.ChallengeRemoved(r.Context(), issuanceID); err != nil {
			writeCertificateError(w, requestID, err)
			return
		}
		writeNoContent(w)
	}
}

func (h *handler) serveCertificateInstalled(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if h.certificates == nil {
		writeInternalError(w, requestID, errCertServiceMissing)
		return
	}
	token, ok := sessionBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request serverv1.CertificateInstalledRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Version <= 0 || !validCertificateIssuanceID(request.IssuanceId) {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.routes.AuthorizeSession(r.Context(), routeID, uint64(request.Version), token); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	if _, err := h.certificates.Installed(
		r.Context(), request.IssuanceId, routeID, uint64(request.Version),
	); err != nil {
		writeCertificateError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveSessionAcquisition(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	if !h.requireOperationalSwitch(w, r, requestID, coreadmin.SwitchNewSessions) {
		return
	}
	var request serverv1.CreateRouteSessionRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.RouteToken == "" || len(request.RouteToken) > maxCredentialBytes {
		writeInvalidRequest(w, requestID)
		return
	}
	routeToken := credentials.RouteToken(request.RouteToken)
	allowedIPPrefixes, requestErr := routeAllowedIPPrefixes(request.AllowedIpPrefixes)
	if requestErr != nil {
		writeInvalidRequest(w, requestID)
		return
	}
	var setup routes.SessionSetup
	var err error
	if h.signedAuthorization {
		signedService, ok := h.routes.(SignedRouteService)
		if !ok {
			writeInternalError(w, requestID, errRouteServiceMissing)
			return
		}
		signedRequest, requestErr := signedRouteRequest(
			authorization.OperationRouteSessionCreate, "", "", routeToken, 0,
			request.AllowedIpPrefixes, request.SignedAuthorization,
		)
		if requestErr != nil {
			writeInvalidRequest(w, requestID)
			return
		}
		setup, err = signedService.CreateSignedSession(r.Context(), routeID, routeToken, signedRequest)
	} else {
		identity, ok := h.authenticate(w, r, requestID)
		if !ok {
			return
		}
		setup, err = h.routes.CreateSession(r.Context(), identity.ID, routeID, routeToken, allowedIPPrefixes)
	}
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, sessionSetupResponse(setup))
}

func (h *handler) serveTransport(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	token, ok := sessionBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request serverv1.RegisterTransportRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	var serverKey key.NodePublic
	if request.Version <= 0 || request.Endpoint.Version != serverv1.TailcatDescriptorVersionN1 ||
		serverKey.UnmarshalText([]byte(request.Endpoint.PublisherPublicKey)) != nil || serverKey.IsZero() ||
		request.Endpoint.RelayRegion != h.capabilities.Transport.RelayRegion {
		writeInvalidRequest(w, requestID)
		return
	}
	err := h.routes.RegisterTransport(
		r.Context(), routeID, uint64(request.Version), token,
		request.Endpoint.PublisherPublicKey, request.Endpoint.RelayRegion,
	)
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveHeartbeat(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	token, ok := sessionBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request serverv1.HeartbeatRouteSessionRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Version <= 0 {
		writeInvalidRequest(w, requestID)
		return
	}
	var expiresAt time.Time
	var err error
	if h.signedAuthorization {
		signedService, ok := h.routes.(SignedRouteService)
		if !ok {
			writeInternalError(w, requestID, errRouteServiceMissing)
			return
		}
		signedAuthorization := ""
		if request.SignedAuthorization != nil {
			signedAuthorization = *request.SignedAuthorization
			if signedAuthorization == "" || len(signedAuthorization) > authorization.MaxTokenBytes ||
				strings.TrimSpace(signedAuthorization) != signedAuthorization {
				writeInvalidRequest(w, requestID)
				return
			}
		}
		requestHash, hashErr := authorization.CanonicalRequestHash(authorization.CoreRequest{
			Operation: authorization.OperationRenew, Version: uint64(request.Version),
		})
		if hashErr != nil {
			writeInvalidRequest(w, requestID)
			return
		}
		expiresAt, err = signedService.HeartbeatSigned(
			r.Context(), routeID, uint64(request.Version), token, signedAuthorization, requestHash,
		)
	} else {
		expiresAt, err = h.routes.Heartbeat(r.Context(), routeID, uint64(request.Version), token)
	}
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, serverv1.HeartbeatResponse{ExpiresAt: expiresAt})
}

func (h *handler) serveReady(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	token, ok := sessionBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request serverv1.RouteVersionRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Version <= 0 {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.routes.Ready(r.Context(), routeID, uint64(request.Version), token); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func bearerToken(header http.Header) (credentials.AccessToken, bool) {
	token, err := credentials.Bearer(header)
	if err != nil || len(token) > maxCredentialBytes {
		return "", false
	}
	return credentials.AccessToken(token), true
}

func sessionBearer(header http.Header) (credentials.SessionToken, bool) {
	token, err := credentials.Bearer(header)
	return credentials.SessionToken(token), err == nil && len(token) <= maxCredentialBytes
}

func routeBearer(header http.Header) (credentials.RouteToken, bool) {
	token, err := credentials.Bearer(header)
	if err != nil || len(token) > maxCredentialBytes {
		return "", false
	}
	routeToken := credentials.RouteToken(token)
	if _, _, err := credentials.ParseRouteToken(routeToken); err != nil {
		return "", false
	}
	return routeToken, true
}

func signedRouteRequest(
	operation authorization.Operation,
	hostname, localTarget string,
	routeToken credentials.RouteToken,
	version uint64,
	prefixValues *serverv1.AllowedIPPrefixes,
	token *serverv1.SignedAuthorizationToken,
) (routes.SignedRequest, error) {
	if token == nil || *token == "" || len(*token) > authorization.MaxTokenBytes || strings.TrimSpace(*token) != *token {
		return routes.SignedRequest{}, authorization.ErrInvalid
	}
	var prefixes []string
	if prefixValues != nil {
		prefixes = slices.Clone(*prefixValues)
		canonical, err := authorization.CanonicalizeIPPrefixes(prefixes)
		if err != nil || !slices.Equal(canonical, prefixes) {
			return routes.SignedRequest{}, authorization.ErrInvalid
		}
	}
	requestHash, err := authorization.CanonicalRequestHash(authorization.CoreRequest{
		Operation: operation, Hostname: hostname, LocalTarget: localTarget,
		RouteToken: routeToken.String(), AllowedIPPrefixes: prefixes, Version: version,
	})
	if err != nil {
		return routes.SignedRequest{}, err
	}
	ipPolicyHash, err := authorization.IPPolicyHash(prefixes)
	if err != nil {
		return routes.SignedRequest{}, err
	}
	return routes.SignedRequest{
		Token: *token, RequestHash: requestHash, IPPolicyHash: ipPolicyHash, AllowedIPPrefixes: prefixes,
	}, nil
}

func routeAllowedIPPrefixes(values *serverv1.AllowedIPPrefixes) ([]string, error) {
	if values == nil {
		return nil, nil
	}
	prefixes := slices.Clone(*values)
	canonical, err := authorization.CanonicalizeIPPrefixes(prefixes)
	if err != nil || !slices.Equal(canonical, prefixes) {
		return nil, authorization.ErrInvalid
	}
	return prefixes, nil
}

func (h *handler) authenticate(w http.ResponseWriter, r *http.Request, requestID string) (state.Identity, bool) {
	principal, ok := h.authenticatePrincipal(w, r, requestID)
	if !ok {
		return state.Identity{}, false
	}
	if !principal.HasGrant(auth.GrantPublish) {
		writeProblem(w, requestID, http.StatusForbidden, serverv1.PermissionDenied, "Permission denied", "permission-denied")
		return state.Identity{}, false
	}
	return principal.Identity, true
}

func (h *handler) authenticatePrincipal(w http.ResponseWriter, r *http.Request, requestID string) (auth.Principal, bool) {
	if h.auth == nil {
		writeInternalError(w, requestID, errAuthServiceMissing)
		return auth.Principal{}, false
	}
	token, ok := bearerToken(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return auth.Principal{}, false
	}
	principal, err := h.auth.Authenticate(r.Context(), token)
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeUnauthenticated(w, requestID)
		return auth.Principal{}, false
	}
	if err != nil {
		writeInternalError(w, requestID, err)
		return auth.Principal{}, false
	}
	return principal, true
}

func routePath(path string) (routeID, operation string, ok bool) {
	remainder, ok := strings.CutPrefix(path, routePathPrefix)
	if !ok || remainder == "" {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) > 2 || parts[0] == "" || len(parts) == 2 && parts[1] == "" {
		return "", "", false
	}
	if len(parts) == 2 {
		operation = parts[1]
	}
	return parts[0], operation, true
}

func certificateIssuancePath(path string) (issuanceID, operation string, ok bool) {
	remainder, ok := strings.CutPrefix(path, certificateIssuancePrefix)
	if !ok || remainder == "" {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) > 2 || !validCertificateIssuanceID(parts[0]) || len(parts) == 2 && parts[1] == "" {
		return "", "", false
	}
	if len(parts) == 2 {
		operation = parts[1]
	}
	return parts[0], operation, true
}

func domainVerificationPath(path string) (id, operation string, ok bool) {
	remainder, ok := strings.CutPrefix(path, domainVerificationPrefix)
	if !ok || remainder == "" {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) > 2 || parts[0] == "" || len(parts) == 2 && parts[1] == "" {
		return "", "", false
	}
	if len(parts) == 2 {
		operation = parts[1]
	}
	return parts[0], operation, true
}

func validDomainVerificationID(value string) bool {
	const prefix = "verification_"
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func validCertificateIssuanceID(value string) bool {
	const prefix = "issuance_"
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func validHostnameID(value string) bool {
	const prefix = "hostname_"
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func decodeRequest(w http.ResponseWriter, r *http.Request, requestID string, value any) bool {
	if err := decodeJSON(w, r, value); err != nil {
		status, title, problemType := http.StatusBadRequest, "Invalid request", "invalid-request"
		var maxBytesError *http.MaxBytesError
		switch {
		case errors.As(err, &maxBytesError):
			status, title, problemType = http.StatusRequestEntityTooLarge, "Request body too large", "request-too-large"
		case errors.Is(err, errUnsupportedMediaType):
			status, title, problemType = http.StatusUnsupportedMediaType, "Unsupported media type", "unsupported-media-type"
		}
		writeProblem(w, requestID, status, serverv1.InvalidArgument, title, problemType)
		return false
	}
	return true
}

func routeResponse(route routes.Route) serverv1.Route {
	return serverv1.Route{
		Id: route.ID, Hostname: route.Hostname, LocalTarget: route.LocalTarget,
		Status: serverv1.RouteStatus(route.Status), Version: int(route.Version), CreatedAt: route.CreatedAt,
	}
}

func hostnameResponse(hostname routes.Hostname) serverv1.Hostname {
	result := serverv1.Hostname{
		Id: hostname.ID, Hostname: hostname.Hostname, Kind: serverv1.HostnameKind(hostname.Kind),
		Status: serverv1.HostnameStatus(hostname.Status), Source: serverv1.HostnameSource(hostname.Source),
		CreatedAt: hostname.CreatedAt,
	}
	if !hostname.ActivatedAt.IsZero() {
		result.ActivatedAt = &hostname.ActivatedAt
	}
	if !hostname.DeactivatedAt.IsZero() {
		result.DeactivatedAt = &hostname.DeactivatedAt
	}
	return result
}

func domainVerificationResponse(verification routes.DomainVerification) serverv1.DomainVerification {
	result := serverv1.DomainVerification{
		Id: verification.ID, Domain: verification.Domain, VerificationTarget: verification.VerificationTarget,
		Apex: verification.Apex, Status: serverv1.DomainVerificationStatus(verification.Status),
		Records: make([]serverv1.DNSRecord, 0, len(verification.Records)), CreatedAt: verification.CreatedAt,
	}
	for _, record := range verification.Records {
		result.Records = append(result.Records, serverv1.DNSRecord{
			Name: record.Name, Type: serverv1.DNSRecordType(record.Type), Value: record.Value,
		})
	}
	if verification.HostnameID != "" {
		result.HostnameId = &verification.HostnameID
	}
	if !verification.VerifiedAt.IsZero() {
		result.VerifiedAt = &verification.VerifiedAt
	}
	if !verification.InvalidatedAt.IsZero() {
		result.InvalidatedAt = &verification.InvalidatedAt
	}
	return result
}

func sessionSetupResponse(setup routes.SessionSetup) serverv1.SessionSetup {
	return serverv1.SessionSetup{
		Route: routeResponse(setup.Route),
		Session: serverv1.RouteSession{
			Id: setup.Session.ID, RouteId: setup.Session.RouteID, Version: int(setup.Session.Version),
			Status: serverv1.RouteSessionStatus(setup.Session.Status), CreatedAt: setup.Session.CreatedAt, ExpiresAt: setup.Session.ExpiresAt,
		},
		SessionToken: setup.SessionToken.String(), WorkerPublicKey: setup.WorkerPublicKey,
	}
}

func certificateIssuanceResponse(issuance certificates.Issuance) serverv1.CertificateIssuance {
	response := serverv1.CertificateIssuance{
		Id: issuance.ID, RouteId: issuance.RouteID, Version: int(issuance.Version), Hostname: issuance.Hostname,
		AcmeProfile: issuance.ACMEProfile, Status: serverv1.CertificateIssuanceStatus(issuance.Status), CreatedAt: issuance.CreatedAt, UpdatedAt: issuance.UpdatedAt,
	}
	if challenge := issuance.Challenge(); challenge != nil {
		response.Challenge = &serverv1.CertificateChallenge{
			Id: challenge.ID, Hostname: challenge.Hostname,
			Digest: base64.RawURLEncoding.EncodeToString(challenge.Digest[:]), ExpiresAt: challenge.ExpiresAt,
		}
	}
	if len(issuance.CertificatePEM) != 0 {
		value := string(issuance.CertificatePEM)
		response.CertificatePem = &value
	}
	if !issuance.NotBefore.IsZero() {
		response.NotBefore = &issuance.NotBefore
	}
	if !issuance.NotAfter.IsZero() {
		response.NotAfter = &issuance.NotAfter
	}
	if !issuance.RenewAt.IsZero() {
		response.RenewAt = &issuance.RenewAt
	}
	if !issuance.RetryAt.IsZero() {
		response.RetryAt = &issuance.RetryAt
	}
	if issuance.LastError != "" {
		response.Error = &issuance.LastError
	}
	return response
}

func writeModel(w http.ResponseWriter, requestID string, status int, value any) {
	body, err := marshalJSON(value)
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeJSON(w, status, "application/json", body)
}

func writeRouteError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, routes.ErrUnauthenticated):
		writeUnauthenticated(w, requestID)
	case errors.Is(err, routes.ErrNotFound):
		writeNotFound(w, requestID)
	case errors.Is(err, routes.ErrNameUnavailable):
		writeProblem(w, requestID, http.StatusConflict, serverv1.NameUnavailable, "Name unavailable", "name-unavailable")
	case errors.Is(err, routes.ErrRouteExists), errors.Is(err, routes.ErrStaleSession),
		errors.Is(err, routes.ErrInvalidStatus), errors.Is(err, routes.ErrAuthorizationReplayed):
		writeProblem(w, requestID, http.StatusConflict, serverv1.StatusConflict, "Status conflict", "status-conflict")
	case errors.Is(err, routes.ErrNoWorkerCapacity), errors.Is(err, routes.ErrUnavailable):
		writeProblem(w, requestID, http.StatusServiceUnavailable, serverv1.TemporarilyUnavailable, "Temporarily unavailable", "temporarily-unavailable")
	case errors.Is(err, routes.ErrDNSProofPending):
		writeProblem(w, requestID, http.StatusPreconditionFailed, serverv1.PreconditionFailed, "DNS proof pending", "dns-proof-pending")
	default:
		if errors.Is(err, routes.ErrInvalidArgument) {
			writeInvalidRequest(w, requestID)
			return
		}
		if _, ok := naming.ErrorCodeOf(err); ok {
			writeProblem(w, requestID, http.StatusBadRequest, serverv1.InvalidArgument, "Invalid request", "invalid-request")
			return
		}
		writeInternalError(w, requestID, err)
	}
}

func writeCertificateError(w http.ResponseWriter, requestID string, err error) {
	switch {
	case errors.Is(err, certificates.ErrInvalidArgument):
		writeInvalidRequest(w, requestID)
	case errors.Is(err, certificates.ErrNotFound):
		writeNotFound(w, requestID)
	case errors.Is(err, certificates.ErrInvalidStatus):
		writeProblem(w, requestID, http.StatusPreconditionFailed, serverv1.PreconditionFailed, "Precondition failed", "precondition-failed")
	case errors.Is(err, certificates.ErrRateLimited):
		var limit *certificates.RateLimitError
		if errors.As(err, &limit) {
			// Round up so clients never retry before the stored deadline.
			seconds := max(1, int((time.Until(limit.RetryAt)+time.Second-1)/time.Second))
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
		}
		writeProblem(w, requestID, http.StatusTooManyRequests, serverv1.RateLimited, "Rate limited", "rate-limited")
	case errors.Is(err, certificates.ErrUnavailable):
		writeProblem(w, requestID, http.StatusServiceUnavailable, serverv1.TemporarilyUnavailable, "Temporarily unavailable", "temporarily-unavailable")
	default:
		writeInternalError(w, requestID, err)
	}
}

func writeInvalidRequest(w http.ResponseWriter, requestID string) {
	writeProblem(w, requestID, http.StatusBadRequest, serverv1.InvalidArgument, "Invalid request", "invalid-request")
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) error {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return errUnsupportedMediaType
	}
	responseController := http.NewResponseController(w)
	if err := responseController.SetReadDeadline(time.Now().Add(jsonReadTimeout)); err == nil {
		defer responseController.SetReadDeadline(time.Time{})
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxJSONRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errInvalidJSON
	}
	return nil
}

func requestID(r *http.Request) string {
	values := r.Header.Values(requestIDHeader)
	if len(values) == 1 && validRequestID(values[0]) {
		return values[0]
	}

	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "req_internal"
	}
	return "req_" + hex.EncodeToString(random[:])
}

func validRequestID(value string) bool {
	const prefix = "req_"
	if !strings.HasPrefix(value, prefix) || len(value) == len(prefix) || len(value) > len(prefix)+64 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if (char < 'a' || char > 'z') &&
			(char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func marshalJSON(value any) ([]byte, error) {
	body, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	if len(body) > maxJSONResponseBytes {
		return nil, errResponseTooLarge
	}
	return body, nil
}

func writeProblem(
	w http.ResponseWriter,
	requestID string,
	status int,
	code serverv1.ProblemCode,
	title string,
	problemType string,
) {
	body, err := marshalJSON(serverv1.Problem{
		Type:      "https://tnl.dev/problems/" + problemType,
		Title:     title,
		Status:    status,
		Code:      code,
		RequestId: requestID,
		Details:   map[string]interface{}{},
	})
	if err != nil {
		http.Error(w, title, status)
		return
	}
	writeJSON(w, status, "application/problem+json", body)
}

func writeInternalProblem(w http.ResponseWriter, requestID string) {
	writeProblem(
		w, requestID, http.StatusInternalServerError, serverv1.Internal,
		"Internal server error", "internal",
	)
}

func writeInternalError(w http.ResponseWriter, requestID string, err error) {
	if reporter, ok := w.(interface{ report(error) }); ok {
		reporter.report(err)
	}
	if state.IsDatabaseContention(err) {
		writeProblem(
			w, requestID, http.StatusServiceUnavailable, serverv1.TemporarilyUnavailable,
			"Temporarily unavailable", "temporarily-unavailable",
		)
		return
	}
	writeInternalProblem(w, requestID)
}

func writeUnauthenticated(w http.ResponseWriter, requestID string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeProblem(
		w, requestID, http.StatusUnauthorized, serverv1.Unauthenticated,
		"Unauthenticated", "unauthenticated",
	)
}

func writeNotFound(w http.ResponseWriter, requestID string) {
	writeProblem(w, requestID, http.StatusNotFound, serverv1.NotFound, "Not found", "not-found")
}

func writeMethodNotAllowed(w http.ResponseWriter, requestID, allow string) {
	w.Header().Set("Allow", allow)
	writeProblem(
		w, requestID, http.StatusMethodNotAllowed, serverv1.InvalidArgument,
		"Method not allowed", "method-not-allowed",
	)
}

func writeJSON(w http.ResponseWriter, status int, contentType string, body []byte) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

func writeNoContent(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusNoContent)
}
