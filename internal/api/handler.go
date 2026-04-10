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
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/0xcadams/tnl/internal/auth"
	"github.com/0xcadams/tnl/internal/certificates"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/internal/naming"
	"github.com/0xcadams/tnl/internal/routes"
	"github.com/0xcadams/tnl/internal/state"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"tailscale.com/types/key"
)

const (
	capabilitiesPath       = "/v1/capabilities"
	tokenExchangePath      = "/v1/auth/token"
	credentialsPath        = "/v1/auth/credentials/"
	certificateOrdersPath  = "/v1/certs/orders"
	certificateOrderPrefix = "/v1/certs/orders/"
	hostnameClaimsPath     = "/v1/hostname-claims"
	hostnameClaimPrefix    = "/v1/hostname-claims/"
	routesPath             = "/v1/routes"
	routePathPrefix        = "/v1/routes/"
	authorizationHeader    = "Authorization"
	idempotencyKeyHeader   = "Idempotency-Key"
	requestIDHeader        = "X-Request-ID"
	maxCredentialBytes     = 128
	maxJSONRequestBytes    = 20 << 10
	maxJSONResponseBytes   = 64 << 10
	jsonReadTimeout        = 10 * time.Second
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
	OperationCapabilitiesGet             Operation = "capabilities.get"
	OperationTokenExchange               Operation = "auth.token.exchange"
	OperationCredentialRevoke            Operation = "auth.credential.revoke"
	OperationHostnameClaimsList          Operation = "hostname_claims.list"
	OperationHostnameClaimCreate         Operation = "hostname_claims.create"
	OperationHostnameClaimRelease        Operation = "hostname_claims.release"
	OperationRoutesList                  Operation = "routes.list"
	OperationRouteCreate                 Operation = "routes.create"
	OperationRouteDelete                 Operation = "routes.delete"
	OperationRouteLeaseAcquire           Operation = "routes.lease.acquire"
	OperationRouteTransportRegister      Operation = "routes.transport.register"
	OperationRouteHeartbeat              Operation = "routes.heartbeat"
	OperationRouteReady                  Operation = "routes.ready"
	OperationCertificateOrderCreate      Operation = "certificate_orders.create"
	OperationCertificateOrderGet         Operation = "certificate_orders.get"
	OperationCertificateChallengeReady   Operation = "certificate_orders.challenge_ready"
	OperationCertificateChallengeRemoved Operation = "certificate_orders.challenge_removed"
	OperationCertificateInstalled        Operation = "certificate_orders.installed"
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
	Observer      Observer
	ErrorReporter ErrorReporter
}

// AuthService implements authentication flows without exposing storage to HTTP.
type AuthService interface {
	Exchange(context.Context, credentials.BootstrapToken) (auth.IssuedAccessToken, error)
	Authenticate(context.Context, credentials.AccessToken) (state.Principal, error)
	Revoke(context.Context, state.Principal, credentials.CredentialID) error
}

// RouteService implements hostname claims and fenced route transitions.
type RouteService interface {
	ClaimHostname(context.Context, string, string, string) (routes.HostnameClaim, error)
	ListHostnameClaimsPage(context.Context, string, string) ([]routes.HostnameClaim, string, error)
	ReleaseHostnameClaim(context.Context, string, string) error
	Create(context.Context, string, string, string, credentials.RouteToken) (routes.LeaseSetup, error)
	Acquire(context.Context, string, string, credentials.RouteToken) (routes.LeaseSetup, error)
	RegisterTransport(context.Context, string, uint64, credentials.LeaseToken, string, string) error
	Ready(context.Context, string, uint64, credentials.LeaseToken) error
	Heartbeat(context.Context, string, uint64, credentials.LeaseToken) (time.Time, error)
	AuthorizeLease(context.Context, string, uint64, credentials.LeaseToken) error
	List(context.Context, string) ([]routes.Route, error)
	Delete(context.Context, string, string) error
}

// CertificateService implements durable certificate transitions without exposing storage to HTTP.
type CertificateService interface {
	Create(context.Context, string, uint64, string, []byte) (certificates.Job, error)
	Get(context.Context, string) (certificates.Job, error)
	ChallengeReady(context.Context, string) (certificates.Job, error)
	ChallengeRemoved(context.Context, string) (certificates.Job, error)
	Installed(context.Context, string, string, uint64) (certificates.Job, error)
}

type handler struct {
	capabilities  corev1.Capabilities
	auth          AuthService
	routes        RouteService
	certificates  CertificateService
	observer      Observer
	errorReporter ErrorReporter
}

// NewHandler creates the core API handler without binding a listener.
func NewHandler(capabilities corev1.Capabilities, auth AuthService) http.Handler {
	return NewHandlerWithRoutes(capabilities, auth, nil)
}

// NewHandlerWithRoutes enables hostname-claim and route endpoints.
func NewHandlerWithRoutes(capabilities corev1.Capabilities, auth AuthService, routeService RouteService) http.Handler {
	return NewHandlerWithServices(capabilities, auth, routeService, nil)
}

// NewHandlerWithServices enables hostname-claim, route, and certificate endpoints.
func NewHandlerWithServices(
	capabilities corev1.Capabilities,
	auth AuthService,
	routeService RouteService,
	certificateService CertificateService,
) http.Handler {
	return NewHandlerWithServicesAndConfig(capabilities, auth, routeService, certificateService, HandlerConfig{})
}

// NewHandlerWithServicesAndConfig enables all API services and production observability hooks.
func NewHandlerWithServicesAndConfig(
	capabilities corev1.Capabilities,
	auth AuthService,
	routeService RouteService,
	certificateService CertificateService,
	config HandlerConfig,
) http.Handler {
	return &handler{
		capabilities:  capabilities,
		auth:          auth,
		routes:        routeService,
		certificates:  certificateService,
		observer:      config.Observer,
		errorReporter: config.ErrorReporter,
	}
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
	case capabilitiesPath:
		h.serveCapabilities(w, r, requestID)
	case tokenExchangePath:
		h.serveTokenExchange(w, r, requestID)
	case hostnameClaimsPath:
		h.serveHostnameClaims(w, r, requestID)
	case routesPath:
		h.serveRoutes(w, r, requestID)
	case certificateOrdersPath:
		h.serveCertificateOrders(w, r, requestID)
	default:
		claimID, ok := strings.CutPrefix(r.URL.Path, hostnameClaimPrefix)
		if ok && validHostnameClaimID(claimID) {
			h.serveHostnameClaim(w, r, requestID, claimID)
			return
		}
		credentialID, ok := strings.CutPrefix(r.URL.Path, credentialsPath)
		if ok && credentialID != "" && !strings.Contains(credentialID, "/") {
			h.serveCredentialRevocation(w, r, requestID, credentialID)
			return
		}
		if routeID, operation, ok := routePath(r.URL.Path); ok {
			h.serveRoute(w, r, requestID, routeID, operation)
			return
		}
		if orderID, operation, ok := certificateOrderPath(r.URL.Path); ok {
			h.serveCertificateOrder(w, r, requestID, orderID, operation)
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
	switch path {
	case capabilitiesPath:
		if method == http.MethodGet {
			return OperationCapabilitiesGet
		}
	case tokenExchangePath:
		if method == http.MethodPost {
			return OperationTokenExchange
		}
	case hostnameClaimsPath:
		switch method {
		case http.MethodGet:
			return OperationHostnameClaimsList
		case http.MethodPost:
			return OperationHostnameClaimCreate
		}
	case routesPath:
		switch method {
		case http.MethodGet:
			return OperationRoutesList
		case http.MethodPost:
			return OperationRouteCreate
		}
	case certificateOrdersPath:
		if method == http.MethodPost {
			return OperationCertificateOrderCreate
		}
	}

	if claimID, ok := strings.CutPrefix(path, hostnameClaimPrefix); ok &&
		validHostnameClaimID(claimID) && method == http.MethodDelete {
		return OperationHostnameClaimRelease
	}
	if credentialID, ok := strings.CutPrefix(path, credentialsPath); ok && credentialID != "" &&
		!strings.Contains(credentialID, "/") && method == http.MethodDelete {
		return OperationCredentialRevoke
	}
	if _, routeOperation, ok := routePath(path); ok {
		switch {
		case routeOperation == "" && method == http.MethodDelete:
			return OperationRouteDelete
		case routeOperation == "leases" && method == http.MethodPost:
			return OperationRouteLeaseAcquire
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
	if _, certificateOperation, ok := certificateOrderPath(path); ok {
		switch {
		case certificateOperation == "" && method == http.MethodGet:
			return OperationCertificateOrderGet
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

func (h *handler) serveHostnameClaims(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodGet+", "+http.MethodPost)
		return
	}
	principal, ok := h.authenticate(w, r, requestID)
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
			if !ok || len(query) != 1 || len(values) != 1 || !validHostnameClaimID(values[0]) {
				writeInvalidRequest(w, requestID)
				return
			}
			cursor = values[0]
		}
		claims, next, err := h.routes.ListHostnameClaimsPage(r.Context(), principal.ID, cursor)
		if err != nil {
			writeRouteError(w, requestID, err)
			return
		}
		response := corev1.HostnameClaimPage{Claims: make([]corev1.HostnameClaim, 0, len(claims))}
		for _, claim := range claims {
			response.Claims = append(response.Claims, hostnameClaimResponse(claim))
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
	var request corev1.CreateHostnameClaimRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	label := ""
	if request.Label != nil {
		label = *request.Label
	}
	claim, err := h.routes.ClaimHostname(r.Context(), principal.ID, label, requestKey)
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, hostnameClaimResponse(claim))
}

func (h *handler) serveHostnameClaim(w http.ResponseWriter, r *http.Request, requestID, claimID string) {
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, requestID, http.MethodDelete)
		return
	}
	principal, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if err := h.routes.ReleaseHostnameClaim(r.Context(), principal.ID, claimID); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveCapabilities(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet {
		writeMethodNotAllowed(w, requestID, http.MethodGet)
		return
	}

	body, err := marshalJSON(h.capabilities)
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func (h *handler) serveTokenExchange(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	var request corev1.TokenExchangeRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.BootstrapToken == "" || len(request.BootstrapToken) > maxCredentialBytes {
		writeProblem(
			w, requestID, http.StatusBadRequest, corev1.InvalidArgument,
			"Invalid request", "invalid-request",
		)
		return
	}
	if h.auth == nil {
		writeInternalError(w, requestID, errAuthServiceMissing)
		return
	}
	issued, err := h.auth.Exchange(r.Context(), credentials.BootstrapToken(request.BootstrapToken))
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeProblem(
			w, requestID, http.StatusUnauthorized, corev1.Unauthenticated,
			"Unauthenticated", "unauthenticated",
		)
		return
	}
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	body, err := marshalJSON(corev1.TokenExchangeResponse{
		AccessToken:  issued.Token.String(),
		CredentialId: issued.CredentialID.String(),
		ExpiresAt:    issued.ExpiresAt,
		TokenType:    corev1.Bearer,
	})
	if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeJSON(w, http.StatusOK, "application/json", body)
}

func (h *handler) serveCredentialRevocation(
	w http.ResponseWriter,
	r *http.Request,
	requestID string,
	credentialIDValue string,
) {
	if r.Method != http.MethodDelete {
		writeMethodNotAllowed(w, requestID, http.MethodDelete)
		return
	}
	principal, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	credentialID, err := credentials.ParseCredentialID(credentialIDValue)
	if err != nil {
		writeProblem(
			w, requestID, http.StatusBadRequest, corev1.InvalidArgument,
			"Invalid request", "invalid-request",
		)
		return
	}
	if err := h.auth.Revoke(r.Context(), principal, credentialID); errors.Is(err, auth.ErrCredentialNotFound) {
		writeNotFound(w, requestID)
		return
	} else if err != nil {
		writeInternalError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveRoutes(w http.ResponseWriter, r *http.Request, requestID string) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodGet+", "+http.MethodPost)
		return
	}
	principal, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	if h.routes == nil {
		writeInternalError(w, requestID, errRouteServiceMissing)
		return
	}
	if r.Method == http.MethodGet {
		stored, err := h.routes.List(r.Context(), principal.ID)
		if err != nil {
			writeRouteError(w, requestID, err)
			return
		}
		response := make([]corev1.Route, 0, len(stored))
		for _, route := range stored {
			response = append(response, routeResponse(route))
		}
		writeModel(w, requestID, http.StatusOK, response)
		return
	}
	var request corev1.CreateRouteRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	routeToken := credentials.RouteToken(request.RouteToken)
	if strings.TrimSpace(request.DisplayTarget) == "" || len(request.DisplayTarget) > 256 ||
		len(request.RouteToken) > maxCredentialBytes {
		writeInvalidRequest(w, requestID)
		return
	}
	if _, _, err := credentials.ParseRouteToken(routeToken); err != nil {
		writeInvalidRequest(w, requestID)
		return
	}
	setup, err := h.routes.Create(r.Context(), principal.ID, request.Hostname, request.DisplayTarget, routeToken)
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, leaseSetupResponse(setup))
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
		principal, ok := h.authenticate(w, r, requestID)
		if !ok {
			return
		}
		if err := h.routes.Delete(r.Context(), principal.ID, routeID); err != nil {
			writeRouteError(w, requestID, err)
			return
		}
		writeNoContent(w)
	case "leases":
		h.serveLeaseAcquisition(w, r, requestID, routeID)
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

func (h *handler) serveCertificateOrders(w http.ResponseWriter, r *http.Request, requestID string) {
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
	token, ok := leaseBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request corev1.CreateCertificateOrderRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	csrDER, err := base64.RawURLEncoding.DecodeString(request.Csr)
	if request.RouteId == "" || request.Generation <= 0 || request.Profile == "" || err != nil ||
		base64.RawURLEncoding.EncodeToString(csrDER) != request.Csr {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.routes.AuthorizeLease(
		r.Context(), request.RouteId, uint64(request.Generation), token,
	); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	job, err := h.certificates.Create(
		r.Context(), request.RouteId, uint64(request.Generation), request.Profile, csrDER,
	)
	if err != nil {
		writeCertificateError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, certificateOrderResponse(job))
}

func (h *handler) serveCertificateOrder(
	w http.ResponseWriter,
	r *http.Request,
	requestID, orderID, operation string,
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
	token, ok := leaseBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	job, err := h.certificates.Get(r.Context(), orderID)
	if err != nil {
		writeCertificateError(w, requestID, err)
		return
	}
	if err := h.routes.AuthorizeLease(r.Context(), job.RouteID, job.Generation, token); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	switch operation {
	case "":
		writeModel(w, requestID, http.StatusOK, certificateOrderResponse(job))
	case "challenge-ready":
		job, err = h.certificates.ChallengeReady(r.Context(), orderID)
		if err != nil {
			writeCertificateError(w, requestID, err)
			return
		}
		writeModel(w, requestID, http.StatusOK, certificateOrderResponse(job))
	case "challenge-removed":
		if _, err := h.certificates.ChallengeRemoved(r.Context(), orderID); err != nil {
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
	token, ok := leaseBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request corev1.CertificateInstalledRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Generation <= 0 || !validCertificateOrderID(request.OrderId) {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.routes.AuthorizeLease(r.Context(), routeID, uint64(request.Generation), token); err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	if _, err := h.certificates.Installed(
		r.Context(), request.OrderId, routeID, uint64(request.Generation),
	); err != nil {
		writeCertificateError(w, requestID, err)
		return
	}
	writeNoContent(w)
}

func (h *handler) serveLeaseAcquisition(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	principal, ok := h.authenticate(w, r, requestID)
	if !ok {
		return
	}
	var request corev1.AcquireLeaseRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.RouteToken == "" || len(request.RouteToken) > maxCredentialBytes {
		writeInvalidRequest(w, requestID)
		return
	}
	setup, err := h.routes.Acquire(r.Context(), principal.ID, routeID, credentials.RouteToken(request.RouteToken))
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusCreated, leaseSetupResponse(setup))
}

func (h *handler) serveTransport(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	token, ok := leaseBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request corev1.RegisterTransportRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	var serverKey key.NodePublic
	if request.Generation <= 0 || request.Endpoint.Version != corev1.TailcatDescriptorVersionN1 ||
		serverKey.UnmarshalText([]byte(request.Endpoint.ServerPublicKey)) != nil || serverKey.IsZero() ||
		request.Endpoint.RelayProfile != h.capabilities.Transport.RelayProfile {
		writeInvalidRequest(w, requestID)
		return
	}
	err := h.routes.RegisterTransport(
		r.Context(), routeID, uint64(request.Generation), token,
		request.Endpoint.ServerPublicKey, request.Endpoint.RelayProfile,
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
	token, ok := leaseBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request corev1.LeaseGenerationRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Generation <= 0 {
		writeInvalidRequest(w, requestID)
		return
	}
	expiresAt, err := h.routes.Heartbeat(r.Context(), routeID, uint64(request.Generation), token)
	if err != nil {
		writeRouteError(w, requestID, err)
		return
	}
	writeModel(w, requestID, http.StatusOK, corev1.HeartbeatResponse{ExpiresAt: expiresAt})
}

func (h *handler) serveReady(w http.ResponseWriter, r *http.Request, requestID, routeID string) {
	if r.Method != http.MethodPost {
		writeMethodNotAllowed(w, requestID, http.MethodPost)
		return
	}
	token, ok := leaseBearer(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return
	}
	var request corev1.LeaseGenerationRequest
	if !decodeRequest(w, r, requestID, &request) {
		return
	}
	if request.Generation <= 0 {
		writeInvalidRequest(w, requestID)
		return
	}
	if err := h.routes.Ready(r.Context(), routeID, uint64(request.Generation), token); err != nil {
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

func leaseBearer(header http.Header) (credentials.LeaseToken, bool) {
	token, err := credentials.Bearer(header)
	return credentials.LeaseToken(token), err == nil && len(token) <= maxCredentialBytes
}

func (h *handler) authenticate(w http.ResponseWriter, r *http.Request, requestID string) (state.Principal, bool) {
	if h.auth == nil {
		writeInternalError(w, requestID, errAuthServiceMissing)
		return state.Principal{}, false
	}
	token, ok := bearerToken(r.Header)
	if !ok {
		writeUnauthenticated(w, requestID)
		return state.Principal{}, false
	}
	principal, err := h.auth.Authenticate(r.Context(), token)
	if errors.Is(err, auth.ErrUnauthenticated) {
		writeUnauthenticated(w, requestID)
		return state.Principal{}, false
	}
	if err != nil {
		writeInternalError(w, requestID, err)
		return state.Principal{}, false
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

func certificateOrderPath(path string) (orderID, operation string, ok bool) {
	remainder, ok := strings.CutPrefix(path, certificateOrderPrefix)
	if !ok || remainder == "" {
		return "", "", false
	}
	parts := strings.Split(remainder, "/")
	if len(parts) > 2 || !validCertificateOrderID(parts[0]) || len(parts) == 2 && parts[1] == "" {
		return "", "", false
	}
	if len(parts) == 2 {
		operation = parts[1]
	}
	return parts[0], operation, true
}

func validCertificateOrderID(value string) bool {
	const prefix = "cert_"
	if len(value) != len(prefix)+32 || !strings.HasPrefix(value, prefix) {
		return false
	}
	_, err := hex.DecodeString(value[len(prefix):])
	return err == nil
}

func validHostnameClaimID(value string) bool {
	const prefix = "claim_"
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
		writeProblem(w, requestID, status, corev1.InvalidArgument, title, problemType)
		return false
	}
	return true
}

func routeResponse(route routes.Route) corev1.Route {
	return corev1.Route{
		Id: route.ID, Hostname: route.Hostname, DisplayTarget: route.DisplayTarget,
		State: corev1.RouteState(route.State), Generation: int(route.Generation), CreatedAt: route.CreatedAt,
	}
}

func hostnameClaimResponse(claim routes.HostnameClaim) corev1.HostnameClaim {
	return corev1.HostnameClaim{
		Id: claim.ID, Hostname: claim.Hostname, Irreversible: claim.Irreversible, CreatedAt: claim.CreatedAt,
	}
}

func leaseSetupResponse(setup routes.LeaseSetup) corev1.LeaseSetup {
	return corev1.LeaseSetup{
		Route: routeResponse(setup.Route),
		Lease: corev1.RouteLease{
			Id: setup.Lease.ID, RouteId: setup.Lease.RouteID, Generation: int(setup.Lease.Generation),
			Status: corev1.RouteLeaseStatus(setup.Lease.Status), CreatedAt: setup.Lease.CreatedAt, ExpiresAt: setup.Lease.ExpiresAt,
		},
		LeaseToken: setup.LeaseToken.String(), IngressPublicKey: setup.IngressPublicKey,
	}
}

func certificateOrderResponse(job certificates.Job) corev1.CertificateOrder {
	response := corev1.CertificateOrder{
		Id: job.ID, RouteId: job.RouteID, Generation: int(job.Generation), Hostname: job.Hostname,
		Profile: job.Profile, State: corev1.CertificateOrderState(job.State), CreatedAt: job.CreatedAt, UpdatedAt: job.UpdatedAt,
	}
	if challenge := job.Challenge(); challenge != nil {
		response.Challenge = &corev1.CertificateChallenge{
			Id: challenge.ID, Hostname: challenge.Hostname,
			Digest: base64.RawURLEncoding.EncodeToString(challenge.Digest[:]), ExpiresAt: challenge.ExpiresAt,
		}
	}
	if len(job.CertificatePEM) != 0 {
		value := string(job.CertificatePEM)
		response.CertificatePem = &value
	}
	if !job.NotBefore.IsZero() {
		response.NotBefore = &job.NotBefore
	}
	if !job.NotAfter.IsZero() {
		response.NotAfter = &job.NotAfter
	}
	if !job.RenewAt.IsZero() {
		response.RenewAt = &job.RenewAt
	}
	if !job.RetryAt.IsZero() {
		response.RetryAt = &job.RetryAt
	}
	if job.LastError != "" {
		response.Error = &job.LastError
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
		writeProblem(w, requestID, http.StatusConflict, corev1.NameUnavailable, "Name unavailable", "name-unavailable")
	case errors.Is(err, routes.ErrRouteExists), errors.Is(err, routes.ErrStaleLease), errors.Is(err, routes.ErrInvalidState):
		writeProblem(w, requestID, http.StatusConflict, corev1.StateConflict, "State conflict", "state-conflict")
	case errors.Is(err, routes.ErrNoWorkerCapacity):
		writeProblem(w, requestID, http.StatusServiceUnavailable, corev1.TemporarilyUnavailable, "Temporarily unavailable", "temporarily-unavailable")
	default:
		if errors.Is(err, routes.ErrInvalidArgument) {
			writeInvalidRequest(w, requestID)
			return
		}
		if _, ok := naming.ErrorCodeOf(err); ok {
			writeProblem(w, requestID, http.StatusBadRequest, corev1.InvalidArgument, "Invalid request", "invalid-request")
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
	case errors.Is(err, certificates.ErrInvalidState):
		writeProblem(w, requestID, http.StatusPreconditionFailed, corev1.PreconditionFailed, "Precondition failed", "precondition-failed")
	case errors.Is(err, certificates.ErrRateLimited):
		var limit *certificates.RateLimitError
		if errors.As(err, &limit) {
			// Round up so clients never retry before the stored deadline.
			seconds := max(1, int((time.Until(limit.RetryAt)+time.Second-1)/time.Second))
			w.Header().Set("Retry-After", strconv.Itoa(seconds))
		}
		writeProblem(w, requestID, http.StatusTooManyRequests, corev1.RateLimited, "Rate limited", "rate-limited")
	case errors.Is(err, certificates.ErrUnavailable):
		writeProblem(w, requestID, http.StatusServiceUnavailable, corev1.TemporarilyUnavailable, "Temporarily unavailable", "temporarily-unavailable")
	default:
		writeInternalError(w, requestID, err)
	}
}

func writeInvalidRequest(w http.ResponseWriter, requestID string) {
	writeProblem(w, requestID, http.StatusBadRequest, corev1.InvalidArgument, "Invalid request", "invalid-request")
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
	code corev1.ProblemCode,
	title string,
	problemType string,
) {
	body, err := marshalJSON(corev1.Problem{
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
		w, requestID, http.StatusInternalServerError, corev1.Internal,
		"Internal server error", "internal",
	)
}

func writeInternalError(w http.ResponseWriter, requestID string, err error) {
	if reporter, ok := w.(interface{ report(error) }); ok {
		reporter.report(err)
	}
	writeInternalProblem(w, requestID)
}

func writeUnauthenticated(w http.ResponseWriter, requestID string) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	writeProblem(
		w, requestID, http.StatusUnauthorized, corev1.Unauthenticated,
		"Unauthenticated", "unauthenticated",
	)
}

func writeNotFound(w http.ResponseWriter, requestID string) {
	writeProblem(w, requestID, http.StatusNotFound, corev1.NotFound, "Not found", "not-found")
}

func writeMethodNotAllowed(w http.ResponseWriter, requestID, allow string) {
	w.Header().Set("Allow", allow)
	writeProblem(
		w, requestID, http.StatusMethodNotAllowed, corev1.InvalidArgument,
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
