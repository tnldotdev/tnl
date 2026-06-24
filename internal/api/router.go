package api

import (
	"net/http"
	"slices"
	"strings"

	"github.com/tnldotdev/tnl/internal/auth"
)

type endpointHandler func(http.ResponseWriter, *http.Request, string)
type methodNotAllowedHandler func(http.ResponseWriter, *http.Request, string, string)

type registeredPath struct {
	allowed          []string
	validate         func(*http.Request) bool
	methodNotAllowed methodNotAllowedHandler
}

type routeRegistry struct {
	mux   *http.ServeMux
	paths map[string]*registeredPath
}

func (h *handler) newRouter() http.Handler {
	registry := &routeRegistry{mux: http.NewServeMux(), paths: map[string]*registeredPath{}}
	registry.handle(http.MethodGet, healthPath, OperationHealthGet, h.serveHealth, nil, nil)
	registry.handle(http.MethodGet, readinessPath, OperationReadinessGet, h.serveReadiness, nil, nil)
	registry.handle(http.MethodGet, clientIPPath, OperationClientIPGet, h.serveClientIP, nil, nil)
	registry.handle(http.MethodGet, capabilitiesPath, OperationCapabilitiesGet, h.serveCapabilities, nil, nil)
	registry.handle(http.MethodGet, relayMapPath, OperationRelayMapGet, h.serveRelayMap, nil, nil)
	registry.handle(http.MethodPost, tokenExchangePath, OperationTokenExchange, h.serveTokenExchange, nil, nil)
	registry.handle(http.MethodPost, oidcExchangePath, OperationOIDCTokenExchange, h.serveOIDCExchange, nil, nil)
	registry.handle(http.MethodPost, refreshPath, OperationControlSessionRefresh, h.serveRefresh, nil, nil)
	registry.handle(http.MethodPost, logoutPath, OperationControlSessionLogout, h.serveLogout, nil, nil)
	registry.handle(http.MethodGet, hostnamesPath, OperationHostnamesList, h.serveHostnames, nil, nil)
	registry.handle(http.MethodPost, hostnamesPath, OperationHostnameClaim, h.serveHostnames, nil, nil)
	registry.handle(http.MethodDelete, hostnamePrefix+"{id}", OperationHostnameRelease, func(w http.ResponseWriter, r *http.Request, requestID string) {
		h.serveHostname(w, r, requestID, r.PathValue("id"))
	}, validPathValue("id", validHostnameID), nil)
	registry.handle(http.MethodPost, domainVerificationsPath, OperationDomainVerificationCreate, h.serveDomainVerificationCreate, nil, nil)
	registry.handle(http.MethodGet, domainVerificationPrefix+"{id}", OperationDomainVerificationGet, func(w http.ResponseWriter, r *http.Request, requestID string) {
		h.serveDomainVerificationGet(w, r, requestID, r.PathValue("id"))
	}, nil, nil)
	registry.handle(http.MethodPost, domainVerificationPrefix+"{id}/complete", OperationDomainVerificationComplete, func(w http.ResponseWriter, r *http.Request, requestID string) {
		h.serveDomainVerificationComplete(w, r, requestID, r.PathValue("id"))
	}, nil, nil)
	registry.handle(http.MethodGet, routesPath, OperationRoutesList, h.serveRoutesList, nil, nil)
	registry.handle(http.MethodPost, routesPath, OperationRouteCreate, h.serveRouteCreate, nil, nil)
	registry.handle(http.MethodDelete, routePathPrefix+"{id}", OperationRouteDelete, pathValueEndpoint("id", h.serveRouteDelete), nil, nil)
	registry.handle(http.MethodPost, routePathPrefix+"{id}/sessions", OperationRouteSessionCreate, pathValueEndpoint("id", h.serveSessionAcquisition), nil, nil)
	registry.handle(http.MethodPost, routePathPrefix+"{id}/transport", OperationRouteTransportRegister, pathValueEndpoint("id", h.serveTransport), nil, nil)
	registry.handle(http.MethodPost, routePathPrefix+"{id}/heartbeat", OperationRouteHeartbeat, pathValueEndpoint("id", h.serveHeartbeat), nil, nil)
	registry.handle(http.MethodPost, routePathPrefix+"{id}/ready", OperationRouteReady, pathValueEndpoint("id", h.serveReady), nil, nil)
	registry.handle(http.MethodPost, routePathPrefix+"{id}/certificate-installed", OperationCertificateInstalled, pathValueEndpoint("id", h.serveCertificateInstalled), nil, nil)
	registry.handle(http.MethodPost, certificateIssuancesPath, OperationCertificateIssuanceCreate, h.serveCertificateIssuanceCreate, nil, nil)
	registry.handle(http.MethodGet, certificateIssuancePrefix+"{id}", OperationCertificateIssuanceGet, pathValueEndpoint("id", h.serveCertificateIssuanceGet), validPathValue("id", validCertificateIssuanceID), nil)
	registry.handle(http.MethodPost, certificateIssuancePrefix+"{id}/challenge-ready", OperationCertificateChallengeReady, pathValueEndpoint("id", h.serveCertificateChallengeReady), validPathValue("id", validCertificateIssuanceID), nil)
	registry.handle(http.MethodPost, certificateIssuancePrefix+"{id}/challenge-removed", OperationCertificateChallengeRemoved, pathValueEndpoint("id", h.serveCertificateChallengeRemoved), validPathValue("id", validCertificateIssuanceID), nil)

	h.registerAdminRoutes(registry)
	return registry.handler(h)
}

func (h *handler) registerAdminRoutes(registry *routeRegistry) {
	adminFallback := h.adminMethodNotAllowed(nil)
	registry.handle(http.MethodGet, "/v1/admin/status", OperationAdminServerStatus, h.adminEndpoint(h.serveAdminStatus), nil, adminFallback)
	registry.handle(http.MethodGet, "/v1/admin/routes", OperationAdminRoutesList, h.adminEndpoint(h.serveAdminRoutesList), nil, adminFallback)
	registry.handle(http.MethodGet, "/v1/admin/routes/{id}", OperationAdminRouteShow, h.adminPathValueEndpoint("id", validRouteID, h.serveAdminRoute), nil, h.adminMethodNotAllowed(validPathValue("id", validRouteID)))
	registry.handle(http.MethodPost, "/v1/admin/routes/{id}/suspend", OperationAdminRouteSuspend, h.adminPathValueEndpoint("id", validRouteID, h.serveAdminRouteSuspend), nil, h.adminMethodNotAllowed(validPathValue("id", validRouteID)))
	registry.handle(http.MethodPost, "/v1/admin/routes/{id}/resume", OperationAdminRouteResume, h.adminPathValueEndpoint("id", validRouteID, h.serveAdminRouteResume), nil, h.adminMethodNotAllowed(validPathValue("id", validRouteID)))
	registry.handle(http.MethodGet, "/v1/admin/hostnames", OperationAdminHostnamesList, h.adminEndpoint(h.serveAdminHostnamesList), nil, adminFallback)
	registry.handle(http.MethodGet, "/v1/admin/hostnames/{id}", OperationAdminHostnameShow, h.adminPathValueEndpoint("id", validHostnameID, h.serveAdminHostname), nil, h.adminMethodNotAllowed(validPathValue("id", validHostnameID)))
	registry.handle(http.MethodDelete, "/v1/admin/hostnames/{id}", OperationAdminHostnameRemove, h.adminPathValueEndpoint("id", validHostnameID, h.serveAdminHostnameRemove), nil, h.adminMethodNotAllowed(validPathValue("id", validHostnameID)))
	registry.handle(http.MethodPost, "/v1/admin/hostnames/{id}/quarantine", OperationAdminHostnameQuarantine, h.adminPathValueEndpoint("id", validHostnameID, h.serveAdminHostnameQuarantine), nil, h.adminMethodNotAllowed(validPathValue("id", validHostnameID)))
	registry.handle(http.MethodGet, "/v1/admin/credentials", OperationAdminCredentialsList, h.adminEndpoint(h.serveAdminCredentialsList), nil, adminFallback)
	registry.handle(http.MethodDelete, "/v1/admin/credentials/{id}", OperationAdminCredentialRevoke, h.adminPathValueEndpoint("id", validCredentialID, h.serveAdminCredentialRevoke), nil, h.adminMethodNotAllowed(validPathValue("id", validCredentialID)))
	registry.handle(http.MethodGet, "/v1/admin/control-sessions", OperationAdminControlSessionsList, h.adminEndpoint(h.serveAdminControlSessionsList), nil, adminFallback)
	registry.handle(http.MethodDelete, "/v1/admin/control-sessions/{id}", OperationAdminControlSessionRevoke, h.adminPathValueEndpoint("id", validControlSessionID, h.serveAdminControlSessionRevoke), nil, h.adminMethodNotAllowed(validPathValue("id", validControlSessionID)))
	registry.handle(http.MethodGet, "/v1/admin/maintenance-controls", OperationAdminMaintenanceControlsList, h.adminEndpoint(h.serveAdminMaintenanceControlsList), nil, adminFallback)
	registry.handle(http.MethodPut, "/v1/admin/maintenance-controls/{name}", OperationAdminMaintenanceControlSet, h.adminPathValueEndpoint("name", validAdminMaintenanceControl, h.serveAdminMaintenanceControlSet), nil, h.adminMethodNotAllowed(validPathValue("name", validAdminMaintenanceControl)))
}

func (r *routeRegistry) handle(
	method string,
	pattern string,
	operation Operation,
	endpoint endpointHandler,
	validate func(*http.Request) bool,
	methodNotAllowed methodNotAllowedHandler,
) {
	path := r.paths[pattern]
	if path == nil {
		path = &registeredPath{validate: validate, methodNotAllowed: methodNotAllowed}
		r.paths[pattern] = path
	}
	path.allowed = append(path.allowed, method)
	r.mux.HandleFunc(method+" "+pattern, func(w http.ResponseWriter, request *http.Request) {
		requestID := w.Header().Get(requestIDHeader)
		if validate != nil && !validate(request) {
			writeNotFound(w, requestID)
			return
		}
		setOperation(w, operation)
		endpoint(w, request, requestID)
	})
}

func (r *routeRegistry) handler(h *handler) http.Handler {
	for pattern, path := range r.paths {
		path := path
		fallback := func(w http.ResponseWriter, request *http.Request) {
			requestID := w.Header().Get(requestIDHeader)
			if path.validate != nil && !path.validate(request) {
				writeNotFound(w, requestID)
				return
			}
			allowed := strings.Join(path.allowed, ", ")
			if path.methodNotAllowed != nil {
				path.methodNotAllowed(w, request, requestID, allowed)
				return
			}
			writeMethodNotAllowed(w, requestID, allowed)
		}
		r.mux.HandleFunc(pattern, fallback)
		if slices.Contains(path.allowed, http.MethodGet) {
			r.mux.HandleFunc(http.MethodHead+" "+pattern, fallback)
		}
	}
	r.mux.HandleFunc("/v1/admin/{path...}", func(w http.ResponseWriter, request *http.Request) {
		requestID := w.Header().Get(requestIDHeader)
		if _, ok := adminPathParts(request.URL.Path); !ok {
			writeNotFound(w, requestID)
			return
		}
		h.serveAdminEndpoint(w, request, requestID, func(auth.Principal) {
			writeNotFound(w, requestID)
		})
	})
	r.mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		writeNotFound(w, w.Header().Get(requestIDHeader))
	})
	return r.mux
}

func pathValueEndpoint(name string, endpoint func(http.ResponseWriter, *http.Request, string, string)) endpointHandler {
	return func(w http.ResponseWriter, r *http.Request, requestID string) {
		endpoint(w, r, requestID, r.PathValue(name))
	}
}

func (h *handler) adminEndpoint(
	endpoint func(http.ResponseWriter, *http.Request, string, auth.Principal),
) endpointHandler {
	return func(w http.ResponseWriter, r *http.Request, requestID string) {
		h.serveAdminEndpoint(w, r, requestID, func(principal auth.Principal) {
			endpoint(w, r, requestID, principal)
		})
	}
}

func (h *handler) adminPathValueEndpoint(
	name string,
	valid func(string) bool,
	endpoint func(http.ResponseWriter, *http.Request, string, auth.Principal, string),
) endpointHandler {
	return h.adminEndpoint(func(w http.ResponseWriter, r *http.Request, requestID string, principal auth.Principal) {
		value := r.PathValue(name)
		if !valid(value) {
			writeNotFound(w, requestID)
			return
		}
		endpoint(w, r, requestID, principal, value)
	})
}

func (h *handler) adminMethodNotAllowed(validate func(*http.Request) bool) methodNotAllowedHandler {
	return func(w http.ResponseWriter, r *http.Request, requestID, allowed string) {
		h.serveAdminEndpoint(w, r, requestID, func(auth.Principal) {
			if validate != nil && !validate(r) {
				writeNotFound(w, requestID)
				return
			}
			writeMethodNotAllowed(w, requestID, allowed)
		})
	}
}

func validPathValue(name string, valid func(string) bool) func(*http.Request) bool {
	return func(r *http.Request) bool {
		return valid(r.PathValue(name))
	}
}

func setOperation(w http.ResponseWriter, operation Operation) {
	if observed, ok := w.(*observedResponseWriter); ok {
		observed.operation = operation
	}
}
