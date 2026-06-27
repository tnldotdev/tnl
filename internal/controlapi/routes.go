package controlapi

import (
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) ListRoutes(response http.ResponseWriter, request *http.Request, _ controlv1.ListRoutesParams) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	page, err := h.store.ListRoutes(
		request.Context(), principal.IdentityID, request.URL.Query().Get("team_id"), request.URL.Query().Get("cursor"),
	)
	if err != nil {
		writeControlStateProblem(response, "list routes", err)
		return
	}
	body := controlv1.RoutePage{Routes: make([]controlv1.Route, len(page.Routes))}
	for index, route := range page.Routes {
		body.Routes[index] = routeResponse(route)
	}
	if page.NextCursor != "" {
		body.NextCursor = &page.NextCursor
	}
	writeJSON(response, http.StatusOK, body)
}

func (h *handler) CreateRoute(response http.ResponseWriter, request *http.Request, _ controlv1.CreateRouteParams) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	var body controlv1.CreateRouteRequest
	if err := decodeJSON(request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	allowedIPPrefixes := []string(nil)
	if body.AllowedIpPrefixes != nil {
		var err error
		allowedIPPrefixes, err = authorization.CanonicalizeIPPrefixes(*body.AllowedIpPrefixes)
		if err != nil {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid IP policy")
			return
		}
	}
	membershipID := ""
	if body.MembershipId != nil {
		membershipID = *body.MembershipId
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRouteCreate, TeamID: body.TeamId, MembershipID: membershipID,
		DomainID: body.DomainId, CanonicalHostname: body.CanonicalHostname, RouteScope: string(body.RouteScope),
		Target: body.Target, AllowedIPPrefixes: allowedIPPrefixes,
	})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	route, err := h.store.CreateRoute(request.Context(), controlstate.CreateRouteRequest{
		TeamID: body.TeamId, DomainID: body.DomainId, MembershipID: membershipID,
		ActingIdentityID: principal.IdentityID, IdempotencyKey: request.Header.Get("Idempotency-Key"),
		RequestDigest: [32]byte(digest), CanonicalHostname: body.CanonicalHostname, Target: body.Target,
		RouteScope: controlstate.RouteScope(body.RouteScope), AllowedIPPrefixes: allowedIPPrefixes, DNSState: controlstate.RouteDNSUnmanaged,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create route", err)
		return
	}
	writeJSON(response, http.StatusCreated, routeResponse(route))
}

func (h *handler) GetRoute(response http.ResponseWriter, request *http.Request, routeID controlv1.RouteID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	route, err := h.store.GetRoute(request.Context(), principal.IdentityID, string(routeID))
	if err != nil {
		writeControlStateProblem(response, "get route", err)
		return
	}
	writeJSON(response, http.StatusOK, routeResponse(route))
}

func (h *handler) DeleteRoute(response http.ResponseWriter, request *http.Request, routeID controlv1.RouteID) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	if err := h.store.DeleteRoute(request.Context(), principal.IdentityID, string(routeID), time.Now()); err != nil {
		writeControlStateProblem(response, "delete route", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) CreateRouteSession(
	response http.ResponseWriter,
	request *http.Request,
	routeID controlv1.RouteID,
	_ controlv1.CreateRouteSessionParams,
) {
	principal, ok := h.authenticateControlRequest(response, request)
	if !ok {
		return
	}
	var body controlv1.CreateRouteSessionRequest
	if err := decodeJSON(request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if body.AllowedIpPrefixes == nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "IP policy is required")
		return
	}
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(body.AllowedIpPrefixes)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid IP policy")
		return
	}
	body.AllowedIpPrefixes = allowedIPPrefixes
	route, err := h.store.GetRoute(request.Context(), principal.IdentityID, string(routeID))
	if err != nil {
		writeControlStateProblem(response, "read route for session", err)
		return
	}
	membershipID := ""
	if body.MembershipId != nil {
		membershipID = *body.MembershipId
	}
	if body.TeamId != route.TeamID || body.PolicyRevision <= 0 || body.PolicyRevision != route.PolicyRevision ||
		!validLocalCertificatePlan(body.CertificatePlan, route.CanonicalHostname) {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "route session is not authorized")
		return
	}
	serviceAuthority, err := h.store.EnsureServiceAuthority(request.Context(), time.Now())
	if err != nil {
		log.Printf("read relay transport trust bundle: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	plan := authorization.CertificatePlan{
		CacheKey: body.CertificatePlan.CacheKey, Scope: body.CertificatePlan.Scope,
		Identifiers: slices.Clone(body.CertificatePlan.Identifiers), ChallengeMethod: string(body.CertificatePlan.ChallengeMethod),
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRouteSessionCreate, TeamID: route.TeamID, MembershipID: membershipID,
		DomainID: route.DomainID, CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope),
		RouteID: route.ID, RouteVersion: uint64(route.NextRouteVersion), PolicyRevision: uint64(body.PolicyRevision),
		CertificatePlan: &plan, AllowedIPPrefixes: allowedIPPrefixes,
	})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	setup, err := h.store.CreateRouteSession(request.Context(), controlstate.RouteSessionRequest{
		RouteID: route.ID, TeamID: route.TeamID, MembershipID: membershipID,
		ActingIdentityID: principal.IdentityID, RequireLocalAuthority: true, RetrySecret: principal.RetrySecret[:],
		IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestDigest: [32]byte(digest),
		PolicyRevision: uint64(body.PolicyRevision), CertificateCacheKey: plan.CacheKey,
		CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers,
		CertificateChallenge: plan.ChallengeMethod, AllowedIPPrefixes: allowedIPPrefixes,
	}, time.Now(), publisherLeaseDuration, publisherConnectionCredentialDuration)
	if err != nil {
		writeControlStateProblem(response, "create route session", err)
		return
	}
	route, err = h.store.GetRoute(request.Context(), principal.IdentityID, route.ID)
	if err != nil {
		writeControlStateProblem(response, "read created route session", err)
		return
	}
	writeJSON(response, http.StatusCreated, routeSessionSetupResponse(route, setup, body.CertificatePlan, serviceAuthority.CertificatePEM))
}

func (h *handler) HeartbeatRouteSession(response http.ResponseWriter, request *http.Request, routeSessionID controlv1.RouteSessionID) {
	var body controlv1.RouteSessionVersionRequest
	if err := decodeJSON(request, &body); err != nil || body.RouteVersion <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	authentication, ok := h.authenticateRouteSessionRequest(response, request, string(routeSessionID), uint64(body.RouteVersion))
	if !ok {
		return
	}
	setup, err := h.store.HeartbeatRouteSession(
		request.Context(), authentication, time.Now(), publisherLeaseDuration, publisherConnectionCredentialDuration,
	)
	if err != nil {
		writeControlStateProblem(response, "heartbeat route session", err)
		return
	}
	writeJSON(response, http.StatusOK, controlv1.RouteSessionHeartbeat{
		RouteSession:         routeSessionResponse(setup),
		PublisherConnections: publisherConnectionResponses(setup.PublisherConnections),
	})
}

func (h *handler) MarkRouteSessionCertificateInstalled(
	response http.ResponseWriter,
	request *http.Request,
	routeSessionID controlv1.RouteSessionID,
) {
	var body controlv1.CertificateInstalledRequest
	if err := decodeJSON(request, &body); err != nil || body.RouteVersion <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	now := time.Now()
	if body.IssuanceId == "" || len(body.IssuanceId) > 256 || strings.TrimSpace(body.IssuanceId) != body.IssuanceId || !body.NotAfter.After(now) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid certificate acknowledgement")
		return
	}
	authentication, ok := h.authenticateRouteSessionRequest(response, request, string(routeSessionID), uint64(body.RouteVersion))
	if !ok {
		return
	}
	lifecycle, err := h.store.MarkRouteCertificateInstalled(
		request.Context(), authentication, body.IssuanceId, body.NotAfter, now,
	)
	if err != nil {
		writeControlStateProblem(response, "mark route certificate installed", err)
		return
	}
	writeJSON(response, http.StatusOK, routeSessionLifecycleResponse(lifecycle))
}

func (h *handler) MarkRouteSessionReady(response http.ResponseWriter, request *http.Request, routeSessionID controlv1.RouteSessionID) {
	var body controlv1.RouteSessionVersionRequest
	if err := decodeJSON(request, &body); err != nil || body.RouteVersion <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	authentication, ok := h.authenticateRouteSessionRequest(response, request, string(routeSessionID), uint64(body.RouteVersion))
	if !ok {
		return
	}
	lifecycle, err := h.store.MarkRouteSessionReady(request.Context(), authentication, time.Now())
	if err != nil {
		writeControlStateProblem(response, "mark route session ready", err)
		return
	}
	writeJSON(response, http.StatusOK, routeSessionLifecycleResponse(lifecycle))
}

func (h *handler) CloseRouteSession(response http.ResponseWriter, request *http.Request, routeSessionID controlv1.RouteSessionID) {
	token, ok := requestBearerToken(request)
	if !ok || h.store == nil {
		writeBearerProblem(response)
		return
	}
	if err := h.store.CloseRouteSession(
		request.Context(), string(routeSessionID), credentials.SessionToken(token), time.Now(),
	); err != nil {
		writeControlStateProblem(response, "close route session", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
