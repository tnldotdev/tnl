package controlapi

import (
	"net/http"
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
	decision, ok := h.authorizeMutation(response, request, authorization.Request{
		Operation: authorization.OperationRouteCreate, TeamID: body.TeamId,
		RouteMembershipID: membershipID, DomainID: body.DomainId,
		CanonicalHostname: body.CanonicalHostname, RouteScope: string(body.RouteScope),
		Target: body.Target, AllowedIPPrefixes: allowedIPPrefixes,
	})
	if !ok {
		return
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRouteCreate, TeamID: decision.TeamID, MembershipID: decision.RouteMembershipID,
		DomainID: decision.DomainID, CanonicalHostname: decision.CanonicalHostname, RouteScope: decision.RouteScope,
		Target: body.Target, AllowedIPPrefixes: allowedIPPrefixes,
	})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	dnsState := controlstate.RouteDNSUnmanaged
	dnsAuthorityReference := ""
	if h.config.DNSAutomation {
		dnsState = controlstate.RouteDNSPending
		dnsAuthorityReference = decision.DNSAuthorityReference
	}
	route, err := h.store.CreateRoute(request.Context(), controlstate.CreateRouteRequest{
		TeamID: decision.TeamID, DomainID: decision.DomainID, MembershipID: decision.RouteMembershipID,
		ActingIdentityID: decision.IdentityID, IdempotencyKey: request.Header.Get("Idempotency-Key"),
		RequestDigest: [32]byte(digest), CanonicalHostname: decision.CanonicalHostname, Target: body.Target,
		RouteScope: controlstate.RouteScope(decision.RouteScope), AllowedIPPrefixes: allowedIPPrefixes,
		DNSState: dnsState, DNSAuthorityReference: dnsAuthorityReference,
		AuthorityIssuer: h.externalAuthorityIssuer(),
		PolicyRevision:  decision.TeamPolicyRevision,
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
	route, err := h.store.GetRouteForAuthorization(request.Context(), string(routeID))
	if err != nil {
		writeControlStateProblem(response, "read route for deletion", err)
		return
	}
	allowedIPPrefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowedIPPrefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeMutation(response, request, authorization.Request{
		Operation: authorization.OperationRouteDelete, TeamID: route.TeamID,
		RouteMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope),
		Target: route.Target, AllowedIPPrefixes: allowedIPPrefixes, RouteID: route.ID,
	})
	if !ok {
		return
	}
	if err := h.store.DeleteAuthorizedRoute(request.Context(), controlstate.AuthorizedRouteDeleteRequest{
		RouteID: route.ID, TeamID: decision.TeamID, ActingIdentityID: decision.IdentityID,
		AuthorityIssuer: h.externalAuthorityIssuer(), PolicyRevision: decision.TeamPolicyRevision,
	}, time.Now()); err != nil {
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
	route, err := h.store.GetRouteForAuthorization(request.Context(), string(routeID))
	if err != nil {
		writeControlStateProblem(response, "read route for session", err)
		return
	}
	allowedIPPrefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowedIPPrefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeMutation(response, request, authorization.Request{
		Operation: authorization.OperationRouteSessionCreate, TeamID: route.TeamID,
		RouteMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope),
		Target: route.Target, AllowedIPPrefixes: allowedIPPrefixes,
		RouteID: route.ID, RouteVersion: uint64(route.NextRouteVersion),
	})
	if !ok {
		return
	}
	if decision.CertificatePlan == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return
	}
	plan := *decision.CertificatePlan
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRouteSessionCreate, TeamID: decision.TeamID, MembershipID: decision.ActingMembershipID,
		DomainID: decision.DomainID, CanonicalHostname: decision.CanonicalHostname, RouteScope: decision.RouteScope,
		RouteID: route.ID, RouteVersion: uint64(route.NextRouteVersion), PolicyRevision: decision.TeamPolicyRevision,
		CertificatePlan: &plan, AllowedIPPrefixes: allowedIPPrefixes,
	})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	setup, err := h.store.CreateRouteSession(request.Context(), controlstate.RouteSessionRequest{
		RouteID: route.ID, TeamID: decision.TeamID, MembershipID: decision.ActingMembershipID,
		ActingIdentityID: decision.IdentityID, RequireLocalAuthority: h.externalAuthorityIssuer() == "",
		RetrySecret:    decision.RetrySecret[:],
		IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestDigest: [32]byte(digest),
		PolicyRevision: decision.TeamPolicyRevision, CertificateCacheKey: plan.CacheKey,
		CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers,
		CertificateChallenge: plan.ChallengeMethod, AllowedIPPrefixes: allowedIPPrefixes,
		AuthorityIssuer: h.externalAuthorityIssuer(),
	}, time.Now(), publisherLeaseDuration, publisherConnectionCredentialDuration)
	if err != nil {
		writeControlStateProblem(response, "create route session", err)
		return
	}
	route, err = h.store.GetRouteForAuthorization(request.Context(), route.ID)
	if err != nil {
		writeControlStateProblem(response, "read created route session", err)
		return
	}
	writeJSON(response, http.StatusCreated, routeSessionSetupResponse(route, setup, controlv1.CertificatePlan{
		CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers,
		ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod),
	}))
}

func (h *handler) externalAuthorityIssuer() string {
	if h.config.HostedSecret == "" {
		return ""
	}
	return h.config.AuthorityEndpoint
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
