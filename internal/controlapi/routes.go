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
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if _, authorized := principal.teamIDs[teamID]; !authorized {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
		return
	}
	page, err := h.store.ListAuthorizedRoutes(request.Context(), teamID, request.URL.Query().Get("cursor"))
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
	if err := decodeJSON(response, request, &body); err != nil {
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
	if err := authorization.ValidateRouteTarget(body.Target); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid target")
		return
	}
	membershipID := ""
	if body.MembershipId != nil {
		membershipID = *body.MembershipId
	}
	ephemeral := body.Ephemeral != nil && *body.Ephemeral
	decision, ok := h.authorizeMutation(response, request, authorization.Request{
		Operation: authorization.OperationRouteCreate, TeamID: body.TeamId,
		RouteMembershipID: membershipID, DomainID: body.DomainId,
		CanonicalHostname: body.CanonicalHostname, RouteScope: string(body.RouteScope),
		Target: body.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: ephemeral,
	})
	if !ok {
		return
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRouteCreate, TeamID: decision.TeamID, MembershipID: decision.RouteMembershipID,
		DomainID: decision.DomainID, CanonicalHostname: decision.CanonicalHostname, RouteScope: decision.RouteScope,
		Target: body.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: ephemeral,
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
		Ephemeral:       ephemeral,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create route", err)
		return
	}
	writeJSON(response, http.StatusCreated, routeResponse(route))
}

func (h *handler) UpdateRoute(response http.ResponseWriter, request *http.Request, routeID controlv1.RouteID) {
	if _, ok := requestBearerToken(request); !ok {
		writeBearerProblem(response)
		return
	}
	var body struct {
		Target            *string   `json:"target"`
		AllowedIPPrefixes *[]string `json:"allowed_ip_prefixes"`
	}
	if err := decodeJSON(response, request, &body); err != nil || body.Target == nil || body.AllowedIPPrefixes == nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if err := authorization.ValidateRouteTarget(*body.Target); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid target")
		return
	}
	allowedIPPrefixes, err := authorization.CanonicalizeIPPrefixes(*body.AllowedIPPrefixes)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid IP policy")
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	route, err := h.store.GetRouteForAuthorization(request.Context(), string(routeID))
	if err != nil {
		writeControlStateProblem(response, "read route for update", err)
		return
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationRouteUpdate, TeamID: route.TeamID,
		RouteMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope),
		Target: *body.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: route.Ephemeral, RouteID: route.ID,
		RouteMutationRevision: route.MutationRevision,
	})
	if !ok {
		return
	}
	updated, err := h.store.UpdateAuthorizedRoute(request.Context(), controlstate.AuthorizedRouteUpdateRequest{
		RouteID: route.ID, TeamID: decision.TeamID, ActingIdentityID: decision.IdentityID,
		Target: *body.Target, AllowedIPPrefixes: allowedIPPrefixes,
		AuthorityIssuer: h.externalAuthorityIssuer(), PolicyRevision: decision.TeamPolicyRevision,
		ExpectedMutationRevision: route.MutationRevision,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "update route", err)
		return
	}
	writeJSON(response, http.StatusOK, routeResponse(updated))
}

func (h *handler) GetRoute(response http.ResponseWriter, request *http.Request, routeID controlv1.RouteID) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	route, err := h.store.GetRouteForAuthorization(request.Context(), string(routeID))
	if err != nil {
		writeControlStateProblem(response, "get route", err)
		return
	}
	if _, authorized := principal.teamIDs[route.TeamID]; !authorized {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	writeJSON(response, http.StatusOK, routeResponse(route))
}

func (h *handler) DeleteRoute(response http.ResponseWriter, request *http.Request, routeID controlv1.RouteID) {
	if _, ok := requestBearerToken(request); !ok {
		writeBearerProblem(response)
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	route, err := h.store.GetRouteForAuthorization(request.Context(), string(routeID))
	if err != nil {
		writeControlStateProblem(response, "read route for deletion", err)
		return
	}
	allowedIPPrefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowedIPPrefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationRouteDelete, TeamID: route.TeamID,
		RouteMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope),
		Target: route.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: route.Ephemeral, RouteID: route.ID,
		RouteMutationRevision: route.MutationRevision,
	})
	if !ok {
		return
	}
	if err := h.store.DeleteAuthorizedRoute(request.Context(), controlstate.AuthorizedRouteDeleteRequest{
		RouteID: route.ID, TeamID: decision.TeamID, ActingIdentityID: decision.IdentityID,
		AuthorityIssuer: h.externalAuthorityIssuer(), PolicyRevision: decision.TeamPolicyRevision,
		ExpectedMutationRevision: route.MutationRevision,
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
	if _, ok := requestBearerToken(request); !ok {
		writeBearerProblem(response)
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	idempotencyKey := request.Header.Get("Idempotency-Key")
	route, err := h.store.GetRouteForSessionAuthorization(request.Context(), string(routeID), idempotencyKey)
	if err != nil {
		writeControlStateProblem(response, "read route for session", err)
		return
	}
	allowedIPPrefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowedIPPrefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationRouteSessionCreate, TeamID: route.TeamID,
		RouteMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope),
		Target: route.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: route.Ephemeral,
		RouteID: route.ID, RouteVersion: route.AuthorizationRouteVersion,
		RouteMutationRevision: route.MutationRevision,
	})
	if !ok {
		return
	}
	if decision.CertificatePlan == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return
	}
	plan := *decision.CertificatePlan
	if plan.ChallengeMethod == string(controlv1.Dns01) && !h.config.DNSAutomation {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "certificate plan requires DNS-01 automation, which is not configured")
		return
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationRouteSessionCreate, TeamID: decision.TeamID, MembershipID: decision.ActingMembershipID,
		DomainID: decision.DomainID, CanonicalHostname: decision.CanonicalHostname, RouteScope: decision.RouteScope,
		RouteID: route.ID, RouteVersion: route.AuthorizationRouteVersion, PolicyRevision: decision.TeamPolicyRevision,
		Target: route.Target, Ephemeral: route.Ephemeral, CertificatePlan: &plan, AllowedIPPrefixes: allowedIPPrefixes,
	})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	setup, err := h.store.CreateRouteSession(request.Context(), controlstate.RouteSessionRequest{
		RouteID: route.ID, TeamID: decision.TeamID, MembershipID: decision.ActingMembershipID,
		ActingIdentityID: decision.IdentityID, RequireLocalAuthority: h.externalAuthorityIssuer() == "",
		RetrySecret:    decision.RetrySecret[:],
		IdempotencyKey: idempotencyKey, RequestDigest: [32]byte(digest),
		PolicyRevision: decision.TeamPolicyRevision, CertificateCacheKey: plan.CacheKey,
		CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers,
		CertificateChallenge:     plan.ChallengeMethod,
		AuthorityIssuer:          h.externalAuthorityIssuer(),
		ExpectedMutationRevision: route.MutationRevision,
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
	if err := decodeJSON(response, request, &body); err != nil || body.RouteVersion <= 0 {
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
		PublisherConnections: connectionAssignmentResponses(setup.PublisherConnections),
		PolicyDenials:        int64(setup.PolicyDenials),
	})
}

func (h *handler) MarkRouteSessionCertificateInstalled(
	response http.ResponseWriter,
	request *http.Request,
	routeSessionID controlv1.RouteSessionID,
) {
	var body controlv1.CertificateInstalledRequest
	if err := decodeJSON(response, request, &body); err != nil || body.RouteVersion <= 0 {
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
	if err := decodeJSON(response, request, &body); err != nil || body.RouteVersion <= 0 {
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
		request.Context(), string(routeSessionID), credentials.RouteSessionToken(token), time.Now(),
	); err != nil {
		writeControlStateProblem(response, "close route session", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
