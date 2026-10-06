package controlapi

import (
	"errors"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/readiness"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) ListPublicURLs(response http.ResponseWriter, request *http.Request, _ controlv1.ListPublicURLsParams) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	teamID := request.URL.Query().Get("team_id")
	if _, authorized := principal.teamIDs[teamID]; !authorized {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "operation is not authorized")
		return
	}
	query := request.URL.Query()
	var page controlstate.PublicURLPage
	var err error
	if hostnames, filtered := query["canonical_hostname"]; filtered {
		hostname := query.Get("canonical_hostname")
		canonical, nameErr := naming.CanonicalizeHostname(hostname)
		if len(hostnames) != 1 || query.Has("cursor") || nameErr != nil || canonical != hostname {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "provide one canonical hostname without a cursor")
			return
		}
		var route controlstate.PublicURL
		route, err = h.store.GetAuthorizedPublicURLByHostname(request.Context(), teamID, hostname)
		if errors.Is(err, controlstate.ErrPublicURLNotFound) {
			err = nil
		} else if err == nil {
			page.PublicURLs = []controlstate.PublicURL{route}
		}
	} else {
		page, err = h.store.ListAuthorizedPublicURLs(request.Context(), teamID, query.Get("cursor"))
	}
	if err != nil {
		writeControlStateProblem(response, "list public URLs", err)
		return
	}
	body := controlv1.PublicURLPage{PublicUrls: make([]controlv1.PublicURL, len(page.PublicURLs))}
	for index, route := range page.PublicURLs {
		body.PublicUrls[index] = publicURLResponse(route)
	}
	if page.NextCursor != "" {
		body.NextCursor = &page.NextCursor
	}
	writeJSON(response, http.StatusOK, body)
}

func (h *handler) CreatePublicURL(response http.ResponseWriter, request *http.Request, _ controlv1.CreatePublicURLParams) {
	var body controlv1.CreatePublicURLRequest
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil {
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
	if err := authorization.ValidateTarget(body.Target); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid target")
		return
	}
	membershipID := ""
	if body.MembershipId != nil {
		membershipID = *body.MembershipId
	}
	ephemeral := body.Ephemeral != nil && *body.Ephemeral
	decision, ok := h.authorizeMutation(response, request, authorization.Request{
		Operation: authorization.OperationPublicURLCreate, TeamID: body.TeamId,
		PublicURLMembershipID: membershipID, DomainID: body.DomainId,
		CanonicalHostname: body.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(body.PublicUrlScope),
		Target: body.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: ephemeral,
	})
	if !ok {
		return
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationPublicURLCreate, TeamID: decision.TeamID, MembershipID: decision.PublicURLMembershipID,
		DomainID: decision.DomainID, CanonicalHostname: decision.CanonicalHostname, PublicURLScope: decision.PublicURLScope,
		Target: body.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: ephemeral,
	})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	dnsState := controlstate.PublicURLDNSUnmanaged
	dnsAuthorityReference := ""
	if h.config.DNSAutomation {
		dnsState = controlstate.PublicURLDNSPending
		dnsAuthorityReference = decision.DNSAuthorityReference
	}
	route, err := h.store.CreatePublicURL(request.Context(), controlstate.CreatePublicURLRequest{
		GuestID: decision.GuestID,
		TeamID:  decision.TeamID, DomainID: decision.DomainID, MembershipID: decision.PublicURLMembershipID,
		ActingIdentityID: decision.IdentityID, IdempotencyKey: request.Header.Get("Idempotency-Key"),
		RequestDigest: [32]byte(digest), CanonicalHostname: decision.CanonicalHostname, Target: body.Target,
		PublicURLScope: controlstate.PublicURLScope(decision.PublicURLScope), AllowedIPPrefixes: allowedIPPrefixes,
		DNSState: dnsState, DNSAuthorityReference: dnsAuthorityReference,
		PolicyRevision: decision.PolicyRevision,
		Ephemeral:      ephemeral,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create public URL", err)
		return
	}
	writeJSON(response, http.StatusCreated, publicURLResponse(route))
}

func (h *handler) UpdatePublicURL(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID) {
	if _, ok := requestBearerToken(request); !ok {
		writeBearerProblem(response)
		return
	}
	var body struct {
		Target            *string   `json:"target"`
		AllowedIPPrefixes *[]string `json:"allowed_ip_prefixes"`
	}
	if err := decodeJSONLimited(response, request, &body, 1<<20); err != nil || body.Target == nil || body.AllowedIPPrefixes == nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if err := authorization.ValidateTarget(*body.Target); err != nil {
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
	route, err := h.store.GetPublicURLForAuthorization(request.Context(), string(publicURLID))
	if err != nil {
		writeControlStateProblem(response, "read public URL for update", err)
		return
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationPublicURLUpdate, TeamID: route.TeamID,
		PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
		Target: *body.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: route.Ephemeral, PublicURLID: route.ID,
		PublicURLMutationRevision: route.MutationRevision,
	})
	if !ok {
		return
	}
	updated, err := h.store.UpdateAuthorizedPublicURL(request.Context(), controlstate.AuthorizedPublicURLUpdateRequest{
		PublicURLID: route.ID, TeamID: decision.TeamID, ActingIdentityID: decision.IdentityID,
		Target: *body.Target, AllowedIPPrefixes: allowedIPPrefixes,
		PolicyRevision:           decision.PolicyRevision,
		ExpectedMutationRevision: route.MutationRevision,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "update public URL", err)
		return
	}
	writeJSON(response, http.StatusOK, publicURLResponse(updated))
}

func (h *handler) GetPublicURL(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	route, err := h.store.GetPublicURLForAuthorization(request.Context(), string(publicURLID))
	if err != nil {
		writeControlStateProblem(response, "get public URL", err)
		return
	}
	if _, authorized := principal.teamIDs[route.TeamID]; !authorized {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "resource not found")
		return
	}
	writeJSON(response, http.StatusOK, publicURLResponse(route))
}

func (h *handler) DeletePublicURL(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID) {
	if _, ok := requestBearerToken(request); !ok {
		writeBearerProblem(response)
		return
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	route, err := h.store.GetPublicURLForAuthorization(request.Context(), string(publicURLID))
	if err != nil {
		writeControlStateProblem(response, "read public URL for deletion", err)
		return
	}
	allowedIPPrefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowedIPPrefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationPublicURLDelete, TeamID: route.TeamID,
		PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
		Target: route.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: route.Ephemeral, PublicURLID: route.ID,
		PublicURLMutationRevision: route.MutationRevision,
	})
	if !ok {
		return
	}
	if err := h.store.DeleteAuthorizedPublicURL(request.Context(), controlstate.AuthorizedPublicURLDeleteRequest{
		PublicURLID: route.ID, TeamID: decision.TeamID, ActingIdentityID: decision.IdentityID,
		GuestID: decision.GuestID, PolicyRevision: decision.PolicyRevision,
		ExpectedMutationRevision: route.MutationRevision,
	}, time.Now()); err != nil {
		writeControlStateProblem(response, "delete public URL", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) CreatePublishRun(
	response http.ResponseWriter,
	request *http.Request,
	publicURLID controlv1.PublicURLID,
	_ controlv1.CreatePublishRunParams,
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
	route, err := h.store.GetPublicURLForPublishRunAuthorization(request.Context(), string(publicURLID), idempotencyKey)
	if err != nil {
		writeControlStateProblem(response, "read public URL for publish run", err)
		return
	}
	allowedIPPrefixes := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowedIPPrefixes[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationPublishRunCreate, TeamID: route.TeamID,
		PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
		Target: route.Target, AllowedIPPrefixes: allowedIPPrefixes, Ephemeral: route.Ephemeral,
		PublicURLID: route.ID, PublishRunNumber: route.AuthorizationPublishRunNumber,
		PublicURLMutationRevision: route.MutationRevision,
	})
	if !ok {
		return
	}
	if decision.CertificatePlan == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "authorization is unavailable")
		return
	}
	plan := *decision.CertificatePlan
	if plan.ChallengeMethod == certificateidentity.ChallengeDNS01 && !h.config.DNSAutomation {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "certificate plan requires DNS-01 automation, which is not configured")
		return
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationPublishRunCreate, TeamID: decision.TeamID, MembershipID: decision.ActingMembershipID,
		DomainID: decision.DomainID, CanonicalHostname: decision.CanonicalHostname, PublicURLScope: decision.PublicURLScope,
		PublicURLID: route.ID, PublishRunNumber: route.AuthorizationPublishRunNumber, PolicyRevision: decision.PolicyRevision,
		Target: route.Target, Ephemeral: route.Ephemeral, CertificatePlan: &plan, AllowedIPPrefixes: allowedIPPrefixes,
	})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	setup, err := h.store.CreatePublishRun(request.Context(), controlstate.PublishRunRequest{
		PublicURLID: route.ID, TeamID: decision.TeamID, MembershipID: decision.ActingMembershipID,
		ActingIdentityID: decision.IdentityID, GuestID: decision.GuestID,
		RetrySecret:    decision.RetrySecret[:],
		IdempotencyKey: idempotencyKey, RequestDigest: [32]byte(digest),
		PolicyRevision: decision.PolicyRevision, CertificateCacheKey: plan.CacheKey,
		CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers,
		CertificateChallenge:     plan.ChallengeMethod,
		ExpectedMutationRevision: route.MutationRevision,
	}, time.Now(), publisherLeaseDuration, publisherConnectionCredentialDuration)
	if err != nil {
		writeControlStateProblem(response, "create publish run", err)
		return
	}
	route, err = h.store.GetPublicURLForAuthorization(request.Context(), route.ID)
	if err != nil {
		writeControlStateProblem(response, "read created publish run", err)
		return
	}
	writeJSON(response, http.StatusCreated, publishRunSetupResponse(route, setup, controlv1.CertificatePlan{
		CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers,
		ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod),
	}))
}

func (h *handler) HeartbeatPublishRun(response http.ResponseWriter, request *http.Request, publishRunID controlv1.PublishRunID) {
	var body controlv1.PublishRunVersionRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	authentication, ok := h.authenticatePublishRunRequest(response, request, string(publishRunID), uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	setup, err := h.store.HeartbeatPublishRun(
		request.Context(), authentication, time.Now(), publisherLeaseDuration, publisherConnectionCredentialDuration,
	)
	if err != nil {
		writeControlStateProblem(response, "heartbeat publish run", err)
		return
	}
	writeJSON(response, http.StatusOK, controlv1.PublishRunHeartbeat{
		PublishRun:           publishRunResponse(setup),
		PublisherConnections: connectionAssignmentResponses(setup.PublisherConnections),
		PolicyDenials:        int64(setup.PolicyDenials),
	})
}

func (h *handler) MarkPublishRunCertificateInstalled(
	response http.ResponseWriter,
	request *http.Request,
	publishRunID controlv1.PublishRunID,
) {
	var body controlv1.CertificateInstalledRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	now := time.Now()
	if body.IssuanceId == "" || len(body.IssuanceId) > 256 || strings.TrimSpace(body.IssuanceId) != body.IssuanceId || !body.NotAfter.After(now) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid certificate acknowledgement")
		return
	}
	authentication, ok := h.authenticatePublishRunRequest(response, request, string(publishRunID), uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	lifecycle, err := h.store.MarkPublicURLCertificateInstalled(
		request.Context(), authentication, body.IssuanceId, body.NotAfter, now,
	)
	if err != nil {
		writeControlStateProblem(response, "mark public URL certificate installed", err)
		return
	}
	writeJSON(response, http.StatusOK, publishRunLifecycleResponse(lifecycle))
}

func (h *handler) MarkPublishRunReady(response http.ResponseWriter, request *http.Request, publishRunID controlv1.PublishRunID) {
	var body controlv1.PublishRunVersionRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	authentication, ok := h.authenticatePublishRunRequest(response, request, string(publishRunID), uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	started := time.Now()
	lifecycle, err := h.store.MarkPublishRunReady(request.Context(), authentication, started)
	if h.config.Metrics != nil {
		outcome := readiness.Ready
		age := time.Since(lifecycle.CreatedAt)
		var notReady *controlstate.PublishRunNotReadyError
		if errors.As(err, &notReady) {
			outcome = notReady.Reason()
			age = time.Since(notReady.CreatedAt)
		} else if err != nil {
			outcome = readiness.Error
		}
		h.config.Metrics.ObservePublishRunReadiness(outcome, time.Since(started), age)
	}
	if err != nil {
		var notReady *controlstate.PublishRunNotReadyError
		if errors.As(err, &notReady) {
			log.Printf("publish run readiness blocked publish_run_id=%s publish_run_number=%d reason=%s certificate_installed=%t ready_publisher_connections=%d age=%s",
				authentication.PublishRunID, authentication.PublishRunNumber, notReady.Reason(), notReady.CertificateInstalled,
				notReady.ReadyPublisherConnectionCount, time.Since(notReady.CreatedAt).Round(time.Second))
		}
		writeControlStateProblem(response, "mark publish run ready", err)
		return
	}
	if age := time.Since(lifecycle.CreatedAt); age >= 30*time.Second {
		log.Printf("publish run ready publish_run_id=%s publish_run_number=%d age=%s ready_publisher_connections=%d",
			authentication.PublishRunID, authentication.PublishRunNumber, age.Round(time.Second), lifecycle.ReadyPublisherConnectionCount)
	}
	writeJSON(response, http.StatusOK, publishRunLifecycleResponse(lifecycle))
}

func (h *handler) ClosePublishRun(response http.ResponseWriter, request *http.Request, publishRunID controlv1.PublishRunID) {
	token, ok := requestBearerToken(request)
	if !ok || h.store == nil {
		writeBearerProblem(response)
		return
	}
	if err := h.store.ClosePublishRun(
		request.Context(), string(publishRunID), credentials.PublishRunToken(token), time.Now(),
	); err != nil {
		writeControlStateProblem(response, "close publish run", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}
