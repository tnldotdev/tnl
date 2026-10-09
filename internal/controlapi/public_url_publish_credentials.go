package controlapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/certificateidentity"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) credentialManagementRoute(response http.ResponseWriter, request *http.Request, publicURLID string) (controlstate.PublicURL, authorization.Decision, bool) {
	if h.publishCredentials == nil || h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "publish credentials are unavailable")
		return controlstate.PublicURL{}, authorization.Decision{}, false
	}
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return controlstate.PublicURL{}, authorization.Decision{}, false
	}
	route, err := h.store.GetPublicURLForAuthorization(request.Context(), publicURLID)
	if err != nil {
		writeControlStateProblem(response, "read public URL for publish credential", err)
		return controlstate.PublicURL{}, authorization.Decision{}, false
	}
	if route.Ephemeral || route.Purpose != controlstate.PublicURLPurposeApp || route.LifecycleState != controlstate.PublicURLLifecycleEnabled {
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "a publish credential needs an enabled, saved app public URL")
		return controlstate.PublicURL{}, authorization.Decision{}, false
	}
	allowed := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowed[index] = prefix.String()
	}
	decision, ok := h.authorizeExistingRouteMutation(response, request, principal, authorization.Request{
		Operation: authorization.OperationPublishRunCreate, TeamID: route.TeamID,
		PublicURLMembershipID: route.MembershipID, DomainID: route.DomainID,
		CanonicalHostname: route.CanonicalHostname, PublicURLScope: authorization.PublicURLScope(route.PublicURLScope),
		Target: route.Target, AllowedIPPrefixes: allowed, Ephemeral: route.Ephemeral,
		PublicURLID: route.ID, PublishRunNumber: route.AuthorizationPublishRunNumber,
		PublicURLMutationRevision: route.MutationRevision,
	})
	if !ok {
		return controlstate.PublicURL{}, authorization.Decision{}, false
	}
	if decision.CertificatePlan == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "certificate plan is unavailable")
		return controlstate.PublicURL{}, authorization.Decision{}, false
	}
	if decision.CertificatePlan.ChallengeMethod == certificateidentity.ChallengeDNS01 && !h.config.DNSAutomation {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "certificate plan requires DNS-01 automation, which is not configured")
		return controlstate.PublicURL{}, authorization.Decision{}, false
	}
	return route, decision, true
}

func (h *handler) CreatePublicURLPublishCredential(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID) {
	route, decision, ok := h.credentialManagementRoute(response, request, string(publicURLID))
	if !ok {
		return
	}
	now := time.Now()
	credential, secret, err := h.publishCredentials.CreatePublicURLPublishCredential(request.Context(), controlstate.CreatePublicURLPublishCredentialRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, MembershipID: decision.ActingMembershipID,
		IdentityID: decision.IdentityID, Target: route.Target, PolicyRevision: decision.PolicyRevision,
		CertificatePlan: *decision.CertificatePlan, Now: now, ExpiresAt: now.Add(90 * 24 * time.Hour),
	})
	if err != nil {
		writeControlStateProblem(response, "create public URL publish credential", err)
		return
	}
	response.Header().Set("Cache-Control", "no-store")
	writeJSON(response, http.StatusCreated, controlv1.IssuedPublicURLPublishCredential{
		Id: credential.ID, PublicUrlId: credential.PublicURLID,
		CreatedAt: credential.CreatedAt, ExpiresAt: credential.ExpiresAt, Credential: secret.String(),
	})
}

func (h *handler) ListPublicURLPublishCredentials(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID) {
	if _, _, ok := h.credentialManagementRoute(response, request, string(publicURLID)); !ok {
		return
	}
	credentials, err := h.publishCredentials.ListPublicURLPublishCredentials(request.Context(), string(publicURLID))
	if err != nil {
		writeControlStateProblem(response, "list public URL publish credentials", err)
		return
	}
	items := make([]controlv1.PublicURLPublishCredential, len(credentials))
	for index, credential := range credentials {
		items[index] = credentialResponse(credential)
	}
	writeJSON(response, http.StatusOK, struct {
		Credentials []controlv1.PublicURLPublishCredential `json:"credentials"`
	}{Credentials: items})
}

func credentialResponse(credential controlstate.PublicURLPublishCredential) controlv1.PublicURLPublishCredential {
	return controlv1.PublicURLPublishCredential{
		Id: credential.ID, PublicUrlId: credential.PublicURLID,
		CreatedAt: credential.CreatedAt, ExpiresAt: credential.ExpiresAt, RevokedAt: credential.RevokedAt,
	}
}

func (h *handler) RevokePublicURLPublishCredential(response http.ResponseWriter, request *http.Request, publicURLID controlv1.PublicURLID, credentialID controlv1.ResourceID) {
	if _, _, ok := h.credentialManagementRoute(response, request, string(publicURLID)); !ok {
		return
	}
	if _, err := h.publishCredentials.RevokePublicURLPublishCredential(request.Context(), string(publicURLID), string(credentialID), time.Now()); err != nil {
		writeControlStateProblem(response, "revoke public URL publish credential", err)
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) authenticateScopedPublisher(response http.ResponseWriter, request *http.Request) (controlstate.PublicURLPublishCredential, controlstate.PublicURL, []byte, bool) {
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return controlstate.PublicURLPublishCredential{}, controlstate.PublicURL{}, nil, false
	}
	if h.publishCredentials == nil || h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "publish credentials are unavailable")
		return controlstate.PublicURLPublishCredential{}, controlstate.PublicURL{}, nil, false
	}
	credential, retrySecret, err := h.publishCredentials.AuthenticatePublicURLPublishCredential(request.Context(), credentials.PublicURLPublishCredential(token), time.Now())
	if errors.Is(err, controlstate.ErrPublicURLPublishCredential) {
		writeBearerProblem(response)
		return controlstate.PublicURLPublishCredential{}, controlstate.PublicURL{}, nil, false
	}
	if err != nil {
		writeControlStateProblem(response, "authenticate public URL publish credential", err)
		return controlstate.PublicURLPublishCredential{}, controlstate.PublicURL{}, nil, false
	}
	route, err := h.store.GetPublicURLForAuthorization(request.Context(), credential.PublicURLID)
	if err != nil {
		writeControlStateProblem(response, "read bound public URL", err)
		return controlstate.PublicURLPublishCredential{}, controlstate.PublicURL{}, nil, false
	}
	if err := h.publishCredentials.ValidatePublicURLPublishCredential(request.Context(), credential, route); err != nil {
		if errors.Is(err, controlstate.ErrPublicURLPublishCredential) {
			writeBearerProblem(response)
		} else {
			writeControlStateProblem(response, "validate bound public URL", err)
		}
		return controlstate.PublicURLPublishCredential{}, controlstate.PublicURL{}, nil, false
	}
	return credential, route, retrySecret, true
}

func (h *handler) GetPublicURLForPublishCredential(response http.ResponseWriter, request *http.Request) {
	_, route, _, ok := h.authenticateScopedPublisher(response, request)
	if ok {
		writeJSON(response, http.StatusOK, publicURLResponse(route))
	}
}
