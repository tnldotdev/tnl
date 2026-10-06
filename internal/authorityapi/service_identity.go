package authorityapi

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (h *handler) authenticateWebService(response http.ResponseWriter, request *http.Request) bool {
	if !h.webSecret.Valid() {
		notFound(response, request)
		return false
	}
	if !h.webSecret.Authenticate(request.Header) {
		writeBearerProblem(response)
		return false
	}
	if h.store == nil {
		writeProblem(response, http.StatusServiceUnavailable, authorityv1.Unavailable, "authority state is unavailable")
		return false
	}
	return true
}

func (h *handler) resolveWebsiteIdentity(response http.ResponseWriter, request *http.Request, body authorityv1.ServiceIdentity) (controlstate.IdentityContext, bool) {
	identity := controlstate.OIDCIdentity{Issuer: h.config.OIDCIssuer, Subject: body.Subject, DisplayName: body.DisplayName}
	if body.VerifiedEmail != nil {
		identity.NormalizedEmail, identity.EmailVerified = string(*body.VerifiedEmail), true
	}
	result, err := h.store.EnsureServiceIdentity(request.Context(), h.config.ManagedDeploymentDomain, identity, time.Now())
	if err != nil {
		writeControlStateProblem(response, "resolve website identity", err)
		return result, false
	}
	return result, true
}

func (h *handler) ResolveServiceIdentity(response http.ResponseWriter, request *http.Request) {
	if !h.authenticateWebService(response, request) {
		return
	}
	var body authorityv1.ServiceIdentity
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid identity request")
		return
	}
	if identity, ok := h.resolveWebsiteIdentity(response, request, body); ok {
		writeJSON(response, http.StatusOK, identityContextResponse(identity))
	}
}

func (h *handler) PreviewServiceInvitation(response http.ResponseWriter, request *http.Request) {
	h.websiteInvitation(response, request, false)
}

func (h *handler) AcceptServiceInvitation(response http.ResponseWriter, request *http.Request) {
	h.websiteInvitation(response, request, true)
}

func (h *handler) websiteInvitation(response http.ResponseWriter, request *http.Request, accept bool) {
	if !h.authenticateWebService(response, request) {
		return
	}
	var body authorityv1.ServiceInvitationRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, authorityv1.InvalidRequest, "invalid invitation request")
		return
	}
	identity, ok := h.resolveWebsiteIdentity(response, request, body.Identity)
	if !ok {
		return
	}
	if accept {
		membership, err := h.store.AcceptInvitation(request.Context(), identity.Identity.ID, credentials.InvitationToken(body.Secret), time.Now())
		if err != nil {
			writeControlStateProblem(response, "accept website invitation", err)
			return
		}
		writeJSON(response, http.StatusOK, membershipResponse(membership))
		return
	}
	preview, err := h.store.PreviewInvitation(request.Context(), identity.Identity.ID, body.Secret, time.Now())
	if err != nil {
		writeControlStateProblem(response, "preview website invitation", err)
		return
	}
	writeJSON(response, http.StatusOK, authorityv1.InvitationPreview{TeamDisplayName: authorityv1.CanonicalLabel(preview.TeamDisplayName), InitialRole: authorityv1.TeamRole(preview.InitialRole), ExpiresAt: preview.ExpiresAt})
}
