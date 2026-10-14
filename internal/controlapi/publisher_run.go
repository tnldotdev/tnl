package controlapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/internal/trafficlimits"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) createPublisherIdentityRun(w http.ResponseWriter, r *http.Request, publicURLID controlv1.PublicURLID) {
	if h.publisherIdentities == nil {
		writeBearerProblem(w)
		return
	}
	token, _ := requestBearerToken(r)
	machine, err := h.publisherIdentities.AuthenticatePublisherAccess(r.Context(), token, time.Now().UTC())
	if errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeBearerProblem(w)
		return
	}
	if err != nil {
		writeControlStateProblem(w, "authenticate publisher", err)
		return
	}
	owned, err := h.publisherIdentities.PublisherMayStartRun(r.Context(), machine, string(publicURLID))
	if err != nil {
		writeControlStateProblem(w, "check publisher grant", err)
		return
	}
	if !owned {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "public URL not found in publisher grant")
		return
	}
	key := r.Header.Get("Idempotency-Key")
	route, err := h.store.GetPublicURLForPublishRunAuthorization(r.Context(), string(publicURLID), key)
	if err != nil {
		writeControlStateProblem(w, "read publisher public URL", err)
		return
	}
	if machine.CreatorID == "" || machine.Scope.TeamID != route.TeamID {
		writeBearerProblem(w)
		return
	}
	plan, err := h.publisherIdentities.PublisherRunPlan(r.Context(), machine, route, h.config.DNSAutomation)
	if errors.Is(err, controlstate.ErrPublisherIdentity) {
		writeBearerProblem(w)
		return
	}
	if err != nil {
		writeControlStateProblem(w, "plan publisher certificate", err)
		return
	}
	var body controlv1.CreatePublishRunRequest
	if err := decodeJSONLimited(w, r, &body, 1024); err != nil || body.PublisherProof == nil || *body.PublisherProof == "" {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "a signed publisher run proof is required")
		return
	}
	public, err := h.publisherIdentities.PublisherKeyForAccess(r.Context(), machine)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	retrySecret, err := publisheridentity.VerifyRun(public, *body.PublisherProof, route.ID, key)
	if err != nil {
		writeBearerProblem(w)
		return
	}
	selection := trafficlimits.Selection{}
	if selected := body.Traffic; selected != nil {
		selection = trafficlimits.Selection{Connections: selected.Connections, Rate: selected.Rate,
			RatePer: selected.RatePer, Burst: selected.Burst, UploadBytes: selected.UploadBytes, DownloadBytes: selected.DownloadBytes}
	}
	effective, err := selection.Resolve(h.config.TrafficDefaults, h.config.TrafficCeiling)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, err.Error())
		return
	}
	allowed := make([]string, len(route.AllowedIPPrefixes))
	for index, prefix := range route.AllowedIPPrefixes {
		allowed[index] = prefix.String()
	}
	digest, err := authorization.CanonicalRequestHash(authorization.OperationRequest{
		Operation: authorization.OperationPublishRunCreate, TeamID: route.TeamID,
		DomainID: route.DomainID, CanonicalHostname: route.CanonicalHostname,
		PublicURLScope: authorization.PublicURLScope(route.PublicURLScope), PublicURLID: route.ID,
		PublishRunNumber: route.AuthorizationPublishRunNumber, PolicyRevision: uint64(route.PolicyRevision),
		Target: route.Target, Ephemeral: route.Ephemeral, CertificatePlan: &plan, AllowedIPPrefixes: allowed,
	})
	if err != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid publish run scope")
		return
	}
	signed := append(digest[:], machine.ID...)
	signed = append(signed, machine.GrantID...)
	if body.Traffic != nil {
		encoded, err := json.Marshal(body.Traffic)
		if err != nil {
			writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid traffic limits")
			return
		}
		signed = append(signed, encoded...)
	}
	digest = sha256.Sum256(signed)
	setup, err := h.store.CreatePublishRun(r.Context(), controlstate.PublishRunRequest{
		PublicURLID: route.ID, TeamID: route.TeamID, ActingIdentityID: machine.CreatorID,
		PublisherIdentityID: machine.ID, PublisherGrantID: machine.GrantID,
		RetrySecret: retrySecret[:], IdempotencyKey: key, RequestDigest: [32]byte(digest),
		PolicyRevision: uint64(route.PolicyRevision), CertificateCacheKey: plan.CacheKey,
		CertificateScope: plan.Scope, CertificateIdentifiers: plan.Identifiers,
		CertificateChallenge: plan.ChallengeMethod, ExpectedMutationRevision: route.MutationRevision,
		Traffic: &effective,
	}, time.Now().UTC(), publisherLeaseDuration, publisherConnectionCredentialDuration)
	if err != nil {
		writeControlStateProblem(w, "create publisher run", err)
		return
	}
	route, err = h.store.GetPublicURLForAuthorization(r.Context(), route.ID)
	if err != nil {
		writeControlStateProblem(w, "read created publisher run", err)
		return
	}
	writeJSON(w, http.StatusCreated, publishRunSetupResponse(route, setup, controlv1.CertificatePlan{
		CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers,
		ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod),
	}))
}
