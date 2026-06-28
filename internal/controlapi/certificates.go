package controlapi

import (
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateCertificateIssuance(
	response http.ResponseWriter,
	request *http.Request,
	routeSessionID controlv1.RouteSessionID,
	_ controlv1.CreateCertificateIssuanceParams,
) {
	if !h.config.CertificateIssuance {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "certificate issuance is unavailable")
		return
	}
	var body controlv1.CreateCertificateIssuanceRequest
	if err := decodeJSON(response, request, &body); err != nil || body.RouteVersion <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	authentication, ok := h.authenticateRouteSessionRequest(response, request, string(routeSessionID), uint64(body.RouteVersion))
	if !ok {
		return
	}
	digest := certificateIssuanceRequestDigest(uint64(body.RouteVersion), body.Csr)
	issuance, err := h.store.CreateCertificateIssuance(request.Context(), controlstate.CreateCertificateIssuanceRequest{
		Authentication: authentication, DirectoryURL: h.config.ACMEDirectoryURL,
		IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestDigest: digest, CSRDER: body.Csr,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create certificate issuance", err)
		return
	}
	writeJSON(response, http.StatusCreated, certificateIssuanceResponse(issuance))
}

func (h *handler) GetCertificateIssuance(response http.ResponseWriter, request *http.Request, issuanceID controlv1.IssuanceID) {
	token, ok := requestBearerToken(request)
	if !ok || h.store == nil {
		writeBearerProblem(response)
		return
	}
	issuance, err := h.store.GetCertificateIssuance(
		request.Context(), string(issuanceID), credentials.SessionToken(token), time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "get certificate issuance", err)
		return
	}
	writeJSON(response, http.StatusOK, certificateIssuanceResponse(issuance))
}

func (h *handler) MarkCertificateChallengeReady(response http.ResponseWriter, request *http.Request, issuanceID controlv1.IssuanceID) {
	token, ok := requestBearerToken(request)
	if !ok || h.store == nil {
		writeBearerProblem(response)
		return
	}
	issuance, err := h.store.MarkCertificateChallengeReady(
		request.Context(), string(issuanceID), credentials.SessionToken(token), time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "mark certificate challenge ready", err)
		return
	}
	writeJSON(response, http.StatusOK, certificateIssuanceResponse(issuance))
}

func (h *handler) MarkCertificateChallengeRemoved(response http.ResponseWriter, request *http.Request, issuanceID controlv1.IssuanceID) {
	token, ok := requestBearerToken(request)
	if !ok || h.store == nil {
		writeBearerProblem(response)
		return
	}
	issuance, err := h.store.MarkCertificateChallengeRemoved(
		request.Context(), string(issuanceID), credentials.SessionToken(token), time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "mark certificate challenge removed", err)
		return
	}
	writeJSON(response, http.StatusOK, certificateIssuanceResponse(issuance))
}
