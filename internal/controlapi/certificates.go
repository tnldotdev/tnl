package controlapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateCertificateIssuance(
	response http.ResponseWriter,
	request *http.Request,
	publishRunID controlv1.PublishRunID,
	_ controlv1.CreateCertificateIssuanceParams,
) {
	if !h.config.CertificateIssuance {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "certificate issuance is unavailable")
		return
	}
	var body controlv1.CreateCertificateIssuanceRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublishRunNumber <= 0 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	authentication, ok := h.authenticatePublishRunRequest(response, request, string(publishRunID), uint64(body.PublishRunNumber))
	if !ok {
		return
	}
	digest := certificateIssuanceRequestDigest(uint64(body.PublishRunNumber), body.Csr)
	issuance, err := h.certificates.CreateCertificateIssuance(request.Context(), controlstate.CreateCertificateIssuanceRequest{
		Authentication: authentication, DirectoryURL: h.config.ACMEDirectoryURL,
		IdempotencyKey: request.Header.Get("Idempotency-Key"), RequestDigest: digest, CSRDER: body.Csr,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create certificate issuance", err)
		return
	}
	if issuance.NewOrder {
		plan := "exact"
		for _, identifier := range issuance.CertificatePlan.Identifiers {
			if strings.HasPrefix(identifier, "*.") {
				plan = "wildcard"
				break
			}
		}
		h.config.Metrics.ObserveCertificateOrder(string(issuance.DomainKind), plan)
	}
	writeJSON(response, http.StatusCreated, certificateIssuanceResponse(issuance))
}

func (h *handler) GetCertificateIssuance(response http.ResponseWriter, request *http.Request, issuanceID controlv1.IssuanceID) {
	token, ok := requestBearerToken(request)
	if !ok || h.store == nil {
		writeBearerProblem(response)
		return
	}
	issuance, err := h.certificates.GetCertificateIssuance(
		request.Context(), string(issuanceID), credentials.PublishRunToken(token), time.Now(),
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
	issuance, err := h.certificates.MarkCertificateChallengeReady(
		request.Context(), string(issuanceID), credentials.PublishRunToken(token), time.Now(),
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
	issuance, err := h.certificates.MarkCertificateChallengeRemoved(
		request.Context(), string(issuanceID), credentials.PublishRunToken(token), time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "mark certificate challenge removed", err)
		return
	}
	writeJSON(response, http.StatusOK, certificateIssuanceResponse(issuance))
}
