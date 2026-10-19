package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type managedCertificateStore interface {
	CreatePrivateCertificateIssuance(context.Context, string, string, string, string, string, int64, []byte, time.Time) (controlstate.CertificateIssuance, error)
	GetPrivateCertificateIssuance(context.Context, string, string, string, string, time.Time) (controlstate.CertificateIssuance, error)
	MarkPrivateCertificateInstalled(context.Context, string, string, string, string, int64, time.Time, time.Time) error
}

func writeManagedCertificateProblem(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrPrivateServiceAccess) || errors.Is(err, controlstate.ErrPrivateServiceConflict) {
		privateVisitorError(w, operation, err)
		return
	}
	writeControlStateProblem(w, operation, err)
}

func managedCertificatePlan(plan controlstate.CertificatePlan) controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod)}
}

func privateCertificateResponse(value controlstate.CertificateIssuance) controlv1.PrivateCertificateIssuance {
	result := controlv1.PrivateCertificateIssuance{Id: value.ID, PrivateServiceId: value.PrivateServiceID, PrivateRunId: value.PrivateRunID, RunNumber: int64(value.PrivateRunNumber), PublisherIdentityId: value.PublisherIdentityID, CertificatePlan: managedCertificatePlan(value.CertificatePlan), State: controlv1.CertificateIssuanceState(value.State), NotBefore: value.NotBefore, NotAfter: value.NotAfter, RetryAt: value.RetryAt}
	if value.CertificatePEM != "" {
		result.CertificatePem = &value.CertificatePEM
	}
	return result
}

func (h *handler) managedCertificates(w http.ResponseWriter, r *http.Request) (managedCertificateStore, string, bool) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return nil, "", false
	}
	store, ok := h.store.(managedCertificateStore)
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "managed certificate issuance is unavailable")
	}
	return store, token, ok
}

func (h *handler) CreatePrivateCertificateIssuance(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID, _ controlv1.CreatePrivateCertificateIssuanceParams) {
	store, token, ok := h.managedCertificates(w, r)
	if !ok {
		return
	}
	if !h.config.CertificateIssuance || !h.config.DNSAutomation {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "managed services require DNS-01 certificate automation")
		return
	}
	var body controlv1.CreatePrivateCertificateIssuanceRequest
	if decodeJSONLimited(w, r, &body, 128<<10) != nil || body.RunNumber < 1 || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid managed certificate request")
		return
	}
	value, err := store.CreatePrivateCertificateIssuance(r.Context(), service, run, token, h.config.ACMEDirectoryURL, r.Header.Get("Idempotency-Key"), body.RunNumber, body.Csr, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "issue managed certificate", err)
		return
	}
	writeJSON(w, http.StatusCreated, privateCertificateResponse(value))
}

func (h *handler) GetPrivateCertificateIssuance(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID, issuance controlv1.IssuanceID) {
	store, token, ok := h.managedCertificates(w, r)
	if !ok {
		return
	}
	value, err := store.GetPrivateCertificateIssuance(r.Context(), service, run, token, issuance, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "read managed certificate", err)
		return
	}
	writeJSON(w, http.StatusOK, privateCertificateResponse(value))
}

func (h *handler) MarkPrivateCertificateInstalled(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	store, token, ok := h.managedCertificates(w, r)
	if !ok {
		return
	}
	var body controlv1.PrivateCertificateInstalledRequest
	if decodeJSON(w, r, &body) != nil || body.RunNumber < 1 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid managed certificate acknowledgement")
		return
	}
	if err := store.MarkPrivateCertificateInstalled(r.Context(), service, run, token, body.IssuanceId, body.RunNumber, body.NotAfter, time.Now()); err != nil {
		writeManagedCertificateProblem(w, "install managed certificate", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
