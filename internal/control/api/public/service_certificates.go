package public

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type managedCertificateStore interface {
	CreateServiceCertificateIssuance(context.Context, string, string, string, string, string, int64, []byte, time.Time) (controlstate.CertificateIssuance, error)
	GetServiceCertificateIssuance(context.Context, string, string, string, string, time.Time) (controlstate.CertificateIssuance, error)
	MarkServiceCertificateInstalled(context.Context, string, string, string, string, int64, time.Time, time.Time) error
}

func writeManagedCertificateProblem(w http.ResponseWriter, operation string, err error) {
	if errors.Is(err, controlstate.ErrServiceAccess) || errors.Is(err, controlstate.ErrServiceConflict) {
		serviceVisitorError(w, operation, err)
		return
	}
	writeControlStateProblem(w, operation, err)
}

func managedCertificatePlan(plan controlstate.CertificatePlan) controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod)}
}

func serviceCertificateResponse(value controlstate.CertificateIssuance) controlv1.ServiceCertificateIssuance {
	result := controlv1.ServiceCertificateIssuance{Id: value.ID, ServiceId: value.ServiceID, ServiceRunId: value.ServiceRunID, RunNumber: int64(value.ServiceRunNumber), PublisherIdentityId: value.PublisherIdentityID, CertificatePlan: managedCertificatePlan(value.CertificatePlan), State: controlv1.CertificateIssuanceState(value.State), NotBefore: value.NotBefore, NotAfter: value.NotAfter, RetryAt: value.RetryAt}
	if value.CertificatePEM != "" {
		result.CertificatePem = &value.CertificatePEM
	}
	return result
}

func (h *handler) serviceCertificates(w http.ResponseWriter, r *http.Request) (managedCertificateStore, string, bool) {
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

func (h *handler) CreateServiceCertificateIssuance(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID, _ controlv1.CreateServiceCertificateIssuanceParams) {
	store, token, ok := h.serviceCertificates(w, r)
	if !ok {
		return
	}
	if !h.config.CertificateIssuance || !h.config.DNSAutomation {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "services require DNS-01 certificate automation")
		return
	}
	var body controlv1.CreateServiceCertificateIssuanceRequest
	if decodeJSONLimited(w, r, &body, 128<<10) != nil || body.RunNumber < 1 || r.Header.Get("Idempotency-Key") == "" {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid managed certificate request")
		return
	}
	value, err := store.CreateServiceCertificateIssuance(r.Context(), service, run, token, h.config.ACMEDirectoryURL, r.Header.Get("Idempotency-Key"), body.RunNumber, body.Csr, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "issue managed certificate", err)
		return
	}
	if value.NewOrder {
		h.config.Metrics.ObserveCertificateOrder("service", string(value.DomainKind), "exact")
	}
	writeJSON(w, http.StatusCreated, serviceCertificateResponse(value))
}

func (h *handler) GetServiceCertificateIssuance(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID, issuance controlv1.IssuanceID) {
	store, token, ok := h.serviceCertificates(w, r)
	if !ok {
		return
	}
	value, err := store.GetServiceCertificateIssuance(r.Context(), service, run, token, issuance, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "read managed certificate", err)
		return
	}
	writeJSON(w, http.StatusOK, serviceCertificateResponse(value))
}

func (h *handler) MarkServiceCertificateInstalled(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	store, token, ok := h.serviceCertificates(w, r)
	if !ok {
		return
	}
	var body controlv1.ServiceCertificateInstalledRequest
	if decodeJSON(w, r, &body) != nil || body.RunNumber < 1 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid managed certificate acknowledgement")
		return
	}
	if err := store.MarkServiceCertificateInstalled(r.Context(), service, run, token, body.IssuanceId, body.RunNumber, body.NotAfter, time.Now()); err != nil {
		writeManagedCertificateProblem(w, "install managed certificate", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
