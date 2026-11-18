package public

import (
	"context"
	"net/http"
	"strings"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type managedCertificateStore interface {
	CreateServiceCertificateIssuance(context.Context, string, string, string, string, string, int64, []byte, time.Time) (controlstate.CertificateIssuance, error)
	GetServiceCertificateIssuance(context.Context, string, string, string, string, time.Time) (controlstate.CertificateIssuance, error)
	MarkServiceCertificateInstalled(context.Context, string, string, string, string, int64, time.Time, time.Time) error
	MarkSuppliedServiceCertificateInstalled(context.Context, string, string, string, int64, string, string, time.Time) (controlv1.SuppliedServiceCertificateInstallation, error)
}

func writeManagedCertificateProblem(ctx context.Context, w http.ResponseWriter, operation string, err error) {
	if failure.Only(err, controlstate.ErrVisitorPermission) {
		writeProblem(w, http.StatusForbidden, controlv1.Forbidden, "visitor permission denied")
		return
	}
	if failure.Only(err, controlstate.ErrServiceAccess) || failure.Only(err, controlstate.ErrServiceConflict) {
		serviceVisitorError(ctx, w, operation, err)
		return
	}
	if controlstate.IsUnavailable(err) {
		writeUnavailableProblem(ctx, w, failure.Operation(operation), "certificate authorization is unavailable", failure.ServerUnavailable, err)
		return
	}
	writeControlStateProblem(ctx, w, operation, err)
}

func managedCertificatePlan(plan controlstate.CertificatePlan) controlv1.CertificatePlan {
	return controlv1.CertificatePlan{CacheKey: plan.CacheKey, Scope: plan.Scope, Identifiers: plan.Identifiers, ChallengeMethod: controlv1.CertificateChallengeMethod(plan.ChallengeMethod)}
}

func serviceCertificateResponse(value controlstate.CertificateIssuance) controlv1.ServiceCertificateIssuance {
	result := controlv1.ServiceCertificateIssuance{Id: value.ID, ServiceId: value.ServiceID, ServiceRunId: value.ServiceRunID, RunNumber: int64(value.ServiceRunNumber), PublisherIdentityId: value.PublisherIdentityID, CertificatePlan: managedCertificatePlan(value.CertificatePlan), State: controlv1.CertificateIssuanceState(value.State), RetryAt: value.RetryAt}
	if value.State == controlstate.ACMEOrderWaitingForInstall || value.State == controlstate.ACMEOrderInstalled {
		result.NotBefore, result.NotAfter = value.NotBefore, value.NotAfter
		if value.CertificatePEM != "" {
			result.CertificatePem = &value.CertificatePEM
		}
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
	store, ok := h.dependencies.ServiceCertificates, h.dependencies.ServiceCertificates != nil
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
		writeManagedCertificateProblem(r.Context(), w, "issue managed certificate", err)
		return
	}
	if value.NewOrder {
		plan := "exact"
		for _, identifier := range value.CertificatePlan.Identifiers {
			if strings.HasPrefix(identifier, "*.") {
				plan = "wildcard"
				break
			}
		}
		h.config.Metrics.ObserveCertificateOrder("service", string(value.DomainKind), plan)
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
		writeManagedCertificateProblem(r.Context(), w, "read managed certificate", err)
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
		writeManagedCertificateProblem(r.Context(), w, "install managed certificate", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *handler) MarkSuppliedServiceCertificateInstalled(w http.ResponseWriter, r *http.Request, service controlv1.ServiceID, run controlv1.ServiceRunID) {
	store, token, ok := h.serviceCertificates(w, r)
	if !ok {
		return
	}
	var body controlv1.SuppliedServiceCertificateInstalledRequest
	if decodeJSONLimited(w, r, &body, 160<<10) != nil || body.RunNumber < 1 {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid supplied certificate acknowledgement")
		return
	}
	result, err := store.MarkSuppliedServiceCertificateInstalled(r.Context(), service, run, token, body.RunNumber, body.CertificatePem, body.PreviousCertificateSha256, time.Now())
	if err != nil {
		writeManagedCertificateProblem(r.Context(), w, "install supplied certificate", err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}
