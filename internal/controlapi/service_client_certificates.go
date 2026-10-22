package controlapi

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/visitorsubject"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) IssueServiceClientCertificate(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID) {
	w.Header().Set("Cache-Control", "no-store")
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	var body controlv1.IssueServiceClientCertificateRequest
	if decodeJSONLimited(w, r, &body, 16<<10) != nil {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid service client certificate request")
		return
	}
	store, ok := h.store.(interface {
		IssueServiceClientCertificate(context.Context, string, string, string, []byte, time.Time) (controlstate.ServiceClientCertificate, error)
	})
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "service client certificates are unavailable")
		return
	}
	result, err := store.IssueServiceClientCertificate(r.Context(), service, principal.identityID, body.DeviceId, body.Csr, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "issue service client certificate", err)
		return
	}
	writeJSON(w, http.StatusCreated, result)
}

func (h *handler) AuthorizeServiceClientCertificate(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.AuthorizeServiceClientCertificateRequest
	if decodeJSONLimited(w, r, &body, 32<<10) != nil || body.RunNumber < 1 || !validVisitorSource(body.SourceIp) {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid service client certificate decision")
		return
	}
	source, _ := netip.ParseAddr(body.SourceIp)
	store, ok := h.store.(interface {
		AuthorizeServiceClientCertificate(context.Context, string, string, string, string, int64, netip.Addr, []byte, time.Time) (controlstate.PrivateVisitorValidity, error)
	})
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "service client authorization is unavailable")
		return
	}
	decision, err := store.AuthorizeServiceClientCertificate(r.Context(), service, run, token, body.VisitorConnectionId, body.RunNumber, source, body.Certificate, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "authorize service client certificate", err)
		return
	}
	observability.AuthorizationAdmission(r.Context(), "service_client_certificate", decision.Allowed, decision.Admitted)
	writeJSON(w, http.StatusOK, controlv1.ServiceClientCertificateDecision{Allowed: decision.Allowed, Admitted: decision.Admitted, ValidUntil: decision.ValidUntil})
}

func (h *handler) AuthorizeServiceConnector(w http.ResponseWriter, r *http.Request, service controlv1.PrivateServiceID, run controlv1.PrivateRunID) {
	w.Header().Set("Cache-Control", "no-store")
	token, ok := requestBearerToken(r)
	if !ok {
		writeBearerProblem(w)
		return
	}
	var body controlv1.AuthorizeServiceConnectorRequest
	if decodeJSONLimited(w, r, &body, 4096) != nil || body.RunNumber < 1 || body.GrantRevision < 1 || !validVisitorSource(body.SourceIp) {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "invalid service connector decision")
		return
	}
	store, ok := h.store.(interface {
		AuthorizeVisitorServiceConnector(context.Context, string, string, string, int64, controlstate.SubjectConnectorVisitor, time.Time) (controlstate.PrivateVisitorValidity, error)
	})
	if !ok {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "service connector authorization is unavailable")
		return
	}
	source, _ := netip.ParseAddr(body.SourceIp)
	subject, err := visitorsubject.Parse(body.Subject)
	if err != nil {
		writeProblem(w, 400, controlv1.InvalidRequest, "invalid visitor subject")
		return
	}
	visitor := controlstate.SubjectConnectorVisitor{SessionID: body.ConnectorSessionId, Subject: subject, ConnectionID: body.VisitorConnectionId, Source: source, GrantRevision: body.GrantRevision}
	decision, err := store.AuthorizeVisitorServiceConnector(r.Context(), service, run, token, body.RunNumber, visitor, time.Now())
	if err != nil {
		writeManagedCertificateProblem(w, "authorize service connector", err)
		return
	}
	observability.AuthorizationAdmission(r.Context(), "service_connector", decision.Allowed, decision.Admitted)
	writeJSON(w, http.StatusOK, controlv1.ServiceClientCertificateDecision{Allowed: decision.Allowed, Admitted: decision.Admitted, ValidUntil: decision.ValidUntil})
}
