package ingressapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

func (s generatedServer) GetIngressTransportCertificate(w http.ResponseWriter, r *http.Request, id ingressv1.IngressID) {
	s.handler.ingressTransportCertificate(w, r, id)
}

func (s *service) GetIngressTransportCertificate(ctx context.Context, id string, body ingressv1.GetIngressTransportCertificateJSONRequestBody) (ingressv1.IngressTransportCertificate, error) {
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		return ingressv1.IngressTransportCertificate{}, serviceapi.NewProblemError(400, "invalid_request", "invalid ingress process lease")
	}
	store, ok := s.store.(interface {
		GetIngressTransportCertificate(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.IngressTransportCertificate, error)
	})
	if !ok {
		return ingressv1.IngressTransportCertificate{}, serviceapi.NewProblemError(503, "unavailable", "ingress transport certificate state is unavailable")
	}
	material, err := store.GetIngressTransportCertificate(ctx, identity, s.now())
	if errors.Is(err, controlstate.ErrIngressTransportCertificate) {
		return ingressv1.IngressTransportCertificate{}, serviceapi.NewProblemError(503, "unavailable", "ingress transport certificate is unavailable")
	}
	if err != nil {
		return ingressv1.IngressTransportCertificate{}, s.storeError(ctx, err)
	}
	t := material.IngressTransportTrust
	return ingressv1.IngressTransportCertificate{PrivateKeyPem: material.PrivateKeyPEM, Trust: controlv1.IngressTransportTrust{IngressId: t.IngressID, IngressRunId: t.IngressRunID,
		IngressLeaseRevision: int64(t.IngressLeaseRevision), TlsServerName: t.TLSServerName, CertificatePem: t.CertificatePEM, IssuerPem: t.IssuerPEM, IssuerRevision: t.IssuerRevision,
		PublicKeySha256: t.PublicKeySHA256, LeaseUri: t.LeaseURI, NotBefore: t.NotBefore, NotAfter: t.NotAfter, ValidUntil: t.ValidUntil}}, nil
}

func (h *handler) ingressTransportCertificate(w http.ResponseWriter, r *http.Request, id string) {
	var body ingressv1.GetIngressTransportCertificateJSONBody
	if !serviceapi.DecodeJSON(w, r, &body) {
		return
	}
	identity, ok := ingressLeaseIdentity(id, body.IngressRunId, body.IngressLeaseRevision)
	if !ok {
		serviceapi.WriteProblem(w, 400, "invalid_request", "invalid ingress process lease")
		return
	}
	store, ok := h.service.store.(interface {
		GetIngressTransportCertificate(context.Context, controlstate.IngressLeaseIdentity, time.Time) (controlstate.IngressTransportCertificate, error)
	})
	if !ok {
		serviceapi.WriteProblem(w, 503, "unavailable", "ingress transport certificate state is unavailable")
		return
	}
	material, err := store.GetIngressTransportCertificate(r.Context(), identity, h.service.now())
	if errors.Is(err, controlstate.ErrIngressTransportCertificate) {
		serviceapi.WriteProblem(w, 503, "unavailable", "ingress transport certificate is unavailable; check the registered connector hostname")
		return
	}
	if h.writeServiceError(w, r, err) {
		return
	}
	t := material.IngressTransportTrust
	w.Header().Set("Cache-Control", "no-store")
	serviceapi.WriteJSON(w, 200, ingressv1.IngressTransportCertificate{PrivateKeyPem: material.PrivateKeyPEM, Trust: controlv1.IngressTransportTrust{
		IngressId: t.IngressID, IngressRunId: t.IngressRunID, IngressLeaseRevision: int64(t.IngressLeaseRevision), TlsServerName: t.TLSServerName,
		CertificatePem: t.CertificatePEM, IssuerPem: t.IssuerPEM, IssuerRevision: t.IssuerRevision, PublicKeySha256: t.PublicKeySHA256, LeaseUri: t.LeaseURI,
		NotBefore: t.NotBefore, NotAfter: t.NotAfter, ValidUntil: t.ValidUntil}})
}
