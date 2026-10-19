package controlapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) GetVisitorIngressTransportTrust(w http.ResponseWriter, r *http.Request, id controlv1.PrivateConnectorSessionID) {
	principal, ok := h.authorizeRouteReads(w, r)
	if !ok {
		return
	}
	store, ok := h.store.(interface {
		GetVisitorIngressTransportTrust(context.Context, string, string, time.Time) (controlstate.IngressTransportTrust, error)
	})
	if !ok {
		writeProblem(w, 503, controlv1.Unavailable, "ingress transport trust is unavailable")
		return
	}
	trust, err := store.GetVisitorIngressTransportTrust(r.Context(), principal.identityID, id, time.Now())
	if errors.Is(err, controlstate.ErrIngressLeaseStale) || errors.Is(err, controlstate.ErrIngressTransportCertificate) {
		writeProblem(w, 409, controlv1.Conflict, "assigned ingress is unavailable; obtain fresh ingress assignments")
		return
	}
	if err != nil {
		privateVisitorError(w, "read ingress transport trust", err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, 200, controlv1.IngressTransportTrust{IngressId: trust.IngressID, IngressRunId: trust.IngressRunID, IngressLeaseRevision: int64(trust.IngressLeaseRevision),
		TlsServerName: trust.TLSServerName, CertificatePem: trust.CertificatePEM, IssuerPem: trust.IssuerPEM, IssuerRevision: trust.IssuerRevision,
		PublicKeySha256: trust.PublicKeySHA256, LeaseUri: trust.LeaseURI, NotBefore: trust.NotBefore, NotAfter: trust.NotAfter, ValidUntil: trust.ValidUntil})
}
