package controlapi

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateVisitorCertificate(response http.ResponseWriter, request *http.Request) {
	principal, ok := h.authorizeRouteReads(response, request)
	if !ok {
		return
	}
	var body controlv1.CreateVisitorCertificateRequest
	if err := decodeJSON(response, request, &body); err != nil || body.PublicUrlId == "" || len(body.Csr) == 0 || len(body.Csr) > 8<<10 {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "choose a database public URL and a valid certificate request")
		return
	}
	if h.config.VisitorIssuer == nil || h.visitorCertificates == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "database visitor certificates are unavailable")
		return
	}
	now := time.Now().UTC()
	allowed, err := h.visitorCertificates.DatabaseVisitorAllowed(request.Context(), string(body.PublicUrlId), principal.identityID, now)
	if err != nil {
		writeControlStateProblem(response, "check database visitor access", err)
		return
	}
	if !allowed {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "database public URL access is not granted")
		return
	}
	certificate, err := h.config.VisitorIssuer.Issue(body.Csr, string(body.PublicUrlId), principal.identityID,
		now.Add(visitorcert.MaxLifetime), now)
	if errors.Is(err, visitorcert.ErrInvalidCertificate) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid certificate request")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "issue database visitor certificate", err)
		return
	}
	block, _ := pem.Decode(certificate)
	if block == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "database visitor certificate is unavailable")
		return
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		writeControlStateProblem(response, "read database visitor certificate", err)
		return
	}
	writeJSON(response, http.StatusCreated, controlv1.VisitorCertificate{
		CertificatePem: string(certificate), IssuerPem: string(h.config.VisitorIssuer.CertificatePEM()), NotAfter: leaf.NotAfter,
	})
}
