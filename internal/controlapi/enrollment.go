package controlapi

import (
	"errors"
	"log"
	"net"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/servicepki"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) ListServiceEnrollmentTokens(response http.ResponseWriter, request *http.Request) {
	if _, ok := h.authenticateAdminRequest(response, request); !ok {
		return
	}
	tokens, err := h.store.ListServiceEnrollmentTokens(request.Context())
	if err != nil {
		log.Printf("list service enrollment tokens: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	page := controlv1.ServiceEnrollmentTokenPage{EnrollmentTokens: make([]controlv1.ServiceEnrollmentToken, len(tokens))}
	for index, token := range tokens {
		page.EnrollmentTokens[index] = serviceEnrollmentTokenResponse(token)
	}
	writeJSON(response, http.StatusOK, page)
}

func (h *handler) CreateServiceEnrollmentToken(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	principal, ok := h.authenticateAdminRequest(response, request)
	if !ok {
		return
	}
	var body controlv1.CreateServiceEnrollmentTokenRequest
	if err := decodeJSON(request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	creation := controlstate.CreateServiceEnrollmentTokenRequest{
		Role: servicepki.Role(body.Role), ActorIdentityID: principal.IdentityID, CreatedAt: time.Now(),
	}
	switch body.Role {
	case controlv1.Ingress:
		if body.RelayServiceId != nil {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "ingress tokens cannot have relay service scope")
			return
		}
	case controlv1.Relay:
		if body.RelayServiceId == nil {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "relay service ID is required")
			return
		}
		creation.RelayServiceID = *body.RelayServiceId
		creation.TLSServerName = h.config.RelayServiceHostname(creation.RelayServiceID)
		if creation.TLSServerName == "" {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "relay service ID must be one canonical DNS label")
			return
		}
		creation.RelayAddress = net.JoinHostPort(creation.TLSServerName, "443")
	default:
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "service enrollment role is invalid")
		return
	}
	auditRequestID, err := opaqueid.New("request_")
	if err != nil {
		log.Printf("create service enrollment audit identity: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	creation.AuditRequestID = auditRequestID
	created, err := h.store.CreateServiceEnrollmentToken(request.Context(), creation)
	if errors.Is(err, controlstate.ErrServiceEnrollmentRequest) || errors.Is(err, controlstate.ErrRelayServiceConflict) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "service enrollment token scope is invalid")
		return
	}
	if err != nil {
		log.Printf("create service enrollment token: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	writeJSON(response, http.StatusCreated, controlv1.CreatedServiceEnrollmentToken{
		EnrollmentToken:        serviceEnrollmentTokenResponse(created.EnrollmentToken),
		ServiceEnrollmentToken: created.Token.String(),
	})
}

func (h *handler) RevokeServiceEnrollmentToken(
	response http.ResponseWriter,
	request *http.Request,
	serviceEnrollmentTokenID controlv1.ServiceEnrollmentTokenID,
) {
	principal, ok := h.authenticateAdminRequest(response, request)
	if !ok {
		return
	}
	auditRequestID, err := opaqueid.New("request_")
	if err != nil {
		log.Printf("create service enrollment revocation audit identity: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	_, err = h.store.RevokeServiceEnrollmentToken(
		request.Context(), string(serviceEnrollmentTokenID), principal.IdentityID, auditRequestID, time.Now(),
	)
	if errors.Is(err, controlstate.ErrServiceEnrollmentTokenNotFound) {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "service enrollment token not found")
		return
	}
	if errors.Is(err, controlstate.ErrServiceEnrollmentRequest) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	if err != nil {
		log.Printf("revoke service enrollment token: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	response.WriteHeader(http.StatusNoContent)
}

func (h *handler) EnrollService(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
	var body controlv1.ServiceEnrollmentRequest
	if err := decodeJSON(request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	processID := ""
	switch body.Role {
	case controlv1.Ingress:
		if body.IngressId == nil || body.RelayId != nil {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "exactly one ingress ID is required")
			return
		}
		processID = *body.IngressId
	case controlv1.Relay:
		if body.RelayId == nil || body.IngressId != nil {
			writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "exactly one relay ID is required")
			return
		}
		processID = *body.RelayId
	default:
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "service enrollment role is invalid")
		return
	}
	enrollment, err := h.store.EnrollService(request.Context(), controlstate.ServiceEnrollmentRequest{
		Token: credentials.ServiceEnrollmentToken(body.ServiceEnrollmentToken), Role: servicepki.Role(body.Role),
		ProcessID: processID, CSRPEM: body.CertificateSigningRequest, EnrolledAt: time.Now(),
	})
	if errors.Is(err, controlstate.ErrServiceEnrollmentCredential) {
		writeProblem(response, http.StatusUnauthorized, controlv1.Unauthenticated, "service enrollment credential is invalid")
		return
	}
	if errors.Is(err, controlstate.ErrServiceEnrollmentRequest) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "service enrollment request is invalid")
		return
	}
	if err != nil {
		log.Printf("enroll service: %v", err)
		writeProblem(response, http.StatusInternalServerError, controlv1.Internal, "internal server error")
		return
	}
	writeJSON(response, http.StatusOK, serviceEnrollmentResponse(h.config, enrollment))
}
