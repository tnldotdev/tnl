package controlapi

import (
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateDNSAuthority(
	response http.ResponseWriter,
	request *http.Request,
	params controlv1.CreateDNSAuthorityParams,
) {
	if !h.authenticateHostedService(response, request) {
		return
	}
	if !h.config.DNSAutomation {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "DNS automation is unavailable")
		return
	}
	var body controlv1.CreateDNSAuthorityRequest
	if err := decodeJSON(response, request, &body); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	digest, err := authorityRequestDigest(body)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	authority, err := h.dnsAuthorities.CreateDNSAuthority(request.Context(), controlstate.CreateDNSAuthorityRequest{
		TeamID: body.TeamId, DomainID: body.DomainId, CanonicalDomain: body.CanonicalDomain,
		IdempotencyKey: params.IdempotencyKey, RequestDigest: digest,
	}, time.Now())
	if err != nil {
		writeControlStateProblem(response, "create DNS authority", err)
		return
	}
	writeJSON(response, http.StatusCreated, dnsAuthorityResponse(authority))
}

func (h *handler) GetDNSAuthority(
	response http.ResponseWriter,
	request *http.Request,
	reference controlv1.DNSAuthorityReference,
) {
	if !h.authenticateHostedService(response, request) {
		return
	}
	authority, err := h.dnsAuthorities.GetDNSAuthority(request.Context(), string(reference))
	if err != nil {
		writeControlStateProblem(response, "get DNS authority", err)
		return
	}
	writeJSON(response, http.StatusOK, dnsAuthorityResponse(authority))
}

func (h *handler) ReleaseDNSAuthority(
	response http.ResponseWriter,
	request *http.Request,
	reference controlv1.DNSAuthorityReference,
	params controlv1.ReleaseDNSAuthorityParams,
) {
	if !h.authenticateHostedService(response, request) {
		return
	}
	authority, err := h.dnsAuthorities.ReleaseDNSAuthority(
		request.Context(), string(reference), params.IdempotencyKey, time.Now(),
	)
	if err != nil {
		writeControlStateProblem(response, "release DNS authority", err)
		return
	}
	writeJSON(response, http.StatusAccepted, dnsAuthorityResponse(authority))
}

func (h *handler) authenticateHostedService(response http.ResponseWriter, request *http.Request) bool {
	if !h.hostedSecrets.Valid() || !h.hostedSecrets.Authenticate(request.Header) {
		writeBearerProblem(response)
		return false
	}
	return true
}

func dnsAuthorityResponse(authority controlstate.DNSAuthority) controlv1.DNSAuthority {
	result := controlv1.DNSAuthority{
		Reference: authority.Reference, TeamId: authority.TeamID, DomainId: authority.DomainID,
		CanonicalDomain: authority.CanonicalDomain, State: controlv1.DNSAuthorityState(authority.State),
		RequiredRecords: make([]controlv1.DNSRecord, len(authority.RequiredRecords)),
		CreatedAt:       authority.CreatedAt, UpdatedAt: authority.UpdatedAt,
	}
	for index, record := range authority.RequiredRecords {
		result.RequiredRecords[index] = controlv1.DNSRecord{
			Name: record.Name, Type: controlv1.DNSRecordType(record.Type), Value: record.Value,
		}
	}
	if authority.LastError != "" {
		result.LastError = &authority.LastError
	}
	return result
}

func authorityRequestDigest(value any) ([32]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(encoded), nil
}
