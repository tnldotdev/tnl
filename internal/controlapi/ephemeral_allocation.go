package controlapi

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) AllocateEphemeralPublicURL(response http.ResponseWriter, request *http.Request) {
	if h.store == nil || h.publishCredentials == nil || !h.config.DNSAutomation {
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "ad-hoc allocation requires automated DNS")
		return
	}
	var body controlv1.AllocateEphemeralPublicURLRequest
	if err := decodeJSON(response, request, &body); err != nil || !opaqueid.Valid(body.InvocationId, opaqueid.InvocationPrefix) ||
		body.AllowAllIps != nil && *body.AllowAllIps && body.AllowIp != nil || !validAllocationLimits(body.Limits) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid ad-hoc allocation request")
		return
	}
	target, err := localproxy.NormalizeTarget(body.Target)
	parsed, parseErr := url.Parse(target)
	if err != nil || target != body.Target || parseErr != nil ||
		parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1" {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "target must be a canonical loopback HTTP or HTTPS origin")
		return
	}
	token, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return
	}
	_, digest, _, err := credentials.ParseEphemeralCredential(credentials.EphemeralCredential(token))
	if err != nil {
		writeBearerProblem(response)
		return
	}
	now := time.Now()
	credential, err := h.publishCredentials.AuthenticateEphemeralCredential(request.Context(), credentials.EphemeralCredential(token), now)
	if errors.Is(err, controlstate.ErrEphemeralCredential) {
		writeBearerProblem(response)
		return
	}
	if err != nil {
		writeControlStateProblem(response, "authenticate ad-hoc credential", err)
		return
	}
	prefixes, err := allocationIPPolicy(request, body)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid ad-hoc visitor IP policy")
		return
	}
	bound, err := json.Marshal(struct {
		CredentialID, InvocationID, Target string
		Prefixes                           []string
		Limits                             *controlv1.PublisherApplicationLimits
	}{credential.ID, body.InvocationId, target, prefixes, body.Limits})
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid ad-hoc allocation request")
		return
	}
	result, err := h.store.CreatePublicURL(request.Context(), controlstate.CreatePublicURLRequest{
		TeamID: credential.TeamID, DomainID: credential.DomainID, ActingIdentityID: credential.IdentityID,
		IdempotencyKey: credential.ID + ":" + body.InvocationId, RequestDigest: sha256.Sum256(bound),
		Target: target, PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp,
		ManagedURLMode: h.config.ManagedURLMode, AllowedIPPrefixes: prefixes,
		DNSState: controlstate.PublicURLDNSPending, PolicyRevision: credential.PolicyRevision, Ephemeral: true,
		EphemeralCredentialID: credential.ID, EphemeralTokenDigest: digest, EphemeralNamespace: credential.Namespace,
	}, now)
	if errors.Is(err, controlstate.ErrPublicURLAccess) {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "ad-hoc credential scope is no longer authorized")
		return
	}
	if err != nil {
		writeControlStateProblem(response, "allocate ad-hoc public URL", err)
		return
	}
	writeJSON(response, http.StatusCreated, publicURLResponse(result))
}

func validAllocationLimits(limits *controlv1.PublisherApplicationLimits) bool {
	if limits == nil {
		return true
	}
	if limits.Requests != nil && *limits.Requests <= 0 || limits.Concurrency != nil && *limits.Concurrency <= 0 {
		return false
	}
	if limits.Rate != nil {
		period, err := time.ParseDuration(limits.Rate.Per)
		return err == nil && period > 0 && limits.Rate.Requests > 0
	}
	return true
}

func allocationIPPolicy(request *http.Request, body controlv1.AllocateEphemeralPublicURLRequest) ([]string, error) {
	if body.AllowAllIps != nil && *body.AllowAllIps {
		return []string{}, nil
	}
	values := []string{}
	if body.AllowIp != nil {
		values = append(values, *body.AllowIp...)
	}
	canonical, err := authorization.CanonicalizeIPPrefixes(values)
	if err != nil || len(canonical) > 32 {
		return nil, authorization.ErrInvalid
	}
	remote, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return nil, err
	}
	address, err := netip.ParseAddr(remote)
	if err != nil || address.Zone() != "" {
		return nil, authorization.ErrInvalid
	}
	address = address.Unmap()
	current := netip.PrefixFrom(address, address.BitLen()).String()
	if !slices.Contains(canonical, current) {
		canonical = append(canonical, current)
	}
	slices.Sort(canonical)
	return canonical, nil
}
