package controlapi

import (
	"net/http"
	"net/netip"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/applicationlimits"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) AllocateEphemeralPublicURL(response http.ResponseWriter, request *http.Request) {
	if h.store == nil || h.publisherIdentities == nil || !h.config.DNSAutomation {
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "ad-hoc allocation requires automated DNS")
		return
	}
	var body controlv1.AllocateEphemeralPublicURLRequest
	if err := decodeJSON(response, request, &body); err != nil || !opaqueid.Valid(body.InvocationId, opaqueid.InvocationPrefix) ||
		body.AllowAllIps != nil && *body.AllowAllIps && body.AllowIp != nil || !validAllocationLimits(body.Limits) {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid ad-hoc allocation request")
		return
	}
	if _, err := localproxy.ParseCanonicalTarget(body.Target); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "target must be an HTTP or HTTPS address with a host and port")
		return
	}
	h.allocatePublisherNamespace(response, request, body)
}

func validAllocationLimits(limits *controlv1.PublisherApplicationLimits) bool {
	if limits == nil {
		return true
	}
	requests, concurrency := 0, 0
	if limits.Requests != nil {
		requests = *limits.Requests
		if requests <= 0 {
			return false
		}
	}
	if limits.Concurrency != nil {
		concurrency = *limits.Concurrency
		if concurrency <= 0 {
			return false
		}
	}
	rateRequests := 0
	period := time.Duration(0)
	if limits.Rate != nil {
		var err error
		period, err = time.ParseDuration(limits.Rate.Per)
		if err != nil || period <= 0 || limits.Rate.Requests <= 0 {
			return false
		}
		rateRequests = limits.Rate.Requests
		if limits.Rate.Burst != nil && *limits.Rate.Burst <= 0 {
			return false
		}
	}
	return applicationlimits.Valid(requests, rateRequests, concurrency, period)
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
	address, err := guestRequestAddress(request)
	if err != nil {
		return nil, err
	}
	current := netip.PrefixFrom(address, address.BitLen()).String()
	if !slices.Contains(canonical, current) {
		canonical = append(canonical, current)
	}
	slices.Sort(canonical)
	return canonical, nil
}
