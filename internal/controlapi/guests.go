package controlapi

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (h *handler) CreateGuestDemo(response http.ResponseWriter, request *http.Request) {
	if !h.config.GuestDemoEnabled {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "guest demos are disabled")
		return
	}
	if h.guests == nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "guest demos are unavailable")
		return
	}
	address, err := guestRequestAddress(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid client address")
		return
	}
	if err := h.guests.GuestIssuanceAllowed(request.Context(), address, time.Now()); err != nil {
		if errors.Is(err, controlstate.ErrGuestIssuance) {
			response.Header().Set("Retry-After", "3600")
			writeProblem(response, http.StatusTooManyRequests, controlv1.GuestIssuanceLimited, "guest demo creation is limited on this network; run tnl login to continue")
		} else {
			writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not check guest demo access")
		}
		return
	}
	for range 5 {
		guest, err := controlstate.NewGuestTrialCredential(address)
		if err != nil {
			break
		}
		issuedAt := time.Now()
		domainID, err := h.guests.CreateGuestTrial(request.Context(), guest, h.config.ManagedDeploymentDomain, issuedAt)
		if err != nil {
			if errors.Is(err, controlstate.ErrGuestIssuance) {
				response.Header().Set("Retry-After", "3600")
				writeProblem(response, http.StatusTooManyRequests, controlv1.GuestIssuanceLimited, "guest demo creation is limited on this network; run tnl login to continue")
				return
			}
			if errors.Is(err, controlstate.ErrGuestNamespace) {
				continue
			}
			writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not save guest demo")
			return
		}
		writeJSON(response, http.StatusCreated, controlv1.GuestDemoSession{
			AccessToken: string(guest.Token), GuestId: guest.ID, TeamId: guest.TeamID,
			MembershipId: guest.MembershipID, DomainId: domainID,
			Namespace: guest.NamespaceLabel + "." + h.config.ManagedDeploymentDomain,
			ExpiresAt: issuedAt.Add(controlstate.GuestLifetime),
		})
		return
	}
	writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not choose a guest namespace")
}

func (h *handler) AllocateGuestDemoNumber(response http.ResponseWriter, request *http.Request) {
	if !h.config.GuestDemoEnabled || h.guests == nil {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "guest demos are disabled")
		return
	}
	access, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return
	}
	guest, err := h.guests.GuestTrialByAccessToken(request.Context(), credentials.AccessToken(access))
	if errors.Is(err, controlstate.ErrGuestUnknown) {
		writeBearerProblem(response)
		return
	}
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not check guest trial")
		return
	}
	if !guest.ExpiresAt.After(time.Now()) {
		writeProblem(response, http.StatusForbidden, controlv1.GuestTrialExhausted, "guest demo trial ended; run tnl login to continue")
		return
	}
	address, err := guestRequestAddress(request)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid client address")
		return
	}
	prefix := netip.PrefixFrom(address, address.BitLen()).String()
	matched, err := h.guests.GuestSourceMatches(guest, prefix)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not check guest IP")
		return
	}
	if !matched {
		writeProblem(response, http.StatusForbidden, controlv1.GuestIpChanged, "your IP changed since this guest trial started; run tnl login to continue")
		return
	}
	number, err := h.guests.AllocateGuestDemoNumber(request.Context(), guest.ID, time.Now())
	if errors.Is(err, controlstate.ErrGuestTrialSpent) {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "guest trial is spent; run tnl login to keep publishing")
		return
	}
	if errors.Is(err, controlstate.ErrPublishRunOpen) {
		writeProblem(response, http.StatusConflict, controlv1.Conflict, "stop your other guest demo before starting a new one")
		return
	}
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not start guest demo")
		return
	}
	writeJSON(response, http.StatusOK, controlv1.GuestDemoNumber{Number: number})
}

func guestRequestAddress(request *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read client address: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, errors.New("invalid client address")
	}
	return address.Unmap(), nil
}
