package controlapi

import (
	"errors"
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
	if h.guests == nil || h.guestAuthority == nil || h.config.HostedSecret == "" {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "guest demos are unavailable")
		return
	}
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid client address")
		return
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" {
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
	guest, err := controlstate.NewGuestTrialCredential(address)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not create guest demo")
		return
	}
	reserved, err := h.guestAuthority.ReserveGuestNamespace(
		request.Context(), h.config.HostedSecret, guest.ID, guest.NamespaceLabel,
	)
	if err != nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not reserve guest namespace")
		return
	}
	if reserved.ManagedDomain != h.config.ManagedDeploymentDomain || reserved.NamespaceLabel != guest.NamespaceLabel {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "guest namespace reservation does not match this server")
		return
	}
	if err := h.guests.CreateGuestTrial(request.Context(), guest, reserved.DomainId, reserved.DnsAuthorityReference, time.Now()); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not save guest demo")
		return
	}
	writeJSON(response, http.StatusCreated, controlv1.GuestDemoSession{
		AccessToken: string(guest.Token), GuestId: guest.ID, TeamId: guest.TeamID,
		MembershipId: guest.MembershipID, DomainId: reserved.DomainId,
		Namespace: guest.NamespaceLabel + "." + h.config.ManagedDeploymentDomain,
		SourceIp:  guest.SourceIP.String(),
	})
}

func (h *handler) ClaimGuestDemo(response http.ResponseWriter, request *http.Request) {
	if !h.config.GuestDemoEnabled || h.guests == nil || h.guestAuthority == nil {
		writeProblem(response, http.StatusNotFound, controlv1.NotFound, "guest demos are disabled")
		return
	}
	access, ok := requestBearerToken(request)
	if !ok {
		writeBearerProblem(response)
		return
	}
	if _, err := h.guestAuthority.IdentityContextWithAccessToken(request.Context(), credentials.AccessToken(access)); err != nil {
		writeBearerProblem(response)
		return
	}
	var body controlv1.ClaimGuestDemoRequest
	if err := decodeJSONLimited(response, request, &body, 1<<16); err != nil {
		writeProblem(response, http.StatusBadRequest, controlv1.InvalidRequest, "invalid request")
		return
	}
	guest, err := h.guests.GuestTrialByAccessToken(request.Context(), credentials.AccessToken(body.GuestAccessToken))
	if err != nil {
		writeProblem(response, http.StatusForbidden, controlv1.Forbidden, "guest credential is invalid or already claimed")
		return
	}
	claimed, err := h.guestAuthority.ClaimGuestNamespace(request.Context(), h.config.HostedSecret, guest.ID, access)
	if err != nil || claimed.NamespaceLabel != guest.NamespaceLabel {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "guest namespace claim failed")
		return
	}
	if err := h.guests.ClaimGuestTrial(request.Context(), guest.ID, time.Now()); err != nil {
		writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "guest namespace claim could not be recorded")
		return
	}
	writeJSON(response, http.StatusOK, controlv1.GuestDemoClaim{
		TeamId: claimed.TeamId, MembershipId: claimed.MembershipId,
		Namespace: guest.NamespaceLabel + "." + h.config.ManagedDeploymentDomain,
	})
}
