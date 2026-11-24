package public

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/control/api/serviceaccess"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (h *handler) CreateGuestDemo(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Cache-Control", "no-store")
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
		writeGuestIssuanceProblem(request.Context(), response, "check guest issuance", err)
		return
	}
	for range 5 {
		credential, err := controlstate.NewGuestTrialCredential(address)
		if err != nil {
			break
		}
		trial, err := h.guests.CreateGuestTrial(request.Context(), credential, h.config.ManagedDomain, time.Now())
		if errors.Is(err, controlstate.ErrGuestNamespace) {
			continue
		}
		if err != nil {
			writeGuestIssuanceProblem(request.Context(), response, "create guest trial", err)
			return
		}
		writeJSON(response, http.StatusCreated, controlv1.GuestDemoSession{
			AccessToken: string(credential.Token), GuestId: trial.ID, ExpiresAt: trial.ExpiresAt,
		})
		return
	}
	writeProblem(response, http.StatusServiceUnavailable, controlv1.Unavailable, "could not choose a guest namespace")
}

func writeGuestIssuanceProblem(ctx context.Context, response http.ResponseWriter, operation failure.Operation, err error) {
	if ctx.Err() != nil {
		return
	}
	if errors.Is(err, controlstate.ErrGuestIssuance) {
		response.Header().Set("Retry-After", "3600")
		writeProblem(response, http.StatusTooManyRequests, controlv1.GuestIssuanceLimited, "guest demo creation is limited on this network; run tnl auth login to continue")
		return
	}
	writeUnavailableProblem(ctx, response, operation, "could not save guest demo", failure.ServerAPIInternal, err)
}

func (h *handler) AllocateGuestDemoService(w http.ResponseWriter, r *http.Request, _ controlv1.AllocateGuestDemoServiceParams) {
	w.Header().Set("Cache-Control", "no-store")
	if !h.config.GuestDemoEnabled {
		writeProblem(w, http.StatusNotFound, controlv1.NotFound, "guest demos are disabled")
		return
	}
	if h.guests == nil {
		writeProblem(w, http.StatusServiceUnavailable, controlv1.Unavailable, "guest demos are unavailable")
		return
	}
	var body controlv1.AllocateGuestDemoServiceRequest
	key := r.Header.Get("Idempotency-Key")
	if decodeJSON(w, r, &body) != nil || !validGuestTarget(body.Target) ||
		key == "" || len(key) > 128 || strings.TrimSpace(key) != key {
		writeProblem(w, http.StatusBadRequest, controlv1.InvalidRequest, "send the bound HTTP loopback listener and an idempotency key")
		return
	}
	credential, ok := guestRequestCredential(w, r)
	if !ok {
		return
	}
	record, err := h.guests.AllocateGuestDemoService(r.Context(), controlstate.AllocateGuestDemoServiceRequest{
		Credential: credential, IdempotencyKey: key, Target: body.Target, DNSAutomation: h.config.DNSAutomation,
		RequirePostQuantum: body.RequirePostQuantum != nil && *body.RequirePostQuantum, Now: time.Now(),
	})
	if err != nil {
		guestProblem(r.Context(), w, "allocate guest demo service", err)
		return
	}
	writeJSON(w, http.StatusCreated, serviceaccess.Service(record))
}

func validGuestTarget(target string) bool {
	if len(target) == 0 || len(target) > 256 || strings.Contains(target, "#") {
		return false
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "http" || u.Opaque != "" || u.User != nil ||
		u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" ||
		u.Path != "" && u.Path != "/" || u.RawPath != "" {
		return false
	}
	ip, err := netip.ParseAddr(u.Hostname())
	if err != nil || ip.Zone() != "" || !ip.Unmap().IsLoopback() {
		return false
	}
	port, err := strconv.Atoi(u.Port())
	return err == nil && port > 0 && port <= 65535
}

func guestRequestAddress(request *http.Request) (netip.Addr, error) {
	host, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("read client address: %w", err)
	}
	address, err := netip.ParseAddr(host)
	if err != nil || address.Zone() != "" || address.Unmap().IsUnspecified() {
		return netip.Addr{}, errors.New("invalid client address")
	}
	return address.Unmap(), nil
}
