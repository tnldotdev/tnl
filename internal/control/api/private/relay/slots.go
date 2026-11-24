package relay

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strconv"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/serverhttp"
)

// the HTTP boundary turns a slot credential into an exact registration. only
// the public registration fields, never the credential, enter request context.
type slot struct {
	ServiceID       string `json:"service_id"`
	RelayID         string `json:"relay_id"`
	Hostname        string `json:"hostname"`
	RelayAddress    string `json:"relay_address"`
	InternalAddress string `json:"internal_address"`
}

type Slots struct {
	entries map[serverhttp.BearerSecrets]slot
}
type slotContext struct{}

var errEmptySlots = errors.New("at least one relay slot is required")

func validSlotAddress(address string) bool {
	host, port, err := net.SplitHostPort(address)
	n, portErr := strconv.ParseUint(port, 10, 16)
	return err == nil && host != "" && portErr == nil && n != 0 && strconv.FormatUint(n, 10) == port
}

func ParseSlots(data []byte, cluster serverhttp.BearerSecrets) (Slots, error) {
	var entries []struct {
		slot
		Credential string `json:"credential"`
	}
	invalid := func(err error) (Slots, error) {
		return Slots{}, failure.Wrap("configure relay slots", failure.ServerConfigInvalid, err)
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		return invalid(err)
	}
	if len(entries) == 0 {
		return invalid(errEmptySlots)
	}
	slots := Slots{entries: make(map[serverhttp.BearerSecrets]slot)}
	for _, e := range entries {
		host, err := naming.CanonicalizeHostname(e.Hostname)
		if err != nil {
			return invalid(err)
		}
		if !serverhttp.ValidIdentifiers(e.ServiceID, e.RelayID) || host != e.Hostname || !validSlotAddress(e.InternalAddress) || !validSlotAddress(e.RelayAddress) || cluster.Matches(e.Credential) {
			return invalid(errors.New("relay slot needs its own credential and exact registration"))
		}
		secret, err := serverhttp.NewBearerSecrets(e.Credential, "")
		if err != nil {
			return invalid(err)
		}
		for key, existing := range slots.entries {
			// Multiple processes can serve one public relay service. Each still
			// owns a distinct process ID, private address and credential.
			if key == secret || (e.Hostname == existing.Hostname) != (e.ServiceID == existing.ServiceID) || (e.RelayAddress == existing.RelayAddress) != (e.ServiceID == existing.ServiceID) || e.RelayID == existing.RelayID || e.InternalAddress == existing.InternalAddress {
				return invalid(errors.New("relay slots must have distinct credentials, identities and addresses"))
			}
		}
		slots.entries[secret] = e.slot
	}
	return slots, nil
}

func (s Slots) authenticate(r *http.Request) (*http.Request, bool) {
	for secret, slot := range s.entries {
		if secret.Authenticate(r.Header) {
			return r.WithContext(context.WithValue(r.Context(), slotContext{}, slot)), true
		}
	}
	return nil, false
}

func allowedSlot(ctx context.Context, service, id string) bool {
	s, scoped := ctx.Value(slotContext{}).(slot)
	return !scoped || s.ServiceID == service && s.RelayID == id
}

func allowedProcess(ctx context.Context, id string) bool {
	s, scoped := ctx.Value(slotContext{}).(slot)
	return !scoped || s.RelayID == id
}

func slotDenied() error {
	return serverhttp.NewProblemError(http.StatusForbidden, "unauthenticated", "relay credential does not authorize this slot")
}
