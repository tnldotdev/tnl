package invocation

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type guestAllocationControl struct {
	saved                 controlv1.Service
	requests              []controlv1.AllocateGuestDemoServiceRequest
	keys, deleted         []string
	firstErr, deletionErr error
	until                 time.Time
}

func (c *guestAllocationControl) AllocateGuestDemoService(ctx context.Context, key string, body controlv1.AllocateGuestDemoServiceRequest) (controlv1.Service, error) {
	if deadline, ok := ctx.Deadline(); !ok || deadline.After(c.until) {
		return controlv1.Service{}, errors.New("guest allocation lost its fixed deadline")
	}
	c.keys = append(c.keys, key)
	observed := body
	// provider input cannot mutate the original request retained for recovery.
	if body.RequirePostQuantum != nil {
		observed.RequirePostQuantum = new(*body.RequirePostQuantum)
		*body.RequirePostQuantum = false
	}
	c.requests = append(c.requests, observed)
	if len(c.keys) == 1 && c.firstErr != nil {
		return controlv1.Service{}, c.firstErr
	}
	return c.saved, nil
}

func (c *guestAllocationControl) DeleteService(_ context.Context, service string) error {
	c.deleted = append(c.deleted, service)
	return c.deletionErr
}

func TestGuestAllocationCleanupRecoversOnlyItsOriginalService(t *testing.T) {
	allocation, control := guestAllocationFixture(t)
	lost := errors.New("allocation response lost")
	control.firstErr = lost
	if _, err := allocation.allocate(t.Context()); !errors.Is(err, lost) {
		t.Fatal("lost response did not retain its failure", err)
	}
	if err := allocation.cleanup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(control.keys) != 2 || control.keys[0] != control.keys[1] ||
		!reflect.DeepEqual(control.requests[0], control.requests[1]) ||
		!reflect.DeepEqual(control.deleted, []string{control.saved.Id}) {
		t.Fatal("cleanup changed allocation intent or deleted an unobserved service", control.keys, control.deleted)
	}
	if err := allocation.cleanup(t.Context()); err != nil || len(control.keys) != 2 || len(control.deleted) != 1 {
		t.Fatal("confirmed deletion replayed allocation or deletion", err)
	}
}

func TestGuestAllocationCleanupRetainsFailedDeletionAndRejectsForeignResponses(t *testing.T) {
	t.Run("failed deletion", func(t *testing.T) {
		allocation, control := guestAllocationFixture(t)
		if _, err := allocation.allocate(t.Context()); err != nil {
			t.Fatal(err)
		}
		failed := errors.New("delete unavailable")
		control.deletionErr = failed
		if err := allocation.cleanup(t.Context()); !errors.Is(err, failed) {
			t.Fatal(err)
		}
		control.deletionErr = nil
		if err := allocation.cleanup(t.Context()); err != nil || len(control.keys) != 1 ||
			!reflect.DeepEqual(control.deleted, []string{control.saved.Id, control.saved.Id}) {
			t.Fatal("failed deletion lost exact ownership", err, control.deleted)
		}
	})
	t.Run("foreign response", func(t *testing.T) {
		allocation, control := guestAllocationFixture(t)
		control.saved.GuestId = "gst_2222222222222222222222"
		if _, err := allocation.allocate(t.Context()); !errors.Is(err, publisheridentity.ErrScope) {
			t.Fatal("foreign service allocation was accepted", err)
		}
		if err := allocation.cleanup(t.Context()); !errors.Is(err, publisheridentity.ErrScope) || len(control.deleted) != 0 {
			t.Fatal("cleanup guessed an owned ID from a rejected response", err, control.deleted)
		}
	})
}

func TestGuestAllocationCleanupDoesNotReplayAfterFixedExpiry(t *testing.T) {
	for _, known := range []bool{false, true} {
		t.Run(map[bool]string{false: "lost response", true: "confirmed service"}[known], func(t *testing.T) {
			allocation, control := guestAllocationFixture(t)
			if !known {
				control.firstErr = errors.New("allocation response lost")
			}
			_, err := allocation.allocate(t.Context())
			if (err == nil) != known {
				t.Fatal("allocation did not retain its result", err)
			}
			allocation.guest.ExpiresAt = time.Now().Add(-time.Second)
			if err := allocation.cleanup(t.Context()); !errors.Is(err, context.DeadlineExceeded) || len(control.keys) != 1 || len(control.deleted) != 0 {
				t.Fatal("expired cleanup replayed authority", err, control.keys, control.deleted)
			}
		})
	}
}

func guestAllocationFixture(t *testing.T) (*guestServiceAllocation, *guestAllocationControl) {
	t.Helper()
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	until := time.Now().UTC().Add(time.Hour)
	guest := clientstate.GuestSession{GuestID: newID(opaqueid.GuestPrefix), ExpiresAt: until}
	service := controlv1.Service{Id: newID(opaqueid.ServicePrefix), GuestId: guest.GuestID, Protocol: controlv1.ServiceProtocolHTTP,
		Enabled: true, Ephemeral: true, ExpiresAt: new(until), RequirePostQuantum: true, TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "demo.example", Public: true, Port: 443}}
	control := &guestAllocationControl{saved: service, until: until}
	request := controlv1.AllocateGuestDemoServiceRequest{Target: "http://127.0.0.1:43127", RequirePostQuantum: new(true)}
	return &guestServiceAllocation{control: control, guest: guest, request: request, key: newID(opaqueid.IdempotencyPrefix)}, control
}
