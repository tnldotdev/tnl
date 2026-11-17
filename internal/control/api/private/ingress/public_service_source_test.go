package ingress

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type publicSourceStore struct {
	Store
	calls  int
	source netip.Addr
}

func (s *publicSourceStore) PublicServiceVisitorStatus(_ context.Context, _ controlstate.IngressLeaseIdentity, _ string, source netip.Addr, now time.Time) (controlstate.PublicServiceVisitorStatus, error) {
	s.calls++
	s.source = source
	return controlstate.PublicServiceVisitorStatus{State: controlstate.PublicServiceVisitorPending, ValidUntil: now.Add(time.Second)}, nil
}

func TestNativeStatusRequiresLiveSource(t *testing.T) {
	store := &publicSourceStore{}
	service := &service{store: store, now: time.Now}
	body := ingressv1.PublicServiceVisitorLookup{IngressRunId: "ir_" + strings.Repeat("a", 22),
		IngressLeaseRevision: 1, VisitorConnectionId: "vc_" + strings.Repeat("a", 22)}
	for _, invalid := range []string{"", "0.0.0.0", "::", "192.0.2.1/32", "192.0.2.1:443", "fe80::1%en0"} {
		body.ObservedSourceIp = invalid
		if _, err := service.PublicServiceVisitorStatus(t.Context(), "ingress", body); err == nil || store.calls != 0 {
			t.Fatal("invalid source reached status authorization", invalid, err)
		}
	}
	for _, valid := range []string{"192.0.2.1", "::ffff:192.0.2.1"} {
		body.ObservedSourceIp = valid
		if result, err := service.PublicServiceVisitorStatus(t.Context(), "ingress", body); err != nil || result.State != ingressv1.PublicServiceVisitorPending || store.source != netip.MustParseAddr("192.0.2.1") {
			t.Fatal("live source was not passed to status authorization", err)
		}
	}
	if store.calls != 2 {
		t.Fatal("missing live source checks")
	}
}
