package visitortoken

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestReservationProofBindsRunAndTrustedSource(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	reservation := tunnelv1.StreamReservation{ID: "sres_" + strings.Repeat("a", 22), AllocationID: "salloc_" + strings.Repeat("b", 22), Slot: 1, Sequence: 2,
		ResourceKind: "service", ResourceID: "svc_" + strings.Repeat("c", 22), RunID: "srun_" + strings.Repeat("d", 22), RunNumber: 1,
		VisitorConnectionID: "vc_" + strings.Repeat("e", 22), IngressID: "ingress", IngressRunID: "process", IngressLeaseRevision: 1}
	if err := SignReservation(key, &reservation, netip.MustParseAddr("192.0.2.4")); err != nil {
		t.Fatal(err)
	}
	if err := VerifyReservation(key, reservation); err != nil {
		t.Fatal("ingress proof failed to verify", err)
	}
	for _, edit := range []func(*tunnelv1.StreamReservation){
		func(r *tunnelv1.StreamReservation) { r.RunID = "srun_" + strings.Repeat("z", 22) },
		func(r *tunnelv1.StreamReservation) { r.SourceIP = "198.51.100.1" },
		func(r *tunnelv1.StreamReservation) { r.Sequence++ },
	} {
		forged := reservation
		edit(&forged)
		if err := VerifyReservation(key, forged); err == nil {
			t.Fatal("relay rewrote a signed ingress reservation")
		}
	}
}
