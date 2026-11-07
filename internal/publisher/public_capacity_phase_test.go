package publisher

import (
	"net/netip"
	"testing"
)

func TestPublicCapacityPhasesRetainChargesDuringStop(t *testing.T) {
	source := netip.MustParsePrefix("192.0.2.0/24")
	for _, test := range []struct {
		name     string
		phase    publicVisitorPhase
		admitted bool
		source   netip.Prefix
	}{
		{"unverified", unverifiedPublicSetup{}, false, netip.Prefix{}},
		{"verified", verifiedPublicSetup{source: source}, false, source},
		{"committed", committedPublicSetup{}, true, netip.Prefix{}},
		{"promoted", promotedPublicSetup{}, true, netip.Prefix{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			a := &publicVisitorAdmission{phase: test.phase}
			a.phase = stoppedPublicSetup{previous: a.phase}
			if a.admittedLocked() != test.admitted || a.sourceLocked() != test.source {
				t.Fatal("stopping the visitor released its pending or authorized charge")
			}
			a.phase = retiredPublicSetup{}
			if a.admittedLocked() || a.sourceLocked().IsValid() {
				t.Fatal("retired visitor retained a charge")
			}
		})
	}
}
