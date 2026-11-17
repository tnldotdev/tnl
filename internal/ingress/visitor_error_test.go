package ingress

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestVisitorErrorKeepsIndependentCleanupAndRunlessCandidate(t *testing.T) {
	cleanup := errors.New("secret accepted socket cleanup")
	for _, independent := range []bool{false, true} {
		var physical error
		if independent {
			physical = cleanup
		}
		d := &visitorDiagnostic{VisitorError: VisitorError{service: "service", visitor: "visitor", candidate: "candidate", candidateNumber: 7, phase: "selection", denial: "ip_policy"}}
		reported := d.finish(ErrServiceAdmission, physical)
		var scope *VisitorError
		if !errors.As(reported, &scope) || !errors.Is(reported, ErrServiceAdmission) ||
			independent != errors.Is(reported, cleanup) || failure.Only(reported, ErrServiceAdmission) == independent {
			t.Fatal("scoped denial changed raw identity or hid an independent failure")
		}
		if _, run, _, number := scope.ForwardingScope(); run != "" || number != 0 || scope.ForwardingAdmitted() ||
			scope.ForwardingOperation() != ErrServiceAdmission || scope.ForwardingCleanup() != physical && !errors.Is(scope.ForwardingCleanup(), physical) {
			t.Fatal("diagnostic wrapper invented a selected/admitted run or lost cleanup")
		}
		if _, ok := failure.ReasonOf(reported); ok {
			t.Fatal("diagnostic wrapper invented an operational reason")
		}
		encoded, err := json.Marshal(reported)
		if err != nil || string(encoded) != "{}" {
			t.Fatal("diagnostic error serialized a raw cause")
		}
		for _, format := range []string{"%s", "%v", "%+v", "%#v"} {
			if strings.Contains(fmt.Sprintf(format, reported), "secret") {
				t.Fatal("diagnostic error presentation exposed cleanup")
			}
		}
	}
}

func TestVisitorErrorRetainsScopeWhenOnlyFinalPhysicalCleanupFails(t *testing.T) {
	cleanup := errors.New("physical cleanup failed after successful copy")
	d := &visitorDiagnostic{VisitorError: VisitorError{service: "service", run: "selected", number: 7, visitor: "visitor", phase: "copy"}}
	d.admitted.Store(true)
	reported := d.finish(nil, cleanup)
	var scoped *VisitorError
	if !errors.As(reported, &scoped) || !errors.Is(reported, cleanup) || scoped.ForwardingOperation() != nil ||
		scoped.ForwardingCopyResult() != nil || !errors.Is(scoped.ForwardingCleanup(), cleanup) || !scoped.ForwardingAdmitted() {
		t.Fatal("cleanup-only failure lost its successful operation or admitted scope")
	}
	if d.run != "selected" || d.phase != "copy" {
		t.Fatal("final observation mutated the diagnostic carrier")
	}
	if (&visitorDiagnostic{}).finish(nil, nil) != nil {
		t.Fatal("diagnostics invented a successful connection's failure")
	}
}
