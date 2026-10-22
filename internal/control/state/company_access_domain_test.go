package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestCompanyAdmissionDomainsAndDecisionRetries(t *testing.T) {
	for _, value := range []string{"active", "pending", "approved", "denied", "retired", ""} {
		if _, err := parseCompanyAdmissionMode(value); !errors.Is(err, ErrAuthorityInvalid) {
			t.Fatalf("connection/request state accepted as admission mode: %q, %v", value, err)
		}
	}
	for _, value := range []string{"approval", "managed", "active", "pending", "retired", ""} {
		if _, err := parseCompanyOwnerAdmissionDecision(value); !errors.Is(err, ErrAuthorityInvalid) {
			t.Fatalf("configuration/state accepted as owner decision: %q, %v", value, err)
		}
	}
	for _, state := range []companyAdmissionRequestState{companyRequestPending, companyRequestApproved, companyRequestDenied} {
		for _, decision := range []companyOwnerAdmissionDecision{companyOwnerApprove, companyOwnerDeny} {
			next, err := state.decide(decision)
			if err != nil || string(next) != string(decision) {
				t.Fatalf("owner retry/revision changed: %s + %s = %s, %v", state, decision, next, err)
			}
		}
	}
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	for _, check := range []struct {
		state                string
		until                time.Time
		provision, automatic bool
	}{
		{"pending", now.Add(time.Minute), true, false},
		{"pending", now, false, false},
		{"active", now, true, true},
		{"retired", now.Add(time.Minute), false, false},
	} {
		connection := companyConnectionFromRow(controlstatedb.ControlIdentityConnection{State: check.state, Admission: "managed", SetupExpiresAt: timestamptz(check.until)})
		if connection.acceptsProvisioning(now) != check.provision || connection.automaticallyAdmits() != check.automatic {
			t.Fatalf("connection state crossed provisioning/admission boundary: %+v", check)
		}
	}
}
