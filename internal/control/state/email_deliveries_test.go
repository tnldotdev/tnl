package state

import "testing"

func TestInvitationEmailOutcomePhases(t *testing.T) {
	for _, test := range []struct {
		status int
		phase  emailDeliveryNextPhase
	}{
		{0, emailDeliveryRetryQueued},
		{200, emailDeliveryRetryQueued},
		{204, emailDeliveryCompleted},
		{302, emailDeliveryRetryQueued},
		{400, emailDeliveryCompleted},
		{401, emailDeliveryRetryQueued},
		{422, emailDeliveryCompleted},
		{429, emailDeliveryRetryQueued},
		{503, emailDeliveryRetryQueued},
	} {
		outcome := InvitationEmailOutcome(test.status)
		if outcome.phase != test.phase || outcome.status != test.status {
			t.Errorf("status %d: outcome = %+v, want phase %d", test.status, outcome, test.phase)
		}
	}
}
