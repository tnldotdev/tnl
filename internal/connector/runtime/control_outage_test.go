package runtime

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
)

func TestOwnerOutageRetainsOnlyKnownTemporaryRenewalFailures(t *testing.T) {
	outage := failure.Wrap("renew authority", failure.ServerUnavailable, errors.New("connection refused"))
	denied := failure.Wrap("renew authority", failure.Authentication, errors.New("revoked"))
	for _, test := range []struct {
		name      string
		err       error
		temporary bool
	}{
		{"outage", outage, true},
		{"wrapped outage", fmt.Errorf("renew: %w", outage), true},
		{"request deadline", context.DeadlineExceeded, true},
		{"multiple transient causes", errors.Join(outage, context.DeadlineExceeded), true},
		{"revocation", denied, false},
		{"revocation with outage", errors.Join(outage, denied), false},
		{"unexpected fault", errors.New("unexpected fault"), false},
		{"cancellation", context.Canceled, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := temporaryOwnerRenewal(test.err); got != test.temporary {
				t.Fatalf("temporary = %v, want %v", got, test.temporary)
			}
		})
	}
}
