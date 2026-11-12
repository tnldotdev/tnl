package httpaccess

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestSharePreparationFailureDoesNotLogCauses(t *testing.T) {
	for _, test := range []struct {
		err  error
		want string
	}{
		{fmt.Errorf("private detail: %w", context.DeadlineExceeded), "policy refresh timed out"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrPolicy), "visitor policy unavailable"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrKey), "verification key unavailable"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrToken), "visitor token invalid"},
		{fmt.Errorf("private detail: %w", visitortoken.ErrBinding), "visitor token binding invalid"},
		{errors.New("private detail"), "visitor permission unavailable"},
	} {
		if got := sharePreparationFailure(test.err); got != test.want {
			t.Fatalf("share preparation reason = %q, want %q", got, test.want)
		}
	}
}
