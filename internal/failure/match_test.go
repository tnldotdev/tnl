package failure

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestOnly(t *testing.T) {
	cleanup := errors.New("cleanup failed")
	for _, test := range []struct {
		err  error
		want bool
	}{
		{nil, false}, {context.Canceled, true}, {fmt.Errorf("read: %w", context.Canceled), true},
		{errors.Join(context.Canceled, fmt.Errorf("write: %w", context.Canceled)), true},
		{errors.Join(context.Canceled, cleanup), false},
		{fmt.Errorf("finish: %w", errors.Join(context.Canceled, cleanup)), false},
		{context.DeadlineExceeded, false},
	} {
		if got := Only(test.err, context.Canceled); got != test.want {
			t.Fatalf("Only(%v, canceled) = %t", test.err, got)
		}
	}
}
