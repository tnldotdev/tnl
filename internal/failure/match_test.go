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

func TestOnlyWrappedSentinel(t *testing.T) {
	notFound := Wrap("read resource", ServerResourceNotFound, errors.New("not found"))
	cleanup := errors.New("independent cleanup failure")
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"sentinel", notFound, true},
		{"wrapped sentinel", fmt.Errorf("delete: %w", notFound), true},
		{"joined matches", errors.Join(notFound, fmt.Errorf("delete: %w", notFound)), true},
		{"independent cause", errors.Join(notFound, cleanup), false},
		{"wrapped independent cause", fmt.Errorf("delete: %w", errors.Join(notFound, cleanup)), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := Only(test.err, notFound); got != test.want {
				t.Fatalf("Only(%v, wrapped sentinel) = %t, want %t", test.err, got, test.want)
			}
		})
	}
}
