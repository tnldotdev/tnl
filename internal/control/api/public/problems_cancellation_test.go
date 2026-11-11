package public

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
)

func TestCanceledControlStateRequestDoesNotWriteInternalProblem(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w := httptest.NewRecorder()
	serviceVisitorError(ctx, w, "authorize workload visitor", fmt.Errorf("database canceled: %w", context.Canceled))
	if w.Body.Len() != 0 || w.Flushed {
		t.Fatal("canceled request wrote an internal problem", w.Body.String())
	}
	// a database cancellation while the request remains current is still an
	// unexpected failure. only the request's own lifetime suppresses reporting.
	current := httptest.NewRecorder()
	serviceVisitorError(t.Context(), current, "authorize workload visitor", fmt.Errorf("database canceled: %w", context.Canceled))
	if current.Code != 500 {
		t.Fatal("active request hid a database failure", current.Code)
	}
}
