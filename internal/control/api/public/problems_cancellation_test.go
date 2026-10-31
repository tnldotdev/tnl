package public

import (
	"context"
	"fmt"
	"net/http/httptest"
	"testing"
)

type canceledProblemResponse struct {
	*httptest.ResponseRecorder
	ctx context.Context
}

func (w canceledProblemResponse) ObservabilityContext() context.Context { return w.ctx }

func TestCanceledControlStateRequestDoesNotWriteInternalProblem(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	w := canceledProblemResponse{httptest.NewRecorder(), ctx}
	serviceVisitorError(w, "authorize workload visitor", fmt.Errorf("database canceled: %w", context.Canceled))
	if w.Body.Len() != 0 || w.Flushed {
		t.Fatal("canceled request wrote an internal problem", w.Body.String())
	}
	// a database cancellation while the request remains current is still an
	// unexpected failure. only the request's own lifetime suppresses reporting.
	current := httptest.NewRecorder()
	serviceVisitorError(current, "authorize workload visitor", fmt.Errorf("database canceled: %w", context.Canceled))
	if current.Code != 500 {
		t.Fatal("active request hid a database failure", current.Code)
	}
}
