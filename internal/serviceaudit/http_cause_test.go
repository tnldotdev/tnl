package serviceaudit

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type causeTransport struct{ cause error }

func (tr causeTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, tr.cause }

func TestHTTPReporterPreservesSafeCauses(t *testing.T) {
	for _, cause := range []error{ErrRejected, context.Canceled, context.DeadlineExceeded, errors.New("secret-provider-value")} {
		for _, source := range []string{"destination", "transport"} {
			t.Run(source+"/"+fmt.Sprint(cause), func(t *testing.T) {
				report := HTTPReporter(&http.Client{Transport: causeTransport{cause}}, func(context.Context) (Destination, error) {
					if source == "destination" {
						return Destination{}, cause
					}
					return Destination{URL: "https://secret-destination.invalid", Bearer: "secret-bearer"}, nil
				})
				err := report(t.Context(), Batch{})
				if !errors.Is(err, cause) || strings.Contains(fmt.Sprintf("%v %+v %#v", err, err, err), "secret") {
					t.Fatalf("report lost cause identity or safe formatting: %v", err)
				}
			})
		}
	}
}

func TestHTTPReporterDestinationRejectionDoesNotRetry(t *testing.T) {
	var attempts atomic.Int64
	q, err := NewQueue(t.Context(), QueueConfig{RetryMin: time.Millisecond, RetryMax: time.Millisecond, Report: HTTPReporter(nil, func(context.Context) (Destination, error) {
		attempts.Add(1)
		return Destination{}, ErrRejected
	})})
	if err != nil {
		t.Fatal(err)
	}
	if !q.Observe(observation()) {
		t.Fatal("fixture rejected")
	}
	if err := q.Close(t.Context()); err != nil {
		t.Fatal(err)
	}
	if attempts.Load() != 1 {
		t.Fatal("permanent destination rejection retried", attempts.Load())
	}
}
