package ingress

import (
	"context"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

// a service run can close while ingress reports its first publisher byte.
// control then cancels the open episode and permanently rejects the observation.
func TestRecoveryReporterStopsAfterCanceledEpisode(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		control := new(staleRecoveryControl)
		reporter, err := NewRecoveryReporter(ctx, control, time.Second, nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		defer func() {
			cancel()
			if err := reporter.Close(t.Context()); err != nil {
				t.Error(err)
			}
		}()
		reporter.Observe(ingressv1.ServiceRunReference{ServiceId: "service", ServiceRunId: "run", RunNumber: 1}, "visitor", 7, time.Now().UTC(), nil)
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if control.calls != 1 {
			t.Fatalf("canceled recovery episode retried %d times, want one observation", control.calls)
		}
	})
}

type staleRecoveryControl struct{ calls int }

func (c *staleRecoveryControl) ObserveRecovery(context.Context, ingressv1.ServiceRunReference, string, uint64, time.Time, []byte) (ingressv1.ServiceRecoveryObservation, error) {
	c.calls++
	return ingressv1.ServiceRecoveryObservation{}, &ControlProblemError{
		Operation: "observe service recovery", Status: http.StatusConflict,
		Problem: &ingressv1.Problem{Code: ingressv1.RecoveryEpisodeStale},
	}
}
