package ingress

import (
	"context"
	"net/http"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

// A publish run can close while ingress is reporting its first publisher byte.
// Control then cancels the open episode and permanently rejects the observation.
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
		reporter.Observe("public_url_test", 1, 7, time.Now().UTC())
		time.Sleep(2 * time.Second)
		synctest.Wait()
		if control.calls != 1 {
			t.Fatalf("canceled recovery episode retried %d times, want one observation", control.calls)
		}
	})
}

type staleRecoveryControl struct{ calls int }

func (c *staleRecoveryControl) ObserveRecovery(context.Context, string, uint64, uint64, time.Time) (ingressv1.PublicURLRecoveryObservation, error) {
	c.calls++
	return ingressv1.PublicURLRecoveryObservation{}, &ControlProblemError{
		Operation: "observe route recovery", Status: http.StatusConflict,
		Problem: &ingressv1.Problem{Type: "https://tnl.dev/p/recovery-episode-stale"},
	}
}
