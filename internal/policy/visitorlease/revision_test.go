package visitorlease

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

func TestWaitRevisionUsesOnlyInstalledPolicyAndOriginalDeadline(t *testing.T) {
	for _, finish := range []string{"installed", "deadline", "disabled", "expired", "closed", "cancelled"} {
		t.Run(finish, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				lease, update, _ := fixture(t)
				if err := lease.Apply(lease.Begin(), update); err != nil {
					t.Fatal(err)
				}
				timeout := 5 * time.Second
				if finish == "expired" {
					timeout = time.Minute
				}
				ctx, cancel := context.WithTimeout(t.Context(), timeout)
				defer cancel()
				done := make(chan error, 1)
				go func() { done <- lease.WaitRevision(ctx, 2) }()
				synctest.Wait()
				select {
				case err := <-done:
					t.Fatal("an uninstalled revision supplied authority", err)
				default:
				}
				want := visitortoken.ErrPolicy
				switch finish {
				case "installed", "disabled":
					update.View.VisitorPolicyRevision++
					update.Enabled = finish == "installed"
					if err := lease.Apply(lease.Begin(), update); err != nil {
						t.Fatal(err)
					}
					if update.Enabled {
						want = nil
					}
				case "deadline":
					time.Sleep(5 * time.Second)
					want = context.DeadlineExceeded
				case "expired":
					time.Sleep(10 * time.Second)
				case "closed":
					lease.Close()
				case "cancelled":
					cancel()
					want = context.Canceled
				}
				if err := <-done; !errors.Is(err, want) {
					t.Fatal("revision wait changed its deadline or ignored policy retirement", err, want)
				}
			})
		})
	}
}
