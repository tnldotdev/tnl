package identity

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

type lateAuthorityCheckpoint struct {
	ApplicationCheckpoint
	originalDeadline time.Time
	independent      error
}

func (p lateAuthorityCheckpoint) Checkpoint(ctx context.Context, next clientstate.ApplicationPublicationRecord) error {
	if next.IdentityExpiresAt.After(p.originalDeadline) && next.Phase != clientstate.ApplicationRefreshPending && next.Phase != clientstate.ApplicationDenied && next.Phase != clientstate.ApplicationCleanupPending && next.Phase != clientstate.ApplicationCleanupDone {
		<-ctx.Done()
		// emulate a synchronous store returning either late success or only its
		// independent failure. the identity owner must preserve the cause itself.
		return p.independent
	}
	return p.ApplicationCheckpoint.Checkpoint(ctx, next)
}

func TestApplicationSessionLateCheckpointCannotAdvanceExpiredFenceOrRecover(t *testing.T) {
	for _, independent := range []bool{false, true} {
		t.Run(map[bool]string{false: "late-success", true: "independent-storage-failure"}[independent], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				deadline := time.Now().Add(5 * time.Second)
				a := &applicationSessionAuthority{response: applicationSessionResponse()}
				a.response.IdentityExpiresAt, a.response.ExpiresAt, a.response.RenewAfter = deadline, deadline, deadline.Add(-time.Second)
				s, err := exchangeApplicationSession(t, t.Context(), applicationSessionControl{}, a, *a.response.Publisher.PublicUrlId, "", "ivk_0123456789ABCDEFGHIJKL", "initial-proof")
				if err != nil {
					t.Fatal(err)
				}
				original, err := s.publication.Snapshot(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer clear(original.NativeKey)
				failure := errors.New("independent storage completion failed")
				var injected error
				if independent {
					injected = failure
				}
				s.publication = lateAuthorityCheckpoint{ApplicationCheckpoint: s.publication, originalDeadline: deadline, independent: injected}
				a.refresh = func(context.Context) (authorityv1.MachinePublicationSession, error) {
					response := a.response
					response.IdentityExpiresAt = deadline.Add(time.Minute)
					response.ExpiresAt = response.IdentityExpiresAt
					response.RenewAfter = deadline.Add(30 * time.Second)
					return response, nil
				}
				worker := make(chan error, 1)
				go func() {
					worker <- s.Run(t.Context(), func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
				}()
				err = s.Refresh(t.Context(), "fresh-proof")
				if !errors.Is(err, ErrApplicationSessionUncertain) || !errors.Is(err, context.DeadlineExceeded) || independent && !errors.Is(err, failure) {
					t.Fatal("late checkpoint success/failure lost its uncertainty or cause", err)
				}
				if !s.identityExpiresAt.Equal(deadline) || !s.fence.Load().deadline.Equal(deadline) || s.CheckServing() == nil {
					t.Fatal("late storage return advanced expired authority")
				}
				if err := <-worker; !errors.Is(err, ErrScope) {
					t.Fatal("original serving-fence worker did not stop and join", err)
				}
				if reopened, err := OpenApplicationSession(t.Context(), applicationSessionControl{}, a, s.publication, "replacement-proof"); reopened != nil || !errors.Is(err, ErrScope) || a.exchanges != 1 || a.refreshes != 1 {
					t.Fatal("expired confirmation was reconstructed or regranted", err)
				}
				if err := s.CleanupAllocation(t.Context()); err != nil {
					t.Fatal("original-key cleanup became unavailable", err)
				}
				final, err := s.publication.Snapshot(t.Context())
				if err != nil || final.Phase != clientstate.ApplicationCleanupDone || len(final.NativeKey) != 0 || final.Nonce != original.Nonce {
					t.Fatal("cleanup discarded or replaced original tuple", err)
				}
			})
		})
	}
}
