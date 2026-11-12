package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func TestIntegrationEnvironmentProvisioningExchangeExpiryAfterWrite(t *testing.T) {
	for _, boundary := range []string{"machine_proof_uses", "machine_provisioning_sessions"} {
		for _, limit := range []string{"grant", "proof"} {
			t.Run(boundary+"/"+limit, func(t *testing.T) {
				f := newProvisioningEnvironmentFixture(t)
				ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
				workers := newIntegrationWorkers(t, cancel)
				defer workers.stop()
				gate, err := f.d.pool.Begin(ctx)
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if _, err := gate.Exec(ctx, `SELECT pg_advisory_xact_lock(7397)`); err != nil {
					t.Fatal(err)
				}
				// the table name is a test-owned literal, never caller input. the
				// wait graph proves exchange has passed its initial expiry check.
				_, err = f.d.pool.Exec(ctx, `CREATE FUNCTION control.provisioning_exchange_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(7397); RETURN NEW; END $$; CREATE TRIGGER provisioning_exchange_wait BEFORE INSERT ON control.`+boundary+` FOR EACH ROW EXECUTE FUNCTION control.provisioning_exchange_wait()`)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now()
				deadline := now.Add(3 * time.Second).Truncate(time.Second)
				signedAt := now
				if limit == "grant" {
					if _, err := f.d.pool.Exec(ctx, `UPDATE control.machine_provisioning_grants SET expires_at=$2 WHERE id=$1`, f.grant.ID, deadline); err != nil {
						t.Fatal(err)
					}
				} else {
					signedAt = deadline.Add(-publisherproof.AssertionLifetime)
				}
				const audience = "https://control.example/v1/provisioning-sessions/exchange"
				assertion, err := publisherproof.Sign(f.machine.ID, "first", machineproof.Provisioning(f.grant.ID, string(ProvisioningRead)), audience, f.key, signedAt)
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan error, 1)
				issued := make(chan ProvisioningSession, 1)
				workers.Go(func() {
					session, err := f.d.ExchangeProvisioning(ctx, f.machine.ID, f.grant.ID, ProvisioningRead, MachineProof{Assertion: assertion}, audience, now)
					issued <- session
					done <- err
				})
				waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
				timer := time.NewTimer(time.Until(deadline))
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-ctx.Done():
					t.Fatal(ctx.Err())
				}
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrMachineDenied) {
					t.Fatal("exchange committed after its captured deadline", err)
				}
				if session := awaitIntegrationResult(t, ctx, issued); session.Credential != "" || !session.ExpiresAt.IsZero() {
					t.Fatal("denied exchange returned session facts")
				}
				var proofs, sessions int
				if err := f.d.pool.QueryRow(ctx, `SELECT (SELECT count(*) FROM control.machine_proof_uses WHERE machine_id=$1),(SELECT count(*) FROM control.machine_provisioning_sessions WHERE machine_id=$1)`, f.machine.ID).Scan(&proofs, &sessions); err != nil || proofs != 0 || sessions != 0 {
					t.Fatal("expired exchange retained proof consumption or a session", proofs, sessions, err)
				}
			})
		}
	}
}
