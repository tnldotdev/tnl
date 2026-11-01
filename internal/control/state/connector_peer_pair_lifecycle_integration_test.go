package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func connectorPairWorker(t *testing.T, parent context.Context, work func(context.Context) error) (chan error, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	workers := newIntegrationWorkers(t, cancel)
	done := make(chan error, 1)
	workers.Go(func() { done <- work(ctx) })
	return done, workers.stop
}

func (f connectorPairFixture) claim(t *testing.T, pair ConnectorPeerPair, slot int, at time.Time) {
	t.Helper()
	if _, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[slot].RelayLease, netip.MustParseAddr("192.0.2.10"), testConnectorLegProof(t, pair, slot, at, f.key), at); err != nil {
		t.Fatal(err)
	}
}

func (f connectorPairFixture) binding(t *testing.T, pair ConnectorPeerPair, at time.Time) (connectorPeerBinding, error) {
	t.Helper()
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	if err := lockServiceAdmission(t.Context(), tx, pair.ServiceID); err != nil {
		t.Fatal(err)
	}
	q := controlstatedb.New(tx)
	run, err := q.LockServiceRun(t.Context(), controlstatedb.LockServiceRunParams{ID: pair.ServiceRunID, ServiceID: pair.ServiceID})
	if err != nil {
		t.Fatal(err)
	}
	row, err := q.LockConnectorPeerPairForLegClaim(t.Context(), pair.ID)
	if err != nil {
		t.Fatal(err)
	}
	return f.d.connectorPeerPairBinding(t.Context(), tx, run, row, at)
}

func (f connectorPairFixture) report(t *testing.T, pair ConnectorPeerPair, until, at time.Time) {
	t.Helper()
	if err := f.d.ConfirmConnectorPeerPairPrepared(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, f.run.Token,
		ConnectorPeerPairPrepared{DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: until}, at); err != nil {
		t.Fatal(err)
	}
}

func TestIntegrationConnectorPeerPairStableReplacementLifecycle(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	replace := f.request
	replace.Action, replace.PreviousPairID, replace.PreviousGeneration, replace.RequestedAt = "replace", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Second)
	f.sign(t, &replace)
	next, err := f.d.PrepareConnectorPeerPair(f.visitor, replace, replace.RequestedAt)
	if err != nil || next.ID == pair.ID || next.Key == pair.Key || next.DeliveryID == pair.DeliveryID || next.DeliveryGeneration <= pair.DeliveryGeneration || !next.PublisherPreparedUntil.IsZero() {
		t.Fatal("stable-owner replacement failed to rotate its session", err)
	}
	if _, err := f.d.HeartbeatServiceRun(t.Context(), pair.ServiceID, pair.ServiceRunID, f.run.Token, f.now.Add(2*time.Second)); err != nil {
		t.Fatal(err)
	}
	before := connectorPairSavedAuthority(t, f.d, next.ID)
	retry, err := f.d.PrepareConnectorPeerPair(f.visitor, replace, f.now.Add(3*time.Second))
	if err != nil || retry.ID != next.ID || retry.Key != next.Key || retry.DeliveryID != next.DeliveryID || retry.DeliveryGeneration != next.DeliveryGeneration || !retry.ExpiresAt.Equal(next.ExpiresAt) || !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, next.ID)) {
		t.Fatal("lost replacement reply changed material, bound or durable state", err)
	}
	for _, action := range []string{"create", "renew", "replace"} {
		stale := f.request
		if action != "create" {
			stale.PreviousPairID, stale.PreviousGeneration = pair.ID, pair.DeliveryGeneration
		}
		stale.Action, stale.RequestedAt = action, f.now.Add(4*time.Second)
		f.sign(t, &stale)
		if _, err := f.d.PrepareConnectorPeerPair(f.visitor, stale, stale.RequestedAt); err == nil {
			t.Fatal("action confusion or stale predecessor recovered replacement", action)
		}
		if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, next.ID)) {
			t.Fatal("denied action changed replacement authority")
		}
	}
	if _, err := f.d.PrepareConnectorPeerPair(f.visitor, replace, next.ExpiresAt); err == nil {
		t.Fatal("exact reply retry revived expired replacement")
	}
}

func TestIntegrationConnectorPeerPairConcurrentReplacements(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	tx, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, tx)
	var blocker int32
	if err := tx.QueryRow(t.Context(), `SELECT pg_backend_pid() FROM control.service_runs WHERE id=$1 FOR UPDATE`, pair.ServiceRunID).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	var done [2]chan error
	success := make(chan ConnectorPeerPair, 2)
	for i := range done {
		r := f.request
		r.Action, r.PreviousPairID, r.PreviousGeneration, r.RequestedAt = "replace", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Duration(i+1)*time.Second)
		f.sign(t, &r)
		var join func()
		done[i], join = connectorPairWorker(t, f.visitor, func(ctx context.Context) error {
			next, err := f.d.PrepareConnectorPeerPair(ctx, r, r.RequestedAt)
			if err == nil {
				success <- next
			}
			return err
		})
		defer join()
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	first := waitForPostgresBlock(t, ctx, f.d, blocker, done[0])
	waitForPostgresBlock(t, ctx, f.d, first, done[1])
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	wins, conflicts := 0, 0
	for _, result := range done {
		err := awaitIntegrationResult(t, ctx, result)
		if err == nil {
			wins++
		} else if errors.Is(err, ErrServiceConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 || len(success) != 1 {
		t.Fatal("different predecessor proofs did not serialize to one successor", wins, conflicts)
	}
	var count int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_peer_pairs WHERE service_run_id=$1`, pair.ServiceRunID).Scan(&count); err != nil || count != 1 {
		t.Fatal("replacement retained duplicate sessions", err)
	}
}

func TestIntegrationConnectorPeerPairSupersededProofCannotBorrowRenewal(t *testing.T) {
	for _, action := range []string{"create", "replace"} {
		t.Run(action, func(t *testing.T) {
			f := newConnectorPairFixture(t)
			pair := f.create(t)
			original := f.request
			if action == "replace" {
				original.Action, original.PreviousPairID, original.PreviousGeneration, original.RequestedAt = action, pair.ID, pair.DeliveryGeneration, f.now.Add(time.Second)
				f.sign(t, &original)
				var err error
				pair, err = f.d.PrepareConnectorPeerPair(f.visitor, original, original.RequestedAt)
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.d.HeartbeatServiceRun(t.Context(), pair.ServiceID, pair.ServiceRunID, f.run.Token, f.now.Add(10*time.Second)); err != nil {
				t.Fatal(err)
			}
			renew := original
			renew.Action, renew.PreviousPairID, renew.PreviousGeneration, renew.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(11*time.Second)
			f.sign(t, &renew)
			current, err := f.d.RenewConnectorPeerPair(f.visitor, renew, renew.RequestedAt)
			if err != nil || !current.ExpiresAt.After(pair.ExpiresAt) {
				t.Fatal("fixture never advanced authority through a fresh renewal", err)
			}
			before := connectorPairSavedAuthority(t, f.d, pair.ID)
			old, err := f.d.PrepareConnectorPeerPair(f.visitor, original, f.now.Add(12*time.Second))
			t.Logf("action=%s original_until=%s fresh_renewal_until=%s old_proof_reply_until=%s", action, pair.ExpiresAt, current.ExpiresAt, old.ExpiresAt)
			if !errors.Is(err, ErrServiceConflict) || old.ID != "" || !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
				t.Fatal("superseded proof borrowed a later authorization or changed state", err)
			}
			latest, err := f.d.RenewConnectorPeerPair(f.visitor, renew, f.now.Add(13*time.Second))
			if err != nil || latest.ID != current.ID || latest.Key != current.Key || !latest.ExpiresAt.Equal(current.ExpiresAt) {
				t.Fatal("latest uncertain renewal lost its exact material or bound", err)
			}
		})
	}
}

func TestIntegrationConnectorPeerPairReplacementInsertRollback(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	for slot := range pair.Relays {
		f.claim(t, pair, slot, f.now)
	}
	f.report(t, pair, pair.ExpiresAt, f.now.Add(time.Second))
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	_, err := f.d.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_native_insert() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='native insert fixture rejected'; END $$;
	CREATE CONSTRAINT TRIGGER reject_native_insert AFTER INSERT ON control.connector_peer_pairs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.reject_native_insert()`)
	if err != nil {
		t.Fatal(err)
	}
	r := f.request
	r.Action, r.PreviousPairID, r.PreviousGeneration, r.RequestedAt = "replace", pair.ID, pair.DeliveryGeneration, f.now.Add(2*time.Second)
	f.sign(t, &r)
	_, err = f.d.PrepareConnectorPeerPair(f.visitor, r, r.RequestedAt)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" {
		t.Fatal("deferred insertion fault not reached or cause lost", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("failed successor insertion deleted predecessor, claims, report or expiry")
	}
}

func TestIntegrationConnectorPeerPairIndependentClaimBoundsAndReports(t *testing.T) {
	for _, shortSlot := range []int{0, 1} {
		t.Run(string(rune('0'+shortSlot)), func(t *testing.T) {
			f := newConnectorPairFixture(t)
			pair := f.create(t)
			principal := f.visitor.Value(controlPrincipalKey{}).(ControlPrincipal)
			short := f.now.Add(5 * time.Second)
			if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, principal.SessionID, short); err != nil {
				t.Fatal(err)
			}
			f.claim(t, pair, shortSlot, f.now)
			before := connectorPairSavedAuthority(t, f.d, pair.ID)
			binding, err := f.binding(t, pair, f.now.Add(time.Second))
			if err != nil || binding.claimsCurrent || !binding.preparedUntil.IsZero() {
				t.Fatal("either first slot must remain authorized but pending", err)
			}
			if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
				t.Fatal("pending binding read wrote authority")
			}
			if _, err := f.d.DeliverConnectorPeerPair(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, f.now.Add(time.Second)); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("one leg delivered key", err)
			}
			if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, principal.SessionID, f.now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			f.claim(t, pair, 1-shortSlot, f.now.Add(time.Second))
			f.report(t, pair, short, f.now.Add(2*time.Second))
			var claims []byte
			if err := f.d.pool.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(c) ORDER BY connection_slot) FROM control.connector_peer_pair_leg_claims c WHERE pair_id=$1`, pair.ID).Scan(&claims); err != nil {
				t.Fatal(err)
			}
			r := f.request
			r.Action, r.PreviousPairID, r.PreviousGeneration, r.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(3*time.Second)
			f.sign(t, &r)
			if _, err := f.d.RenewConnectorPeerPair(f.visitor, r, r.RequestedAt); err != nil {
				t.Fatal(err)
			}
			var afterClaims []byte
			if err := f.d.pool.QueryRow(t.Context(), `SELECT jsonb_agg(to_jsonb(c) ORDER BY connection_slot) FROM control.connector_peer_pair_leg_claims c WHERE pair_id=$1`, pair.ID).Scan(&afterClaims); err != nil || !bytes.Equal(claims, afterClaims) {
				t.Fatal("pair renewal renewed claim evidence", err)
			}
			binding, err = f.binding(t, pair, f.now.Add(4*time.Second))
			if err != nil || binding.expiresAt.After(short) || !binding.preparedUntil.Equal(short) {
				t.Fatal("parent growth widened old claim/report", err)
			}
			if _, err := f.d.DeliverConnectorPeerPair(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, f.now.Add(6*time.Second)); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("expired claim revived by pair renewal", err)
			}
			f.claim(t, pair, shortSlot, f.now.Add(7*time.Second))
			binding, err = f.binding(t, pair, f.now.Add(8*time.Second))
			if err != nil || !binding.claimsCurrent || !binding.preparedUntil.IsZero() {
				t.Fatal("fresh claims silently renewed expired installation", err)
			}
			f.report(t, pair, binding.expiresAt, f.now.Add(8*time.Second))
			installed, err := f.binding(t, pair, f.now.Add(9*time.Second))
			if err != nil || !installed.preparedUntil.Equal(binding.expiresAt) {
				t.Fatal("new report failed to record only the checked snapshot", err)
			}
			shorter := f.now.Add(12 * time.Second)
			if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, principal.SessionID, shorter); err != nil {
				t.Fatal(err)
			}
			f.claim(t, pair, shortSlot, f.now.Add(10*time.Second))
			if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, principal.SessionID, f.now.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			clipped, err := f.binding(t, pair, f.now.Add(11*time.Second))
			if err != nil || !clipped.preparedUntil.Equal(shorter) || !installed.preparedUntil.Equal(binding.expiresAt) {
				t.Fatal("shorter fresh claim did not clip only current installation snapshot", err)
			}
		})
	}
}

func TestIntegrationConnectorPeerPairClaimOrderSourceDenial(t *testing.T) {
	for _, first := range []int{0, 1} {
		t.Run(string(rune('0'+first)), func(t *testing.T) {
			f := newConnectorPairFixture(t)
			pair := f.create(t)
			f.claim(t, pair, first, f.now)
			pending, err := f.binding(t, pair, f.now.Add(time.Second))
			if err != nil || pending.claimsCurrent {
				t.Fatal("first valid slot was not pending", err)
			}
			second := 1 - first
			at := f.now.Add(time.Second)
			if _, err := testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[second].RelayLease, netip.MustParseAddr("192.0.2.11"), testConnectorLegProof(t, pair, second, at, f.key), at); err != nil {
				t.Fatal("second independently signed source claim", err)
			}
			before := connectorPairSavedAuthority(t, f.d, pair.ID)
			if _, err := f.binding(t, pair, f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("different source claims became pending instead of denial", err)
			}
			if _, err := f.d.DeliverConnectorPeerPair(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, f.now.Add(2*time.Second)); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("different source claims delivered key", err)
			}
			if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
				t.Fatal("source denial changed authority")
			}
		})
	}
}

func TestIntegrationConnectorPeerPairClaimReportRollbackAndReadOnlyDelivery(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	for slot := range pair.Relays {
		f.claim(t, pair, slot, f.now)
	}
	_, err := f.d.pool.Exec(t.Context(), `CREATE FUNCTION control.reject_native_commit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION USING ERRCODE='23514',MESSAGE='native commit fixture rejected'; END $$;
	CREATE CONSTRAINT TRIGGER reject_claim_commit AFTER INSERT OR UPDATE ON control.connector_peer_pair_leg_claims DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.reject_native_commit();
	CREATE CONSTRAINT TRIGGER reject_report_commit AFTER UPDATE ON control.connector_peer_pairs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION control.reject_native_commit()`)
	if err != nil {
		t.Fatal(err)
	}
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	at := f.now.Add(time.Second)
	_, err = testClaimConnectorPeerPairLeg(t, f.d, t.Context(), pair.Relays[0].RelayLease, netip.MustParseAddr("192.0.2.10"), testConnectorLegProof(t, pair, 0, at, f.key), at)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" || !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("claim commit rejection lost cause or mutated evidence", err)
	}
	err = f.d.ConfirmConnectorPeerPairPrepared(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, f.run.Token, ConnectorPeerPairPrepared{DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: pair.ExpiresAt}, at)
	if !errors.As(err, &constraint) || constraint.Code != "23514" || !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("report commit rejection lost cause or mutated authority", err)
	}
	if _, err := f.d.DeliverConnectorPeerPair(t.Context(), pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, at); err != nil || !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("pure delivery attempted a durable write", err)
	}
}

func TestIntegrationConnectorPeerPairExpiryDuringDatabaseWait(t *testing.T) {
	for _, operation := range []string{"claim", "delivery", "report"} {
		t.Run(operation, func(t *testing.T) {
			f := newConnectorPairFixture(t)
			pair := f.create(t)
			for slot := range pair.Relays {
				f.claim(t, pair, slot, f.now)
			}
			until := f.now.Add(50 * time.Millisecond)
			if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs SET expires_at=$2 WHERE id=$1`, pair.ID, until); err != nil {
				t.Fatal(err)
			}
			before := connectorPairSavedAuthority(t, f.d, pair.ID)
			tx, err := f.d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, tx)
			var blocker int32
			if err := tx.QueryRow(t.Context(), `SELECT pg_backend_pid() FROM control.service_runs WHERE id=$1 FOR UPDATE`, pair.ServiceRunID).Scan(&blocker); err != nil {
				t.Fatal(err)
			}
			proof := testConnectorLegProof(t, pair, 0, f.now.Add(time.Millisecond), f.key)
			source := netip.MustParseAddr("192.0.2.10")
			message, err := proof.RelayClaimMessage(source)
			if err != nil {
				t.Fatal(err)
			}
			seed := sha256.Sum256([]byte(pair.Relays[0].RelayLease.RelayRunID))
			signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed[:]), message)
			done, join := connectorPairWorker(t, f.visitor, func(ctx context.Context) error {
				switch operation {
				case "claim":
					_, err := f.d.ClaimConnectorPeerPairLeg(ctx, pair.Relays[0].RelayLease, source, proof, signature, f.now)
					return err
				case "delivery":
					_, err := f.d.DeliverConnectorPeerPair(ctx, pair.ServiceID, pair.ServiceRunID, pair.ID, pair.DeliveryGeneration, f.run.Token, f.now)
					return err
				default:
					return f.d.ConfirmConnectorPeerPairPrepared(ctx, pair.ServiceID, pair.ServiceRunID, pair.ID, f.run.Token, ConnectorPeerPairPrepared{DeliveryID: pair.DeliveryID, DeliveryGeneration: pair.DeliveryGeneration, BindingExpiresAt: until}, f.now)
				}
			})
			defer join()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			waitForPostgresBlock(t, ctx, f.d, blocker, done)
			timer := time.NewTimer(60 * time.Millisecond)
			defer timer.Stop()
			<-timer.C
			if err := tx.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("database wait returned expired authority", err)
			}
			if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
				t.Fatal("expired operation changed authority")
			}
		})
	}
}
