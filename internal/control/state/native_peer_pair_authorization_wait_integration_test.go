package state

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestIntegrationNativePeerPairAuthorizationExpiryDuringWait(t *testing.T) {
	for _, test := range []struct {
		action, authority, gate string
	}{
		{"create", "request", "run"},
		{"create", "subject", "run"},
		{"create", "publisher", "run"},
		{"create", "certificate", "run"},
		{"create", "relay", "run"},
		{"create-reply", "pair", "pair"},
		{"renew", "pair", "run"},
		{"renew-reply", "pair", "pair"},
		{"replace-reply", "pair", "pair"},
		{"renew", "pair", "write"},
		{"renew", "pair", "deferred"},
		{"create", "request", "write"},
		{"create", "request", "deferred"},
	} {
		t.Run(test.action+"/"+test.authority+"/"+test.gate, func(t *testing.T) {
			f := newNativePairFixture(t)
			r := f.request
			var pair NativePeerPair
			if test.action != "create" {
				pair = f.create(t)
				if test.action != "create-reply" {
					r.Action, r.PreviousPairID, r.PreviousGeneration, r.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Millisecond)
					if test.action == "replace-reply" {
						r.Action = "replace"
					}
					f.sign(t, &r)
					if test.action == "renew-reply" {
						var err error
						pair, err = f.d.RenewNativePeerPair(f.visitor, r, r.RequestedAt)
						if err != nil {
							t.Fatal(err)
						}
					} else if test.action == "replace-reply" {
						var err error
						pair, err = f.d.PrepareNativePeerPair(f.visitor, r, r.RequestedAt)
						if err != nil {
							t.Fatal(err)
						}
					}
				}
			}
			// leave time to reach even the deferred gate before expiry. measure
			// the crossing from operation entry, not from fixture setup or an
			// arbitrary goroutine scheduling delay. the supplied authority clock
			// remains f.now; the original 50 ms review proof runs separately.
			until := f.now.Add(time.Second)
			var query string
			var id string
			switch test.authority {
			case "request":
				r.RequestedAt = until.Add(-5 * time.Minute)
				f.sign(t, &r)
			case "subject":
				query, id = `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, f.visitor.Value(controlPrincipalKey{}).(ControlPrincipal).SessionID
			case "publisher":
				query, id = `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, r.ServiceRunID
			case "certificate":
				query, id = `UPDATE control.service_runs SET certificate_expires_at=$2 WHERE id=$1`, r.ServiceRunID
			case "relay":
				query, id = `UPDATE control.relay_leases SET lease_expires_at=$2 WHERE relay_id=$1`, r.ExpectedRelays[0].RelayLease.RelayID
			case "pair":
				query, id = `UPDATE control.native_peer_pairs SET expires_at=$2 WHERE id=$1`, pair.ID
			}
			if query != "" {
				if _, err := f.d.pool.Exec(t.Context(), query, id, until); err != nil {
					t.Fatal(err)
				}
			}
			saved := func() []byte {
				t.Helper()
				var value []byte
				if err := f.d.pool.QueryRow(t.Context(), `SELECT COALESCE(jsonb_agg(to_jsonb(p) ORDER BY id),'[]'::jsonb) FROM control.native_peer_pairs p WHERE service_run_id=$1`, r.ServiceRunID).Scan(&value); err != nil {
					t.Fatal(err)
				}
				return value
			}
			before := saved()
			gate, err := f.d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			blocker := int32(gate.Conn().PgConn().PID())
			switch test.gate {
			case "run":
				_, err = gate.Exec(t.Context(), `SELECT id FROM control.service_runs WHERE id=$1 FOR UPDATE`, r.ServiceRunID)
			case "pair":
				_, err = gate.Exec(t.Context(), `SELECT id FROM control.native_peer_pairs WHERE id=$1 FOR UPDATE`, pair.ID)
			default:
				// gate the write itself or a deferred commit-time constraint, after
				// the proposed deadline and prior pair expiry have been selected.
				_, err = gate.Exec(t.Context(), `SELECT pg_advisory_xact_lock(7319)`)
				if err == nil {
					trigger := `CREATE TRIGGER authorization_wait BEFORE INSERT OR UPDATE ON control.native_peer_pairs`
					if test.gate == "deferred" {
						trigger = `CREATE CONSTRAINT TRIGGER authorization_wait AFTER INSERT OR UPDATE ON control.native_peer_pairs DEFERRABLE INITIALLY DEFERRED`
					}
					_, err = f.d.pool.Exec(t.Context(), `CREATE FUNCTION control.native_authorization_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(7319); RETURN NEW; END $$; `+trigger+` FOR EACH ROW EXECUTE FUNCTION control.native_authorization_wait()`)
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			entered := make(chan time.Time, 1)
			done, join := nativePairWorker(t, f.visitor, func(ctx context.Context) error {
				entered <- time.Now()
				at := f.now.Add(2 * time.Millisecond)
				if r.Action == "renew" {
					_, err := f.d.RenewNativePeerPair(ctx, r, at)
					return err
				}
				_, err := f.d.PrepareNativePeerPair(ctx, r, at)
				return err
			})
			defer join()
			ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
			defer cancel()
			waitForPostgresBlock(t, ctx, f.d, blocker, done)
			started := awaitIntegrationResult(t, ctx, entered)
			timer := time.NewTimer(time.Until(started.Add(time.Second + 10*time.Millisecond)))
			defer timer.Stop()
			<-timer.C
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			want := ErrServiceAccess
			if test.authority == "pair" && (test.action == "create-reply" || test.action == "replace-reply") && test.gate == "pair" {
				want = ErrServiceConflict
			}
			if !errors.Is(err, want) || !bytes.Equal(before, saved()) {
				t.Fatal("database wait revived authority or changed denied durable state", err)
			}
		})
	}
}

func TestIntegrationNativePeerPairAuthorizationCurrentStateAfterWait(t *testing.T) {
	for _, action := range []string{"create", "renew"} {
		for _, authority := range []string{"subject", "run", "relay"} {
			t.Run(action+"/"+authority, func(t *testing.T) {
				f := newNativePairFixture(t)
				r := f.request
				var pair NativePeerPair
				if action == "renew" {
					pair = f.create(t)
					r.Action, r.PreviousPairID, r.PreviousGeneration, r.RequestedAt = action, pair.ID, pair.DeliveryGeneration, f.now.Add(time.Second)
					f.sign(t, &r)
				}
				gate, err := f.d.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				var query string
				var id string
				want := ErrServiceAccess
				switch authority {
				case "subject":
					query, id = `UPDATE control.control_sessions SET revoked_at=created_at,revoked_by=identity_id WHERE id=$1`, f.visitor.Value(controlPrincipalKey{}).(ControlPrincipal).SessionID
					want = ErrVisitorPermission
				case "run":
					query, id = `UPDATE control.service_runs SET healthy=false WHERE id=$1`, r.ServiceRunID
				case "relay":
					query, id = `UPDATE control.relay_leases SET draining=true WHERE relay_id=$1`, r.ExpectedRelays[0].RelayLease.RelayID
				}
				if _, err := gate.Exec(t.Context(), query, id); err != nil {
					t.Fatal(err)
				}
				var before []byte
				if pair.ID != "" {
					before = nativePairSavedAuthority(t, f.d, pair.ID)
				}
				done, join := nativePairWorker(t, f.visitor, func(ctx context.Context) error {
					if action == "renew" {
						_, err := f.d.RenewNativePeerPair(ctx, r, r.RequestedAt)
						return err
					}
					_, err := f.d.PrepareNativePeerPair(ctx, r, f.now)
					return err
				})
				defer join()
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, want) {
					t.Fatal("signed request borrowed stale authority after a lock wait", err)
				}
				if pair.ID == "" {
					var count int
					if err := f.d.pool.QueryRow(ctx, `SELECT count(*) FROM control.native_peer_pairs WHERE service_run_id=$1`, r.ServiceRunID).Scan(&count); err != nil || count != 0 {
						t.Fatal("denied create persisted a pair", count, err)
					}
				} else {
					// the independently committed revocation changes parent/run state,
					// but authorization must not alter the saved pair itself.
					var old, current struct{ Pair map[string]any }
					if err := json.Unmarshal(before, &old); err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(nativePairSavedAuthority(t, f.d, pair.ID), &current); err != nil || !reflect.DeepEqual(old.Pair, current.Pair) {
						t.Fatal("denied renewal changed the durable pair", err)
					}
				}
			})
		}
	}
}
