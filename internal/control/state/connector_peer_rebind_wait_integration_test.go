package state

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"
)

func TestIntegrationConnectorRebindCannotCommitAfterAuthorityWait(t *testing.T) {
	for _, phase := range []string{"prepare", "activate"} {
		for _, boundary := range []string{"pair", "write", "deferred"} {
			t.Run(phase+"/"+boundary, func(t *testing.T) {
				f := newConnectorPairFixture(t)
				pair := f.create(t)
				request := connectorRebindRequest(t, f, pair, "prepare", f.now)
				at := f.now
				deadline := f.now.Add(time.Second)
				if phase == "activate" {
					state, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, request, f.now)
					if err != nil || state.Pending == nil {
						t.Fatal(err)
					}
					pending := *state.Pending
					connectorRebindClaimBoth(t, f, pending, connectorPairCompanySource, f.now)
					// claims record their completion time. the next synthetic
					// request must not move the control clock behind that fact.
					var checked time.Time
					if err := f.d.pool.QueryRow(t.Context(), `SELECT max(checked_at) FROM control.connector_peer_pair_leg_claims
						WHERE pair_id=$1 AND delivery_generation=$2`, pending.ID, pending.DeliveryGeneration).Scan(&checked); err != nil {
						t.Fatal(err)
					}
					at = checked.Add(time.Microsecond)
					deadline = at.Add(time.Second)
					connectorRebindReport(t, f, pending, "installed", at)
					connectorRebindReport(t, f, pending, "proved", at)
					request.Proof.Phase, request.Proof.ExpectedGeneration, request.Proof.ExpectedRelays = phase, pending.DeliveryGeneration, nil
					request.Proof.BindingChallenge, request.Proof.PathProofs = pending.BindingChallenge, connectorRebindProofs(t, pending, 0)
					request.Proof.RequestedAt = at
					request = signConnectorRebind(t, f, request.Proof)
					if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.connector_peer_pending_bindings SET pending_until=$2 WHERE pair_id=$1`, pair.ID, deadline); err != nil {
						t.Fatal(err)
					}
				} else if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.connector_peer_pairs SET expires_at=$2 WHERE id=$1`, pair.ID, deadline); err != nil {
					t.Fatal(err)
				}
				before := connectorPairSavedAuthority(t, f.d, pair.ID)
				gate, err := f.d.pool.Begin(t.Context())
				if err != nil {
					t.Fatal(err)
				}
				defer rollbackTestTransaction(t, gate)
				if boundary == "pair" {
					_, err = gate.Exec(t.Context(), `SELECT id FROM control.connector_peer_pairs WHERE id=$1 FOR UPDATE`, pair.ID)
				} else {
					_, err = gate.Exec(t.Context(), `SELECT pg_advisory_xact_lock(7347)`)
					if err == nil {
						table, operation := "connector_peer_pending_bindings", "INSERT"
						if phase == "activate" {
							table, operation = "connector_peer_pairs", "UPDATE"
						}
						trigger := "CREATE TRIGGER rebind_wait BEFORE " + operation + " ON control." + table
						if boundary == "deferred" {
							trigger = "CREATE CONSTRAINT TRIGGER rebind_wait AFTER " + operation + " ON control." + table + " DEFERRABLE INITIALLY DEFERRED"
						}
						_, err = f.d.pool.Exec(t.Context(), `CREATE FUNCTION control.rebind_wait() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN PERFORM pg_advisory_xact_lock(7347); RETURN NEW; END $$; `+trigger+` FOR EACH ROW EXECUTE FUNCTION control.rebind_wait()`)
					}
				}
				if err != nil {
					t.Fatal(err)
				}
				entered := make(chan time.Time, 1)
				done, join := connectorPairWorker(t, f.visitor, func(ctx context.Context) error {
					entered <- time.Now()
					_, err := f.d.RebindConnectorPeerPair(ctx, pair.ServiceID, pair.ID, request, at)
					return err
				})
				defer join()
				ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
				defer cancel()
				waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
				started := awaitIntegrationResult(t, ctx, entered)
				timer := time.NewTimer(time.Until(started.Add(time.Second + 10*time.Millisecond)))
				defer timer.Stop()
				<-timer.C
				if err := gate.Commit(ctx); err != nil {
					t.Fatal(err)
				}
				want := ErrServiceAccess
				if phase == "activate" && boundary == "pair" {
					want = ErrServiceConflict
				}
				if err := awaitIntegrationResult(t, ctx, done); !errors.Is(err, want) {
					t.Fatal("rebind spent authority while blocked", err)
				}
				if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
					t.Fatal("expired rebind changed the retained owner or pending evidence")
				}
			})
		}
	}
}

func TestIntegrationConnectorRebindOwnerRenewalIndependentOfMissingRelays(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	for _, relay := range pair.Relays {
		if _, err := f.d.DisconnectServicePublisherConnection(t.Context(), relay.PublisherConnectionID, pair.ServiceRunID, pair.RunNumber, relay.AssignmentRevision, relay.RelayLease, f.now); err != nil {
			t.Fatal(err)
		}
	}
	var state string
	if err := f.d.pool.QueryRow(t.Context(), `SELECT state FROM control.service_runs WHERE id=$1`, pair.ServiceRunID).Scan(&state); err != nil || state != "starting" {
		t.Fatal("fixture did not lose both ready connections", state, err)
	}
	if _, err := f.d.HeartbeatServiceRun(t.Context(), pair.ServiceID, pair.ServiceRunID, f.run.Token, f.now.Add(time.Second), ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
		t.Fatal(err)
	}
	renew := f.request
	renew.Action, renew.PreviousPairID, renew.PreviousGeneration, renew.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, f.now.Add(time.Second)
	f.sign(t, &renew)
	current, err := f.d.RenewConnectorPeerPair(f.visitor, "https://control.example.test", renew, renew.RequestedAt)
	if err != nil || current.ID != pair.ID || current.Relays != pair.Relays || current.SessionKey != pair.SessionKey || !current.ExpiresAt.After(pair.ExpiresAt) {
		t.Fatal("temporary relay loss ended owner authority or changed its binding", err)
	}
	inspect := connectorRebindRequest(t, f, current, "inspect", renew.RequestedAt)
	observed, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, inspect, renew.RequestedAt)
	if err != nil || len(observed.ReadyRelays) != 0 || observed.Active == nil || observed.Active.BindingState != "suspended" {
		t.Fatal("inspect invented relay delivery authority during an outage", err)
	}
	if err := f.d.RevokeVisitorDevice(f.visitor, pair.Subject.IdentityID, pair.Subject.DeviceID, renew.RequestedAt); err != nil {
		t.Fatal(err)
	}
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	renew.RequestedAt = renew.RequestedAt.Add(time.Second)
	f.sign(t, &renew)
	if _, err := f.d.RenewConnectorPeerPair(f.visitor, "https://control.example.test", renew, renew.RequestedAt); err == nil || errors.Is(err, ErrConnectorPeerBindingStale) {
		t.Fatal("revocation during an outage became recoverable delivery loss", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("revoked renewal changed owner authority")
	}
}
