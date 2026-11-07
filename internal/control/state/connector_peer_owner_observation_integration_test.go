package state

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"testing"
	"time"
)

func TestIntegrationConnectorRebindOwnerObservationDoesNotRenewDelivery(t *testing.T) {
	for _, pending := range []bool{false, true} {
		t.Run(map[bool]string{false: "active", true: "pending"}[pending], func(t *testing.T) {
			f := newConnectorPairFixture(t)
			pair := f.create(t)
			page, err := f.d.ListConnectorPeerPairs(t.Context(), pair.ServiceID, pair.ServiceRunID, "", f.run.Token, f.now)
			if err != nil || len(page.Items) != 1 || page.Items[0].OwnerAuthority != nil {
				t.Fatal("uninstalled hint acquired retained-owner authority", err)
			}
			f.now = f.now.Add(time.Second)
			for slot := range 2 {
				f.claim(t, pair, slot, f.now)
			}
			f.now = f.now.Add(time.Second)
			f.report(t, pair, pair.ExpiresAt, f.now)
			generation := pair.DeliveryGeneration
			if pending {
				request := connectorRebindRequest(t, f, pair, "prepare", f.now.Add(time.Second))
				state, err := f.d.RebindConnectorPeerPair(f.visitor, pair.ServiceID, pair.ID, request, request.Proof.RequestedAt)
				if err != nil || state.Pending == nil {
					t.Fatal(err)
				}
				generation = state.Pending.DeliveryGeneration
			}
			at := f.now.Add(2 * time.Second)
			for _, relay := range pair.Relays {
				if _, err := f.d.DisconnectServicePublisherConnection(t.Context(), relay.PublisherConnectionID, pair.ServiceRunID, pair.RunNumber, relay.AssignmentRevision, relay.RelayLease, at); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := f.d.HeartbeatServiceRun(t.Context(), pair.ServiceID, pair.ServiceRunID, f.run.Token, at, ServiceRunHealth{Healthy: true, StreamCapacity: 64}); err != nil {
				t.Fatal(err)
			}
			renew := f.request
			renew.Action, renew.PreviousPairID, renew.PreviousGeneration, renew.RequestedAt = "renew", pair.ID, pair.DeliveryGeneration, at
			f.sign(t, &renew)
			owner, err := f.d.RenewConnectorPeerPair(f.visitor, "https://control.example.test", renew, at)
			if err != nil {
				t.Fatal(err)
			}
			before := connectorPairSavedAuthority(t, f.d, pair.ID)
			page, err = f.d.ListConnectorPeerPairs(t.Context(), pair.ServiceID, pair.ServiceRunID, "", f.run.Token, at)
			if err != nil || len(page.Items) != 1 || page.Items[0].OwnerAuthority == nil || page.Items[0].DeliveryGeneration != generation {
				t.Fatal("missing relays hid an installed owner's current authority", err)
			}
			observation := page.Items[0].OwnerAuthority
			if !observation.ObservedAt.Equal(at) || !observation.ExpiresAt.Equal(owner.ExpiresAt) || !observation.ExpiresAt.After(pair.ExpiresAt) {
				t.Fatal("owner observation inherited the old delivery or pending deadline")
			}
			if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
				t.Fatal("listing renewed a claim, installation, proof, pending operation, or owner")
			}
			if err := f.d.RevokeVisitorDevice(f.visitor, pair.Subject.IdentityID, pair.Subject.DeviceID, at); err != nil {
				t.Fatal(err)
			}
			page, err = f.d.ListConnectorPeerPairs(t.Context(), pair.ServiceID, pair.ServiceRunID, "", f.run.Token, at.Add(time.Second))
			if err != nil || len(page.Items) != 1 || page.Items[0].OwnerAuthority != nil {
				t.Fatal("revoked subject retained owner authority in a publisher observation", err)
			}
		})
	}
}

func TestIntegrationConnectorRebindOwnerObservationRechecksExpiryAfterWait(t *testing.T) {
	f := newConnectorPairFixture(t)
	pair := f.create(t)
	f.now = f.now.Add(time.Second)
	for slot := range 2 {
		f.claim(t, pair, slot, f.now)
	}
	f.now = f.now.Add(time.Second)
	f.report(t, pair, pair.ExpiresAt, f.now)
	parent := f.visitor.Value(controlPrincipalKey{}).(ControlPrincipal)
	if _, err := f.d.pool.Exec(t.Context(), `UPDATE control.control_sessions SET access_expires_at=$2 WHERE id=$1`, parent.SessionID, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	gate, err := f.d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(t.Context(), `SELECT id FROM control.connector_peer_pairs WHERE id=$1 FOR UPDATE`, pair.ID); err != nil {
		t.Fatal(err)
	}
	before := connectorPairSavedAuthority(t, f.d, pair.ID)
	entered := make(chan time.Time, 1)
	var page ConnectorPeerPairCandidates
	done, join := connectorPairWorker(t, t.Context(), func(ctx context.Context) error {
		entered <- time.Now()
		var err error
		page, err = f.d.ListConnectorPeerPairs(ctx, pair.ServiceID, pair.ServiceRunID, "", f.run.Token, f.now)
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
	if err := awaitIntegrationResult(t, ctx, done); err != nil || len(page.Items) != 1 || page.Items[0].OwnerAuthority != nil {
		t.Fatal("publisher listing borrowed an expired parent's authority after waiting", err)
	}
	if !bytes.Equal(before, connectorPairSavedAuthority(t, f.d, pair.ID)) {
		t.Fatal("expired owner observation changed durable state")
	}
}

func TestIntegrationConnectorRebindOwnerObservationExpiryDoesNotRevokePublisher(t *testing.T) {
	for _, expiry := range []string{"owner", "publisher"} {
		t.Run(expiry, func(t *testing.T) {
			f := newConnectorPairFixture(t)
			pairs := []ConnectorPeerPair{f.create(t)}
			f.request.IdempotencyKey = "observations-sibling"
			f.sign(t, &f.request)
			pairs = append(pairs, f.create(t))
			sort.Slice(pairs, func(i, j int) bool { return pairs[i].ID < pairs[j].ID })
			for _, pair := range pairs {
				f.now = f.now.Add(time.Second)
				for slot := range 2 {
					f.claim(t, pair, slot, f.now)
				}
				f.now = f.now.Add(time.Second)
				f.report(t, pair, pair.ExpiresAt, f.now)
			}
			query, id := `UPDATE control.connector_peer_pairs SET expires_at=$2 WHERE id=$1`, pairs[0].ID
			if expiry == "publisher" {
				query, id = `UPDATE control.service_runs SET publisher_expires_at=$2 WHERE id=$1`, pairs[0].ServiceRunID
			}
			if _, err := f.d.pool.Exec(t.Context(), query, id, f.now.Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			before := [2][]byte{connectorPairSavedAuthority(t, f.d, pairs[0].ID), connectorPairSavedAuthority(t, f.d, pairs[1].ID)}
			gate, err := f.d.pool.Begin(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := gate.Exec(t.Context(), `SELECT id FROM control.connector_peer_pairs WHERE id=$1 FOR UPDATE`, pairs[1].ID); err != nil {
				t.Fatal(err)
			}
			entered := make(chan time.Time, 1)
			var page ConnectorPeerPairCandidates
			done, join := connectorPairWorker(t, t.Context(), func(ctx context.Context) error {
				entered <- time.Now()
				var err error
				page, err = f.d.ListConnectorPeerPairs(ctx, pairs[0].ServiceID, pairs[0].ServiceRunID, "", f.run.Token, f.now)
				return err
			})
			defer join()
			ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
			defer cancel()
			// the first owner was observed before listing waits for the second row.
			waitForPostgresBlock(t, ctx, f.d, int32(gate.Conn().PgConn().PID()), done)
			started := awaitIntegrationResult(t, ctx, entered)
			timer := time.NewTimer(time.Until(started.Add(time.Second + 10*time.Millisecond)))
			defer timer.Stop()
			<-timer.C
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			err = awaitIntegrationResult(t, ctx, done)
			if expiry == "publisher" {
				if !errors.Is(err, ErrServiceAccess) {
					t.Fatal("listing retained expired publisher authority", err)
				}
			} else {
				if err != nil || len(page.Items) != 2 {
					t.Fatal("one expired owner rejected the healthy publisher listing", err)
				}
				if page.Items[0].OwnerAuthority != nil || page.Items[1].OwnerAuthority == nil || page.Items[1].PairID != pairs[1].ID {
					t.Fatal("listing retained expired authority or discarded the healthy sibling")
				}
			}
			for index, pair := range pairs {
				if !bytes.Equal(before[index], connectorPairSavedAuthority(t, f.d, pair.ID)) {
					t.Fatal("read-only publisher listing changed durable authority")
				}
			}
		})
	}
}
