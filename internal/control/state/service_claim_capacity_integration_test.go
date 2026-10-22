package state

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func privateClaimRun(t *testing.T, f publishRunFixture) ServiceRunState {
	t.Helper()
	d, now := f.database, f.now
	actor := oidcRouteRequest(t, d, now)
	s, err := d.CreateServiceAt(t.Context(), actor.TeamID, actor.ActingIdentityID, "claims", "claims", ServicePlacement{}, now, ServiceMetadata{Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	enrollment := publisherEnrollment(t, d, actor, PublisherScope{TeamID: actor.TeamID, Kind: "service", ServiceID: s.ID}, now)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := d.RedeemPublisherEnrollment(t.Context(), enrollment.Key, public, now)
	if err != nil {
		t.Fatal(err)
	}
	prepared, err := d.PrepareServiceRun(t.Context(), s.ID, publisher, "claims", now, ServiceMetadata{Protocol: "tcp", TrustRevision: 1})
	if err != nil {
		t.Fatal(err)
	}
	run, err := d.StartServiceRun(t.Context(), s.ID, prepared.RunID, prepared.RunNumber, publisher, now)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func TestIntegrationPrivateMixedProcessClaimCapacity(t *testing.T) {
	for _, order := range []string{"public-first", "private-first", "concurrent"} {
		t.Run(order, func(t *testing.T) {
			f := newPublishRunFixture(t)
			d, now := f.database, f.now
			run := privateClaimRun(t, f)
			public := sessionClaim(t, f)
			var slot ServiceRunAssignment
			for _, candidate := range run.Connections {
				if candidate.RelayServiceID == public.ConnectionAssignmentIdentity.RelayServiceID {
					slot = candidate
				}
			}
			if slot.PublisherConnectionID == "" {
				t.Fatal("fixtures did not share a relay service")
			}
			first := public.RelayLeaseIdentity
			service := f.leases[slot.RelayServiceID]
			processRun, err := opaqueid.New(opaqueid.RelayRunPrefix)
			if err != nil {
				t.Fatal(err)
			}
			second, err := d.RegisterRelay(t.Context(), RelayRegistration{RelayServiceID: slot.RelayServiceID, RelayID: "second-process", RelayRunID: processRun,
				RelayAddress: service.RelayAddress, TLSServerName: service.TLSServerName, InternalRelayAddress: "127.0.0.1:9449", ProtocolVersion: 1, ConnectionCapacity: 1, StreamCapacity: 8}, now, time.Minute)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = d.pool.Exec(t.Context(), `UPDATE control.relay_leases SET connection_capacity=1 WHERE relay_id=$1`, first.RelayID); err != nil {
				t.Fatal(err)
			}
			claimPrivate := func(ctx context.Context, lease RelayLeaseIdentity) error {
				_, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now)
				return err
			}
			claimPublic := func(ctx context.Context, lease RelayLeaseIdentity) error {
				request := public
				request.RelayLeaseIdentity = lease
				_, err := d.ClaimPublisherConnection(ctx, request, now)
				return err
			}
			claims := []func(context.Context, RelayLeaseIdentity) error{claimPublic, claimPrivate}
			if order == "private-first" {
				claims[0], claims[1] = claims[1], claims[0]
			}
			var results [2]error
			if order == "concurrent" {
				start := make(chan struct{})
				var wg sync.WaitGroup
				for i := range claims {
					wg.Go(func() { <-start; results[i] = claims[i](t.Context(), first) })
				}
				close(start)
				wg.Wait()
			} else {
				for i := range claims {
					results[i] = claims[i](t.Context(), first)
				}
			}
			winner, loser := 0, 1
			if results[0] != nil {
				winner, loser = 1, 0
			}
			if results[winner] != nil || !errors.Is(results[loser], ErrRelayConnectionCapacity) {
				t.Fatalf("capacity-1 process admitted mixed claims: public/private results %v", results)
			}
			if err := claims[winner](t.Context(), first); err != nil {
				t.Fatalf("exact committed claim replay consumed another capacity slot: %v", err)
			}
			if err := claims[loser](t.Context(), second.RelayLeaseIdentity); err != nil {
				t.Fatalf("free sibling process was treated as service-wide full: %v", err)
			}
			var count, processes int
			if err := d.pool.QueryRow(t.Context(), `SELECT count(*),count(DISTINCT connected_relay_id) FROM control.publisher_service_connection_slots WHERE connected_relay_id=ANY($1) AND state='connected' AND session_open`, []string{first.RelayID, second.RelayID}).Scan(&count, &processes); err != nil || count != 2 || processes != 2 {
				t.Fatalf("claims did not have two distinct process owners: connections=%d processes=%d %v", count, processes, err)
			}
		})
	}
}

func TestIntegrationPrivateClaimExpiredResponseRecovery(t *testing.T) {
	f := newPublishRunFixture(t)
	d, now, ctx := f.database, f.now, t.Context()
	run := privateClaimRun(t, f)
	for index, slot := range run.Connections {
		lease := f.leases[slot.RelayServiceID].RelayLeaseIdentity
		if _, err := d.ClaimServicePublisherConnection(ctx, slot.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, slot.Revision, slot.Credential, lease, now); err != nil {
			t.Fatal(err)
		}
		if index == 1 {
			if _, err := d.ReadyServicePublisherConnection(ctx, slot.PublisherConnectionID, run.RunID, run.RunNumber, slot.Revision, lease, now); err != nil {
				t.Fatal(err)
			}
		}
	}
	// simulate a live publisher renewing its run while every response for the
	// first slot is lost until its credential expires. the ready sibling's
	// credential expires too, but it still owns its existing tunnel.
	lost, sibling := run.Connections[0], run.Connections[1]
	for at := now.Add(30 * time.Second); at.Before(lost.CredentialExpiresAt); at = at.Add(30 * time.Second) {
		if _, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, at); err != nil {
			t.Fatal(err)
		}
	}
	later := lost.CredentialExpiresAt.Add(time.Second)
	recovered, err := d.HeartbeatServiceRun(ctx, run.ServiceID, run.RunID, run.Token, later)
	if err != nil {
		t.Fatal(err)
	}
	replacement := recovered.Connections[0]
	if replacement.PublisherConnectionID == lost.PublisherConnectionID || replacement.Revision != lost.Revision+1 || replacement.Credential == lost.Credential {
		t.Fatalf("expired connected claim with a live relay was not replaced: id=%s revision=%d state=%s", replacement.PublisherConnectionID, replacement.Revision, replacement.State)
	}
	if current := recovered.Connections[1]; current.PublisherConnectionID != sibling.PublisherConnectionID || current.Revision != sibling.Revision || current.Credential != sibling.Credential || current.State != "ready" {
		t.Fatal("expired connected claim recovery replaced the ready sibling")
	}
	lease := f.leases[replacement.RelayServiceID].RelayLeaseIdentity
	if _, err := d.ClaimServicePublisherConnection(ctx, replacement.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, replacement.Revision, lost.Credential, lease, later); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("old credential claimed replacement: %v", err)
	}
	if _, err := d.ClaimServicePublisherConnection(ctx, replacement.PublisherConnectionID, run.ServiceID, run.RunID, run.RunNumber, replacement.Revision, replacement.Credential, lease, later); err != nil {
		t.Fatal(err)
	}
	oldLease := f.leases[lost.RelayServiceID].RelayLeaseIdentity
	if _, err := d.ReadyServicePublisherConnection(ctx, lost.PublisherConnectionID, run.RunID, run.RunNumber, lost.Revision, oldLease, later); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("late old handshake became ready after replacement: %v", err)
	}
	if _, err := d.DisconnectServicePublisherConnection(ctx, lost.PublisherConnectionID, run.RunID, run.RunNumber, lost.Revision, oldLease, later); !errors.Is(err, ErrServiceAccess) {
		t.Fatalf("late old disconnect modified replacement: %v", err)
	}
	if _, err := d.ReadyServicePublisherConnection(ctx, replacement.PublisherConnectionID, run.RunID, run.RunNumber, replacement.Revision, lease, later); err != nil {
		t.Fatal(err)
	}
}
