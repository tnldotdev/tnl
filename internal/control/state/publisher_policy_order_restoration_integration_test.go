package state

import (
	"context"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationPublisherPolicyRestoredSharedReadAndQueuedRevocation(t *testing.T) {
	for _, revoke := range []string{"identity", "grant"} {
		t.Run(revoke, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			d, now := f.database, f.now
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			if err := d.PrepareVisitorSigningKeys(ctx, testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockLocalTeamForSession(ctx, f.service.TeamID); err != nil {
				t.Fatal(err)
			}
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
			read := func(call context.Context) error {
				_, err := d.ReadPublisherVisitorPolicy(call, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
				return err
			}
			call, stop := context.WithTimeout(ctx, time.Second)
			err = read(call)
			stop()
			if err != nil {
				t.Fatal("shared policy read did not progress within one second", err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			revoked, refreshed := make(chan error, 1), make(chan error, 1)
			workers.Go(func() {
				if revoke == "identity" {
					revoked <- d.RevokePublisherIdentity(ctx, f.service.TeamID, f.publisher.ID, f.publisher.CreatorID, now)
				} else {
					revoked <- d.RevokePublisherGrant(ctx, f.service.TeamID, f.publisher.ID, f.publisher.GrantID, f.publisher.CreatorID, now)
				}
			})
			writer := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), revoked)
			workers.Go(func() { refreshed <- read(ctx) })
			waitForPostgresBlock(t, ctx, d, writer, refreshed)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			revokeErr := awaitIntegrationResult(t, ctx, revoked)
			refreshErr := awaitIntegrationResult(t, ctx, refreshed)
			if revokeErr != nil {
				t.Error("queued publisher revocation failed after the shared guard released", revokeErr)
			}
			requireRestoredOnlyError(t, refreshErr, ErrServiceAccess)
			requireRestoredOnlyError(t, read(ctx), ErrServiceAccess)
		})
	}
}
