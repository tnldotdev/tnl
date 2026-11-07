package state

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationVisitorPolicyPublisherReadsShareTeamGuard(t *testing.T) {
	for _, revoke := range []string{"identity", "grant"} {
		t.Run(revoke, func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "publisher_policy_team_guard")
			request := oidcRouteRequest(t, d, now)
			url := createTestPublicURL(t, d, request, now)
			registerCertificatePlanRelays(t, d, now)
			identity, private := reviewPublisher(t, d, url, request.ActingIdentityID, now)
			setup, err := d.CreatePublishRun(t.Context(), reviewRunRequest(t, d, identity, private, url, "policy-guard"), now, time.Hour, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			gate, err := d.pool.Begin(ctx)
			if err != nil {
				t.Fatal(err)
			}
			defer rollbackTestTransaction(t, gate)
			if _, err := controlstatedb.New(gate).LockLocalTeamForSession(ctx, url.TeamID); err != nil {
				t.Fatal(err)
			}
			scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: url.ID}
			read := func(ctx context.Context) error {
				_, err := d.ReadPublisherVisitorPolicy(ctx, scope, setup.PublishRunID, int64(setup.PublishRunNumber), setup.PublishRunToken.String(), 0, now)
				return err
			}
			call, stop := context.WithTimeout(ctx, time.Second)
			err = read(call)
			stop()
			if err != nil {
				t.Fatal("policy read serialized behind another read's shared team guard", err)
			}
			workers := newIntegrationWorkers(t, cancel)
			defer workers.stop()
			revoked := make(chan error, 1)
			workers.Go(func() {
				if revoke == "identity" {
					revoked <- d.RevokePublisherIdentity(ctx, url.TeamID, identity.ID, request.ActingIdentityID, now)
				} else {
					revoked <- d.RevokePublisherGrant(ctx, url.TeamID, identity.ID, identity.GrantID, request.ActingIdentityID, now)
				}
			})
			writer := waitForPostgresBlock(t, ctx, d, int32(gate.Conn().PgConn().PID()), revoked)
			refreshed := make(chan error, 1)
			workers.Go(func() { refreshed <- read(ctx) })
			waitForPostgresBlock(t, ctx, d, writer, refreshed)
			if err := gate.Commit(ctx); err != nil {
				t.Fatal(err)
			}
			if err := awaitIntegrationResult(t, ctx, revoked); err != nil {
				t.Fatal("revocation did not join after the read guard released", err)
			}
			if err := awaitIntegrationResult(t, ctx, refreshed); !errors.Is(err, ErrPublishRunCredential) {
				t.Fatal("queued policy refresh bypassed publisher revocation", err)
			}
			if err := read(ctx); !errors.Is(err, ErrPublishRunCredential) {
				t.Fatal("policy refresh accepted revoked publisher authority", err)
			}
		})
	}
}
