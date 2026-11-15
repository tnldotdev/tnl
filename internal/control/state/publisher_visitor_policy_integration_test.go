package state

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationVisitorPolicyPublisherReadsShareTeamGuard(t *testing.T) {
	for _, revoke := range []string{"identity", "grant"} {
		t.Run(revoke, func(t *testing.T) {
			f := newServicePublicationFixture(t)
			d, now := f.database, f.now
			scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
			if err := d.PrepareVisitorSigningKeys(t.Context(), testVisitorIssuer, now); err != nil {
				t.Fatal(err)
			}
			read := func(ctx context.Context) error {
				_, err := d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, now)
				return err
			}
			if err := read(t.Context()); err != nil {
				t.Fatal("live publisher policy read failed", err)
			}
			if revoke == "identity" {
				if err := d.RevokePublisherIdentity(t.Context(), f.service.TeamID, f.publisher.ID, f.publisher.CreatorID, now); err != nil {
					t.Fatal(err)
				}
			} else {
				if err := d.RevokePublisherGrant(t.Context(), f.service.TeamID, f.publisher.ID, f.publisher.GrantID, f.publisher.CreatorID, now); err != nil {
					t.Fatal(err)
				}
			}
			if err := read(t.Context()); !errors.Is(err, ErrServiceAccess) {
				t.Fatal("policy refresh accepted revoked publisher authority", err)
			}
		})
	}
}
