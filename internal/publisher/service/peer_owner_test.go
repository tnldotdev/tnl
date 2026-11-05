package service

import (
	"testing"
	"testing/synctest"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func peerOwnerPage(p *PeerSession, observed, expires time.Time) controlv1.ConnectorPeerPairCandidates {
	return controlv1.ConnectorPeerPairCandidates{Items: []controlv1.ConnectorPeerPairCandidate{{PairId: p.identity.pairID, DeliveryGeneration: p.highwater,
		OwnerAuthority: &controlv1.ConnectorPeerPairOwnerAuthority{ObservedAt: observed, ExpiresAt: expires}}}}
}

func TestConnectorPeerOwnerObservationRetainsOnlyOwnerAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		original := p.bindingSnapshot()
		before := p.owner
		p.installedUntil = original.until
		pending := original
		pending.generation++
		pending.until = time.Now().Add(time.Second)
		p.pending, p.highwater = &pending, pending.generation
		p.seen["spent"] = struct{}{}
		time.Sleep(time.Second)
		started := time.Now()
		page := peerOwnerPage(p, before.observedAt.Add(time.Second), before.authorityUntil.Add(time.Minute))
		b.observePeerOwners(started, page)
		b.mu.Lock()
		if p.owner.until != started.Add(page.Items[0].OwnerAuthority.ExpiresAt.Sub(page.Items[0].OwnerAuthority.ObservedAt)) || p.bindingLocked() != original || p.pending != &pending || p.pending.until != pending.until || p.installedUntil != original.until || len(p.seen) != 1 {
			b.mu.Unlock()
			t.Fatal("owner observation changed delivery, installation, pending deadline, or replay history")
		}
		owner := p.owner
		b.mu.Unlock()
		// duplicate and unchanged absolute expiry spend time; neither reanchors
		// the existing expiry at the later request start.
		time.Sleep(time.Second)
		b.observePeerOwners(time.Now(), page)
		page.Items[0].OwnerAuthority.ObservedAt = page.Items[0].OwnerAuthority.ObservedAt.Add(time.Second)
		b.observePeerOwners(time.Now(), page)
		if p.owner.until != owner.until {
			t.Fatal("unchanged authority extended its local expiry")
		}
		page.Items[0].OwnerAuthority.ObservedAt = before.observedAt
		page.Items[0].OwnerAuthority.ExpiresAt = owner.authorityUntil.Add(time.Minute)
		b.observePeerOwners(time.Now(), page)
		if p.owner.until != owner.until {
			t.Fatal("old observation overrode current authority")
		}
		p.pending = nil
		time.Sleep(time.Until(original.until) + time.Millisecond)
		b.mu.Lock()
		current, delivery := p.currentLocked(), p.deliveryCurrentLocked()
		b.mu.Unlock()
		if !current || delivery {
			t.Fatal("delivery expiry either ended the owner or retained packet admission")
		}
		if err := p.Renew(original); err == nil {
			t.Fatal("owner observation revived an expired delivery")
		}
	})
}

func TestConnectorPeerOwnerObservationSpendsTransitAndCannotReviveExpiry(t *testing.T) {
	for _, boundary := range []string{"expired owner", "retired owner", "unregistered owner", "expired response", "invalid duration"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
				started := time.Now()
				page := peerOwnerPage(p, p.owner.observedAt.Add(time.Second), p.owner.authorityUntil.Add(time.Minute))
				switch boundary {
				case "expired owner":
					p.owner.until = started.Add(time.Second)
				case "retired owner":
					p.stop()
				case "unregistered owner":
					delete(b.connectorPeers, p.identity.pairID)
				case "expired response":
					page.Items[0].OwnerAuthority.ExpiresAt = page.Items[0].OwnerAuthority.ObservedAt.Add(time.Second)
				case "invalid duration":
					page.Items[0].OwnerAuthority.ExpiresAt = page.Items[0].OwnerAuthority.ObservedAt.Add(time.Hour)
				}
				before := p.owner
				time.Sleep(2 * time.Second)
				b.observePeerOwners(started, page)
				if p.owner != before {
					t.Fatal("invalid or late observation revived a local owner")
				}
			})
		})
	}
}

func TestConnectorPeerDeliveryRetryCannotReanchorUnchangedAuthority(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		_, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		original := p.bindingSnapshot()
		time.Sleep(time.Second)
		duplicate := original
		duplicate.until = duplicate.until.Add(time.Second)
		if err := p.Renew(duplicate); err != nil || p.bindingSnapshot() != original {
			t.Fatal("duplicate delivery moved its local expiry", err)
		}
		unchanged := duplicate
		unchanged.observedAt = unchanged.observedAt.Add(time.Second)
		if err := p.Renew(unchanged); err != nil || p.bindingSnapshot().until != original.until {
			t.Fatal("unchanged absolute expiry moved its local deadline", err)
		}
	})
}
