package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func peerRetirementPage(pair string, retired, observed, retained time.Time) controlv1.ConnectorPeerPairCandidates {
	return controlv1.ConnectorPeerPairCandidates{Items: []controlv1.ConnectorPeerPairCandidate{{
		PairId: pair, DeliveryGeneration: 1, Disposition: controlv1.ConnectorPeerPairDispositionRetired, OwnerRevision: 2,
		Retirement: &controlv1.ConnectorPeerPairRetirementObservation{RetiredAt: retired, ObservedAt: observed, RetainedUntil: retained},
	}}}
}

type retirementListCall struct {
	page chan controlv1.ConnectorPeerPairCandidates
}

type retirementPeerControl struct {
	list    chan retirementListCall
	deliver func(context.Context) (controlv1.ConnectorPeerPairDelivery, error)
	confirm func(context.Context) error
}

func (c *retirementPeerControl) ListConnectorPeerPairs(ctx context.Context, _, _, _ string, _ credentials.ServiceRunToken) (controlv1.ConnectorPeerPairCandidates, error) {
	call := retirementListCall{page: make(chan controlv1.ConnectorPeerPairCandidates)}
	select {
	case c.list <- call:
	case <-ctx.Done():
		return controlv1.ConnectorPeerPairCandidates{}, context.Cause(ctx)
	}
	select {
	case page := <-call.page:
		return page, nil
	case <-ctx.Done():
		return controlv1.ConnectorPeerPairCandidates{}, context.Cause(ctx)
	}
}

func (c *retirementPeerControl) DeliverConnectorPeerPair(ctx context.Context, _, _, _ string, _ int64, _ credentials.ServiceRunToken) (controlv1.ConnectorPeerPairDelivery, error) {
	return c.deliver(ctx)
}

func (c *retirementPeerControl) ConfirmConnectorPeerPairPrepared(ctx context.Context, _, _, _ string, _ controlv1.ConnectorPeerPairPrepared, _ credentials.ServiceRunToken) error {
	return c.confirm(ctx)
}

func TestConnectorPeerRetirementUnknownFencesActualReconciler(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, original, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		binding := original.bindingSnapshot()
		original.Close()
		b.mu.Lock()
		delete(b.connectorPeers, binding.pairID)
		b.mu.Unlock()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		control := &retirementPeerControl{list: make(chan retirementListCall),
			deliver: func(context.Context) (controlv1.ConnectorPeerPairDelivery, error) {
				t.Error("retired pair scheduled a delivery")
				return controlv1.ConnectorPeerPairDelivery{}, ErrPrivateStream
			},
		}
		done := make(chan error, 1)
		go func() { done <- b.ServeConnectorPeers(ctx, control, "run-token") }()
		call := <-control.list
		now := time.Now()
		call.page <- peerRetirementPage(binding.pairID, now, now, now.Add(time.Minute))
		next := <-control.list
		b.mu.Lock()
		fence := b.connectorPeers[binding.pairID]
		if fence == nil || !fence.unbound || !fence.ownerRetired || fence.packets != nil || fence.preparationDone != nil || len(fence.streams) != 0 || b.reservedStreams != 0 || b.connectorPending != 0 {
			b.mu.Unlock()
			t.Fatal("unknown retirement did not retain only a nonserving owner fence")
		}
		replay, until := fence.replayUntil, fence.retirementUntil
		b.mu.Unlock()
		positive := peerOwnerPage(original, now.Add(time.Second), now.Add(2*time.Minute))
		positive.Items[0].DeliveryGeneration = 100
		next.page <- positive
		next = <-control.list
		if _, err := b.BindPeer(ctx, binding); err == nil {
			t.Fatal("late positive binding bypassed unknown retirement")
		}
		if err := fence.Renew(binding); err == nil {
			t.Fatal("late renewal revived retirement")
		}
		next.page <- peerRetirementPage(binding.pairID, now, time.Now(), now.Add(time.Minute))
		<-control.list
		b.mu.Lock()
		if fence.replayUntil != replay || fence.retirementUntil.After(until) {
			b.mu.Unlock()
			t.Fatal("duplicate retirement extended its original bounds")
		}
		b.mu.Unlock()
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestConnectorPeerRetirementJoinsHeldDeliveryAndConfirmation(t *testing.T) {
	for _, boundary := range []string{"delivery", "confirmation", "capacity"} {
		t.Run(boundary, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				b, p, _, _, fixture := connectorPeerFixture(t, "127.0.0.1:1")
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				binding := p.bindingSnapshot()
				connectorRebindPacketPaths(t, ctx, b, binding)
				entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
				unblock := sync.OnceFunc(func() { close(release) })
				defer unblock()
				served := make(chan error, 1)
				go func() {
					served <- p.serve(ctx, func() error {
						if err := p.markReady(ctx); err != nil {
							return err
						}
						<-p.ctx.Done()
						return nil
					})
				}()
				<-p.ready
				defer func() { p.Close(); <-served }()
				hold := func(call context.Context) {
					close(entered)
					<-call.Done()
					close(canceled)
					<-release
				}
				control := &retirementPeerControl{list: make(chan retirementListCall)}
				control.deliver = func(call context.Context) (controlv1.ConnectorPeerPairDelivery, error) {
					if boundary != "confirmation" {
						hold(call)
					}
					d := fixture.delivery
					d.ObservedAt, d.ExpiresAt = time.Now(), time.Now().Add(time.Minute)
					return d, nil
				}
				control.confirm = func(call context.Context) error {
					if boundary == "confirmation" {
						hold(call)
					}
					return nil
				}
				if boundary == "capacity" {
					now := time.Now()
					for i := range maxConnectorPeerOwners - 1 {
						if err := b.observePeerOwners(now, peerRetirementPage(fmt.Sprintf("cpp_%022d", i), now, now, now.Add(time.Minute))); err != nil {
							t.Fatal(err)
						}
					}
				}
				done := make(chan error, 1)
				go func() { done <- b.ServeConnectorPeers(ctx, control, "run-token") }()
				call := <-control.list
				call.page <- peerOwnerPage(p, p.owner.observedAt, p.owner.authorityUntil)
				<-entered
				call = <-control.list
				now := time.Now()
				retiredPair := binding.pairID
				if boundary == "capacity" {
					retiredPair = "cpp_" + strings.Repeat("Z", 22)
				}
				call.page <- peerRetirementPage(retiredPair, now, now, now.Add(time.Minute))
				<-canceled
				synctest.Wait()
				b.mu.Lock()
				retired, joining, installed := p.ownerRetired || b.closed, p.preparationDone, p.installedUntil
				if boundary != "capacity" {
					b.prunePeerOwnersLocked(time.Now().Add(10 * time.Minute))
				}
				retained := b.connectorPeers[binding.pairID] == p
				b.mu.Unlock()
				if !retired || joining == nil || !retained || !installed.IsZero() {
					t.Fatal("retirement lost an entered preparation or installed its late response")
				}
				if err := p.stageBinding(nextPublisherBinding(binding)); err == nil {
					t.Fatal("late stage bypassed owner retirement")
				}
				select {
				case <-done:
					t.Fatal("reconciler returned before held control callback joined")
				default:
				}
				unblock()
				if boundary == "capacity" {
					if err := <-done; !errors.Is(err, errConnectorPeerOwnerCapacity) {
						t.Fatal("capacity failed before joining its held delivery or lost its error", err)
					}
					return
				}
				<-control.list
				b.mu.Lock()
				if p.preparationDone != nil || !p.installedUntil.IsZero() {
					b.mu.Unlock()
					t.Fatal("late callback recreated installation or escaped its join")
				}
				b.mu.Unlock()
				cancel()
				if err := <-done; err != nil {
					t.Fatal(err)
				}
			})
		})
	}
}

func TestConnectorPeerRetirementFencesQueuedUnboundPreparation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, original, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		binding := original.bindingSnapshot()
		original.Close()
		b.mu.Lock()
		delete(b.connectorPeers, binding.pairID)
		b.mu.Unlock()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		connectorRebindPacketPaths(t, ctx, b, binding)
		entered, release := make(chan struct{}, 5), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		control := &retirementPeerControl{list: make(chan retirementListCall)}
		control.deliver = func(context.Context) (controlv1.ConnectorPeerPairDelivery, error) {
			entered <- struct{}{}
			<-release
			return controlv1.ConnectorPeerPairDelivery{}, ErrPrivateStream
		}
		done := make(chan error, 1)
		go func() { done <- b.ServeConnectorPeers(ctx, control, "run-token") }()
		call := <-control.list
		page := controlv1.ConnectorPeerPairCandidates{Items: []controlv1.ConnectorPeerPairCandidate{}}
		for i := range 5 {
			page.Items = append(page.Items, controlv1.ConnectorPeerPairCandidate{
				PairId: fmt.Sprintf("cpp_%022d", i), DeliveryGeneration: 1, Disposition: controlv1.ConnectorPeerPairDispositionCandidate, OwnerRevision: 1,
			})
		}
		call.page <- page
		for range 4 {
			<-entered
		}
		call = <-control.list
		now := time.Now()
		pair := page.Items[4].PairId
		call.page <- peerRetirementPage(pair, now, now, now.Add(time.Minute))
		synctest.Wait()
		b.mu.Lock()
		p := b.connectorPeers[pair]
		fenced := p != nil && p.unbound && p.ownerRetired && p.preparationDone != nil
		b.mu.Unlock()
		if !fenced {
			t.Fatal("queued preparation was not registered on its exact owner before retirement")
		}
		unblock()
		<-control.list
		select {
		case <-entered:
			t.Fatal("retired queued preparation entered the delivery callback")
		default:
		}
		b.mu.Lock()
		joined := p.preparationDone == nil && p.packets == nil && b.connectorPeers[pair] == p
		b.mu.Unlock()
		if !joined {
			t.Fatal("queued retirement escaped its join or discarded its fence")
		}
		cancel()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
}

func TestConnectorPeerInvalidPageCannotPartiallyApplyRetirement(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		control := &retirementPeerControl{list: make(chan retirementListCall)}
		done := make(chan error, 1)
		go func() { done <- b.ServeConnectorPeers(t.Context(), control, "run-token") }()
		call := <-control.list
		now := time.Now()
		page := peerRetirementPage(p.identity.pairID, now, now, now.Add(time.Minute))
		page.Items = append(page.Items, page.Items[0])
		call.page <- page
		if err := <-done; err == nil {
			t.Fatal("malformed page did not fail reconciliation")
		}
		b.mu.Lock()
		defer b.mu.Unlock()
		if p.ownerRetired || p.ctx.Err() != nil {
			t.Fatal("invalid page partially applied its first retirement")
		}
	})
}

func TestConnectorPeerOmissionAndMissingAuthorityAreNotRetirement(t *testing.T) {
	b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
	now := time.Now()
	for _, page := range []controlv1.ConnectorPeerPairCandidates{
		{Items: []controlv1.ConnectorPeerPairCandidate{}},
		{Items: []controlv1.ConnectorPeerPairCandidate{{PairId: p.identity.pairID, DeliveryGeneration: p.highwater, Disposition: controlv1.ConnectorPeerPairDispositionCandidate, OwnerRevision: 1}}},
	} {
		if err := b.observePeerOwners(now, page); err != nil {
			t.Fatal(err)
		}
		b.mu.Lock()
		current := p.currentLocked() && !p.ownerRetired
		b.mu.Unlock()
		if !current {
			t.Fatal("omission or missing positive authority retired a retained owner")
		}
	}
}

func TestConnectorPeerRetirementJoinsOnlyExactOwnerAndKeepsSharedCarriers(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		binding := p.bindingSnapshot()
		connectorRebindPacketPaths(t, ctx, b, binding)
		siblingBinding := binding
		siblingBinding.pairID = "cpp_" + strings.Repeat("S", 22)
		sibling, err := b.BindPeer(ctx, siblingBinding)
		if err != nil {
			t.Fatal(err)
		}
		defer sibling.Close()
		entered, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		served := make(chan error, 1)
		go func() {
			served <- p.serve(ctx, func() error {
				close(entered)
				<-p.ctx.Done()
				close(canceled)
				<-release
				return nil
			})
		}()
		<-entered
		now := time.Now()
		retired := make(chan error, 1)
		go func() {
			retired <- b.observePeerOwners(now, peerRetirementPage(binding.pairID, now, now, now.Add(time.Minute)))
		}()
		<-canceled
		b.mu.Lock()
		siblingCurrent := sibling.currentLocked()
		slots := b.packetSlots
		b.mu.Unlock()
		if !siblingCurrent || sibling.ctx.Err() != nil {
			t.Fatal("exact retirement interrupted its sibling")
		}
		for _, slot := range slots {
			select {
			case <-slot.packets.Done():
				t.Fatal("exact retirement closed a shared publisher carrier")
			default:
			}
		}
		select {
		case <-retired:
			t.Fatal("retirement returned before its actual entered owner joined")
		default:
		}
		unblock()
		if err := <-retired; err != nil {
			t.Fatal(err)
		}
		if err := <-served; err != nil {
			t.Fatal(err)
		}
	})
}

func TestConnectorPeerRetirementPruningPreservesOriginalReplayAndPositiveBounds(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		binding := p.bindingSnapshot()
		p.Close()
		originalReplay := p.replayUntil
		now := time.Now()
		page := peerRetirementPage(binding.pairID, now, now, now.Add(time.Minute))
		if err := b.observePeerOwners(now, page); err != nil {
			t.Fatal(err)
		}
		time.Sleep(time.Second)
		if err := b.observePeerOwners(time.Now(), page); err != nil {
			t.Fatal(err)
		}
		if p.replayUntil != originalReplay {
			t.Fatal("duplicate retirement reanchored the original replay bound")
		}
		time.Sleep(time.Minute)
		b.mu.Lock()
		b.prunePeerOwnersLocked(time.Now())
		retained := b.connectorPeers[binding.pairID] == p
		b.mu.Unlock()
		if !retained {
			t.Fatal("retirement retention expiry discarded a still-live local replay fence")
		}
		time.Sleep(time.Until(originalReplay) + time.Millisecond)
		b.mu.Lock()
		b.prunePeerOwnersLocked(time.Now())
		pruned := b.connectorPeers[binding.pairID] == nil
		b.mu.Unlock()
		if !pruned {
			t.Fatal("fully joined and independently expired owner was not pruned")
		}
		if _, err := b.BindPeer(t.Context(), binding); err == nil {
			t.Fatal("old positive delivery reconstructed an owner after fence pruning")
		}
	})
}

func TestConnectorPeerRetirementCapacityFailsClosedWithoutEviction(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		b, p, _, _, _ := connectorPeerFixture(t, "127.0.0.1:1")
		binding := p.bindingSnapshot()
		now := time.Now()
		for i := range maxConnectorPeerOwners - 1 {
			id := fmt.Sprintf("cpp_%022d", i)
			if err := b.observePeerOwners(now, peerRetirementPage(id, now, now, now.Add(time.Minute))); err != nil {
				t.Fatal(err)
			}
		}
		unknown := "cpp_" + strings.Repeat("Z", 22)
		if err := b.observePeerOwners(now, peerRetirementPage(unknown, now, now, now.Add(time.Minute))); !errors.Is(err, errConnectorPeerOwnerCapacity) {
			t.Fatal("capacity did not return its actual fail-closed error", err)
		}
		b.mu.Lock()
		fenced, count := b.closed, len(b.connectorPeers)
		b.mu.Unlock()
		if !fenced || count != maxConnectorPeerOwners {
			t.Fatal("capacity evicted an owner fence or left installation open", fenced, count)
		}
		if _, err := b.BindPeer(t.Context(), binding); err == nil {
			t.Fatal("capacity failure allowed a late binding")
		}
	})
}

func TestConnectorPeerCandidateDispositionValidation(t *testing.T) {
	now := time.Now()
	id := "cpp_" + strings.Repeat("A", 22)
	for _, test := range []struct {
		name string
		edit func(*controlv1.ConnectorPeerPairCandidates)
	}{
		{"unknown disposition", func(p *controlv1.ConnectorPeerPairCandidates) { p.Items[0].Disposition = "other" }},
		{"wrong retirement revision", func(p *controlv1.ConnectorPeerPairCandidates) { p.Items[0].OwnerRevision = 1 }},
		{"missing retirement", func(p *controlv1.ConnectorPeerPairCandidates) { p.Items[0].Retirement = nil }},
		{"contradictory authority", func(p *controlv1.ConnectorPeerPairCandidates) {
			p.Items[0].OwnerAuthority = &controlv1.ConnectorPeerPairOwnerAuthority{ObservedAt: now, ExpiresAt: now.Add(time.Minute)}
		}},
		{"zero timestamp", func(p *controlv1.ConnectorPeerPairCandidates) { p.Items[0].Retirement.RetiredAt = time.Time{} }},
		{"future retirement", func(p *controlv1.ConnectorPeerPairCandidates) { p.Items[0].Retirement.RetiredAt = now.Add(time.Second) }},
		{"spent retention", func(p *controlv1.ConnectorPeerPairCandidates) { p.Items[0].Retirement.RetainedUntil = now }},
		{"unbounded retention", func(p *controlv1.ConnectorPeerPairCandidates) {
			p.Items[0].Retirement.RetainedUntil = now.Add(5*time.Minute + 6*time.Second)
		}},
		{"candidate with retirement", func(p *controlv1.ConnectorPeerPairCandidates) {
			p.Items[0].Disposition, p.Items[0].OwnerRevision = controlv1.ConnectorPeerPairDispositionCandidate, 1
		}},
		{"duplicate pair", func(p *controlv1.ConnectorPeerPairCandidates) { p.Items = append(p.Items, p.Items[0]) }},
		{"contradictory cursor", func(p *controlv1.ConnectorPeerPairCandidates) { p.NextAfter = &id }},
	} {
		t.Run(test.name, func(t *testing.T) {
			page := peerRetirementPage(id, now, now, now.Add(time.Minute))
			if !validPeerCandidates(page, "") {
				t.Fatal("valid canonical retirement rejected")
			}
			test.edit(&page)
			if validPeerCandidates(page, "") {
				t.Fatal("invalid page accepted")
			}
		})
	}
}
