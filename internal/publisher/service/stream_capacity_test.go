package service

import (
	"sync"
	"testing"

	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func TestPublisherStreamCapacityIsSharedAcrossRelaySlots(t *testing.T) {
	first := tunnelv1.ServicePublisherConnectionRef{PublisherConnectionID: "first", ConnectionSlot: 0}
	second := tunnelv1.ServicePublisherConnectionRef{PublisherConnectionID: "second", ConnectionSlot: 1}
	bound := &Bound{boundState: &boundState{assignments: map[string]tunnelv1.ServicePublisherConnectionRef{"first": first, "second": second}}, streamCapacity: 3}
	var workers sync.WaitGroup
	var mu sync.Mutex
	var held []func()
	for index := range 20 {
		workers.Go(func() {
			ref := first
			if index%2 != 0 {
				ref = second
			}
			if release, ok := bound.reserveStream(ref); ok {
				mu.Lock()
				held = append(held, release)
				mu.Unlock()
			}
		})
	}
	workers.Wait()
	if len(held) != 3 {
		t.Fatalf("two relay slots admitted %d streams against a capacity-3 run", len(held))
	}
	held[0]()
	replacement, ok := bound.reserveStream(second)
	if !ok {
		t.Fatal("released capacity did not become available")
	}
	held[0]()
	if _, ok := bound.reserveStream(first); ok {
		t.Fatal("duplicate release freed a replacement stream")
	}
	replacement()
	for _, release := range held[1:] {
		release()
	}
	bound.Invalidate()
	if _, ok := bound.reserveStream(first); ok {
		t.Fatal("closed run retained usable capacity")
	}
}
