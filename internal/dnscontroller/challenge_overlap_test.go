package dnscontroller

import (
	"context"
	"crypto/sha256"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func TestChallengeManagerOverlappingReconciliations(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	oldDigest, newDigest := sha256.Sum256([]byte("old")), sha256.Sum256([]byte("new"))
	thirdDigest := sha256.Sum256([]byte("third"))
	snapshot := controlstate.DNSChallengeContext{
		PublicURLID: "public_url_old", TeamID: "team_1", DomainID: "domain_1", CanonicalDomain: "tunnels.example.test",
		AuthorizationID: "authorization_old", Identifier: "*.member.tunnels.example.test", State: "presenting",
		PresentationReference: "presentation_old", ChallengeDigest: oldDigest,
		Presentations: []controlstate.DNSChallengePresentation{{ChallengeDigest: oldDigest, Active: true}, {ChallengeDigest: newDigest, Active: true}},
	}
	var mu sync.Mutex
	store := &challengeStoreStub{getContext: func(_ context.Context, publicURLID, authorizationID string) (controlstate.DNSChallengeContext, error) {
		mu.Lock()
		defer mu.Unlock()
		copy := snapshot
		copy.PublicURLID = publicURLID
		copy.Presentations = slices.Clone(snapshot.Presentations)
		if authorizationID == "authorization_new" {
			copy.AuthorizationID, copy.PresentationReference = "authorization_new", "presentation_new"
			copy.State, copy.ChallengeDigest = "presenting", newDigest
		}
		return copy, nil
	}}
	firstStarted, releaseFirst := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseFirst) }) }
	defer release()
	var reconciliations atomic.Int32
	provider := &challengeProviderStub{reconcile: func(ctx context.Context, _ ChallengeRecord) (Zone, error) {
		if reconciliations.Add(1) == 1 {
			close(firstStarted)
			select {
			case <-releaseFirst:
			case <-ctx.Done():
				return Zone{}, ctx.Err()
			}
		}
		return Zone{}, nil
	}}
	manager, err := NewChallengeManager(store, provider, &challengeVerifierStub{}, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"})
	if err != nil {
		t.Fatal(err)
	}
	otherManager, err := NewChallengeManager(store, provider, &challengeVerifierStub{}, Config{ManagedDomain: "tunnels.example.test", ManagedZoneID: "Z123"})
	if err != nil {
		t.Fatal(err)
	}
	firstDone, secondDone := make(chan error, 1), make(chan error, 1)
	var workers sync.WaitGroup
	t.Cleanup(func() { release(); cancel(); workers.Wait() })
	workers.Go(func() { firstDone <- manager.Present(ctx, "public_url_new", "authorization_new") })
	select {
	case <-firstStarted:
	case <-ctx.Done():
		t.Fatal("first reconciliation did not reach the provider")
	}
	mu.Lock()
	snapshot.State = "cleaning"
	snapshot.Presentations[0].Active = false
	mu.Unlock()
	lockRequested := make(chan struct{})
	store.lockRequested = func() { close(lockRequested) }
	workers.Go(func() { secondDone <- otherManager.Cleanup(ctx, "public_url_old", "authorization_old") })
	select {
	case <-lockRequested:
	case <-ctx.Done():
		t.Fatal("second reconciliation did not request the record lock")
	}
	mu.Lock()
	snapshot.Presentations = append(snapshot.Presentations, controlstate.DNSChallengePresentation{ChallengeDigest: thirdDigest, Active: true})
	mu.Unlock()
	release()
	for _, done := range []chan error{firstDone, secondDone} {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		}
	}
	provider.mu.Lock()
	got, calls := provider.record, provider.calls
	provider.mu.Unlock()
	wantDesired := []string{challengeTXTValue(newDigest), challengeTXTValue(thirdDigest)}
	slices.Sort(wantDesired)
	wantOwned := append([]string{challengeTXTValue(oldDigest)}, wantDesired...)
	slices.Sort(wantOwned)
	if calls != 2 || !slices.Equal(got.DesiredOwnedValues, wantDesired) || !slices.Equal(got.PreviouslyOwnedValues, wantOwned) {
		t.Fatalf("post-lock challenge record = %#v after %d reconciliations", got, calls)
	}
}
