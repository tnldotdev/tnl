package publisher

import (
	"context"
	"crypto/sha256"
	"net"
	"testing"
	"time"
)

func TestVisitorPolicyRevisionFencesCachedAndInflightDecisions(t *testing.T) {
	var cache visitorDecisionCache[bool]
	key := sha256.Sum256([]byte("company-session"))
	load := func(context.Context) (bool, time.Time, bool, error) {
		return true, time.Now().Add(time.Minute), true, nil
	}
	cache.invalidate(1)
	if value, err := cache.check(t.Context(), key, load); err != nil || !value {
		t.Fatal(value, err)
	}
	cache.invalidate(2)
	if value, err := cache.check(t.Context(), key, func(context.Context) (bool, time.Time, bool, error) { return false, time.Time{}, false, nil }); err != nil || value {
		t.Fatal("old company decision survived revision", value, err)
	}
	started, release := make(chan struct{}), make(chan struct{})
	result := make(chan error, 1)
	go func() {
		_, err := cache.check(t.Context(), key, func(context.Context) (bool, time.Time, bool, error) {
			close(started)
			<-release
			return true, time.Now().Add(time.Minute), true, nil
		})
		result <- err
	}()
	<-started
	cache.invalidate(3)
	close(release)
	if err := <-result; err == nil {
		t.Fatal("old in-flight company decision repopulated cache")
	}
	if value, err := cache.check(t.Context(), key, func(context.Context) (bool, time.Time, bool, error) { return false, time.Time{}, false, nil }); err != nil || value {
		t.Fatal("old in-flight access survived", value, err)
	}
}

func TestVisitorPolicyRevisionClosesStreamsWithoutStoppingPublisher(t *testing.T) {
	stream, peer := net.Pipe()
	defer stream.Close()
	defer peer.Close()
	route := &PublicURLServer{streams: map[net.Conn]struct{}{stream: {}}}
	route.invalidateVisitorPolicy(1)
	route.invalidateVisitorPolicy(2)
	if _, err := peer.Read(make([]byte, 1)); err == nil {
		t.Fatal("old visitor stream survived authority revision")
	}
	if route.closed || route.draining {
		t.Fatal("authority change stopped team-owned publisher")
	}
}
