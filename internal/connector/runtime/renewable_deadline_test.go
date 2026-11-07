package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type renewableDeadlineBackend struct {
	fixtureBackend
	mu      sync.Mutex
	current time.Time
	changed chan struct{}
}

func (b *renewableDeadlineBackend) AuthorizationDeadline() (time.Time, <-chan struct{}) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.current, b.changed
}

func TestConnectionOwnerRefreshUpdatesExactHandleBeforeProofExpiry(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	original := time.Now().Add(2 * time.Second)
	b := &renewableDeadlineBackend{fixtureBackend: fixtureBackend{deadline: original}, current: original, changed: make(chan struct{}, 1)}
	life, cancel := context.WithCancel(t.Context())
	reader, writer := io.Pipe()
	defer reader.Close()
	done := make(chan error, 1)
	go func() { done <- Serve(life, scope, directory, "/test/tnl", b, writer) }()
	t.Cleanup(func() {
		cancel()
		_ = writer.Close()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(time.Second):
			t.Error("owner cleanup did not join")
		}
	})
	var initial Status
	if err := json.NewDecoder(reader).Decode(&initial); err != nil {
		t.Fatal(err)
	}
	before, err := ReadHandle(initial.ConnectionHandle)
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	b.current = original.Add(time.Minute)
	b.mu.Unlock()
	b.changed <- struct{}{}
	timer := time.NewTimer(time.Until(original.Add(20 * time.Millisecond)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal("test context ended before original proof expiry")
	}
	after, err := ReadHandle(initial.ConnectionHandle)
	if err != nil || !after.ExpiresAt.Equal(original.Add(time.Minute)) || after.Key != before.Key || after.URL != before.URL || after.ConfigDigest != before.ConfigDigest {
		t.Fatal("proof refresh replaced or failed to update the exact private handle", err)
	}
	var current Status
	request := Request{Schema: Schema, Directory: scope.Directory, ConfigDigest: scope.ConfigDigest}
	if err := Call(t.Context(), initial.ConnectionHandle, "status", request, &current); err != nil || !current.ExpiresAt.Equal(after.ExpiresAt) || current.PID != initial.PID {
		t.Fatal("original owner did not survive its initial proof deadline", err)
	}
}

func TestConnectionRenewableProofDeadlineKeepsMonotonicFence(t *testing.T) {
	now := time.Now()
	deadline := now.Add(time.Minute)
	for _, offset := range []time.Duration{-30 * time.Second, 30 * time.Second} {
		previous := deadline.Add(offset)
		next := previous.Add(time.Minute)
		advanced, err := renewedOwnerDeadline(now, deadline, previous, next, true)
		if err != nil || !advanced.Equal(deadline.Add(time.Minute)) {
			t.Fatal("verified proof did not advance by the authority's exact delta", err)
		}
		if _, err := renewedOwnerDeadline(deadline, deadline, previous, next, true); !errors.Is(err, ErrExpired) {
			t.Fatal("late proof revived an expired owner", err)
		}
	}
}

func TestConnectionOwnerDeadlineUpdateKeepsExactCapability(t *testing.T) {
	scope := fixtureScope(t)
	directory, err := NewDirectory(scope.Directory)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "handle.json")
	previous := Handle{Schema: Schema, URL: "http://127.0.0.1:12345", Key: strings.Repeat("a", 64), Directory: scope.Directory, ConfigDigest: scope.ConfigDigest, ExpiresAt: time.Now().Add(time.Hour), Executable: "/test/tnl"}
	if err := WriteHandle(path, previous); err != nil {
		t.Fatal(err)
	}
	next := previous
	next.ExpiresAt = previous.ExpiresAt.Add(time.Minute)
	foreign := next
	foreign.Key = strings.Repeat("b", 64)
	if err := updateHandle(path, previous, foreign); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("deadline update replaced its retained capability", err)
	}
	stale := previous
	stale.ExpiresAt = stale.ExpiresAt.Add(-time.Second)
	if err := updateHandle(path, stale, next); !errors.Is(err, ErrUnauthorized) {
		t.Fatal("stale reference updated a newer handle", err)
	}
	if err := updateHandle(path, previous, next); err != nil {
		t.Fatal(err)
	}
	current, err := ReadHandle(path)
	if err != nil || !sameHandleCapability(current, previous) || !current.ExpiresAt.Equal(next.ExpiresAt) {
		t.Fatal("deadline update lost exact owner state", err)
	}
}
