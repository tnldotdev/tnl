package connector

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestConnectionSDKCloseFencesWaitersAndRetainsPeers(t *testing.T) {
	f := newSDKFixture(t, true)
	first, err := f.prepare(t.Context(), "first", "db")
	if err != nil {
		t.Fatal(err)
	}
	peer, err := f.prepare(t.Context(), "other", "db")
	if err != nil {
		t.Fatal(err)
	}
	requested := time.Now().Format(time.RFC3339Nano)
	closeOptions := SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID, Handle: first.Owner.ConnectionHandle}
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			if err := f.operations.closeSDK(t.Context(), closeOptions); err != nil {
				t.Error(err)
			}
		})
	}
	workers.Wait()
	if f.stopped != 1 || !f.owners[first.Owner.ConnectionHandle].closed || f.owners[peer.Owner.ConnectionHandle].closed {
		t.Fatal("close did not join exactly its selected owner")
	}
	options := f.options
	options.RequestedAt = requested
	if _, err := f.operations.selectSDK(t.Context(), options, "first"); Reason(err) != failure.ConnectionExpired {
		t.Fatal("pre-close waiter started a replacement", err)
	}
	if f.started != 2 {
		t.Fatal("stale preparation started native")
	}
	replacement, err := f.prepare(t.Context(), "first", "db")
	if err != nil || replacement.Owner.ConnectionHandle == first.Owner.ConnectionHandle {
		t.Fatal("fresh await did not replace joined owner", err)
	}
	if _, err := f.operations.selectSDK(t.Context(), options, "first"); Reason(err) != failure.ConnectionExpired {
		t.Fatal("pre-close waiter adopted the replacement", err)
	}
	options.RequestedAt = time.Now().Add(-sdkRequestLifetime - time.Second).Format(time.RFC3339Nano)
	if _, err := f.operations.selectSDK(t.Context(), options, "never-identified"); !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("request outlived the close-fence retention", err)
	}
	if err := f.operations.closeSDK(t.Context(), closeOptions); err != nil {
		t.Fatal("old close was not idempotent", err)
	}
	if f.stopped != 1 || f.owners[replacement.Owner.ConnectionHandle].closed {
		t.Fatal("old reference closed replacement")
	}
	closeOptions.Handle = filepath.Join(t.TempDir(), "handle.json")
	if err := f.operations.closeSDK(t.Context(), closeOptions); !errors.Is(err, connectorruntime.ErrUnauthorized) {
		t.Fatal("borrowed owner accepted", err)
	}
}

func TestConnectionSDKCloseRetainsFailedCleanupForRetry(t *testing.T) {
	f := newSDKFixture(t, true)
	first, err := f.prepare(t.Context(), "first", "db")
	if err != nil {
		t.Fatal(err)
	}
	options := SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID, Handle: first.Owner.ConnectionHandle}
	f.stopGate = make(chan struct{})
	bounded, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if err := f.operations.closeSDK(bounded, options); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("cleanup did not retain failed join", err)
	}
	if f.owners[first.Owner.ConnectionHandle].closed {
		t.Fatal("failed close claimed joined owner")
	}
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
		for _, record := range r.Owners {
			if record.Owner.ConnectionHandle == first.Owner.ConnectionHandle && record.Failure == failure.ConnectionExpired {
				return nil
			}
		}
		return errors.New("failed close lost its capability")
	}); err != nil {
		t.Fatal(err)
	}
	f.stopGate = nil
	if err := f.operations.closeSDK(t.Context(), options); err != nil {
		t.Fatal(err)
	}
	if !f.owners[first.Owner.ConnectionHandle].closed || f.stopped != 2 {
		t.Fatal("retry did not join retained owner")
	}
	if err := f.operations.closeSDK(t.Context(), options); err != nil || f.stopped != 2 {
		t.Fatal("joined close repeated cleanup", err)
	}
}

func TestConnectionSDKPreparationErrorRetainsExactCloseReference(t *testing.T) {
	f := newSDKFixture(t, true)
	f.prepareError = connectorruntime.ErrUnavailable
	_, err := f.prepare(t.Context(), "first", "db")
	var selected interface{ SDKOwnerHandle() string }
	if !errors.As(err, &selected) || selected.SDKOwnerHandle() == "" {
		t.Fatal("initial failure lost native cleanup reference", err)
	}
	file := selected.SDKOwnerHandle()
	if f.owners[file].closed {
		t.Fatal("preparation failure stopped a reusable owner")
	}
	if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID, Handle: file}); err != nil {
		t.Fatal(err)
	}
	if !f.owners[file].closed || f.stopped != 1 {
		t.Fatal("failure close did not join the exact owner")
	}
}
