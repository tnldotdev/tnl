package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

func sdkCapacityScope(f *sdkFixture, name string) SDKOptions {
	options := f.options
	options.Directory = filepath.Join(options.Directory, name)
	return options
}

func TestConnectionSDKExactCloseReleasesActiveCapacity(t *testing.T) {
	f := newSDKFixture(t, false)
	var waiters []SDKOptions
	for i := range 31 {
		options := sdkCapacityScope(f, "closed-"+strconv.Itoa(i))
		prepared, err := f.operations.selectSDK(t.Context(), options, "")
		if err != nil {
			t.Fatal("could not start owner before exact close", i, err)
		}
		options.RequestedAt = time.Now().Format(time.RFC3339Nano)
		waiters = append(waiters, options)
		if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, Handle: prepared.Owner.ConnectionHandle}); err != nil {
			t.Fatal("exact close did not join owner", i, err)
		}
		if !f.owners[prepared.Owner.ConnectionHandle].closed {
			t.Fatal("exact close returned before releasing native resources", i)
		}
	}
	completed := map[string]sdkOwnerRecord{}
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
		if len(r.Owners) != 31 {
			t.Errorf("exact close retained %d records, want 31 close fences", len(r.Owners))
		}
		for key, record := range r.Owners {
			if record.Owner.ConnectionHandle != "" || record.Failure != failure.ConnectionExpired || record.FinishedAt.IsZero() || record.ClosedAt.IsZero() {
				t.Error("exact close did not leave a completed close fence", key)
			}
			completed[key] = record
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	liveOptions := sdkCapacityScope(f, "live")
	live, err := f.operations.selectSDK(t.Context(), liveOptions, "")
	if err != nil {
		t.Fatal("could not start the one live owner", err)
	}
	// these 32 records own only one live resource. admitting another owner must
	// not require dropping any of the recent close fences to make room.
	next, err := f.operations.selectSDK(t.Context(), sdkCapacityScope(f, "next"), "")
	if err != nil {
		t.Fatal("31 exact closes + 1 live owner blocked the next scope despite spare active capacity", err)
	}
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
		if len(r.Owners) != 33 {
			t.Errorf("registry has %d records, want 31 completed and 2 live", len(r.Owners))
		}
		for key, record := range completed {
			current, present := r.Owners[key]
			if !present || current.Owner.ConnectionHandle != "" || current.Failure != record.Failure || !current.FinishedAt.Equal(record.FinishedAt) || !current.ClosedAt.Equal(record.ClosedAt) {
				t.Error("active admission discarded or changed a recent close fence", key)
			}
		}
		return nil
	}); err != nil {
		t.Fatal("registry could not read back separate active and completed records", err)
	}
	for i, options := range waiters {
		if _, err := f.operations.selectSDK(t.Context(), options, ""); !errors.Is(err, connectorruntime.ErrExpired) {
			t.Error("active admission let a pre-close waiter restart its owner", i, err)
		}
	}
	warm, err := f.operations.selectSDK(t.Context(), liveOptions, "")
	if err != nil || warm.Owner.ConnectionHandle != live.Owner.ConnectionHandle {
		t.Fatal("closed scopes displaced the live peer", err)
	}
	if next.Owner.ConnectionHandle == live.Owner.ConnectionHandle || f.owners[next.Owner.ConnectionHandle].closed || f.owners[live.Owner.ConnectionHandle].closed || f.started != 33 || f.stopped != 31 {
		t.Fatal("capacity reuse restarted or stopped an unrelated owner", f.started, f.stopped)
	}
}

func TestConnectionSDKActiveCapacityIncludesStartingOwners(t *testing.T) {
	f := newSDKFixture(t, false)
	for i := range 31 {
		if _, err := f.operations.selectSDK(t.Context(), sdkCapacityScope(f, "live-"+strconv.Itoa(i)), ""); err != nil {
			t.Fatal(err)
		}
	}
	pending := sdkCapacityScope(f, "starting")
	entered, release := make(chan struct{}), make(chan struct{})
	start := f.operations.start
	f.operations.start = func(ctx context.Context, options OwnerStartOptions, request connectorruntime.StartRequest, accept func(connectorruntime.Status) error) error {
		if request.Context.Directory == pending.Directory {
			close(entered)
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
		return start(ctx, options, request, accept)
	}
	bounded, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	result, finished := make(chan error, 1), make(chan struct{})
	var once sync.Once
	defer func() { once.Do(func() { close(release) }); <-finished }()
	go func() {
		defer close(finished)
		_, err := f.operations.selectSDK(bounded, pending, "")
		result <- err
	}()
	select {
	case <-entered:
	case <-bounded.Done():
		t.Fatal("startup did not reach its reserved slot", bounded.Err())
	}
	// the reservation has no handle or failure yet, but it owns the final active
	// slot. counting only published handles would admit a 33rd native owner.
	if _, err := f.operations.selectSDK(t.Context(), sdkCapacityScope(f, "overflow"), ""); !errors.Is(err, connectorruntime.ErrUnavailable) {
		t.Error("pending startup did not consume active capacity", err)
	}
	once.Do(func() { close(release) })
	if err := <-result; err != nil {
		t.Fatal("reserved startup could not finish", err)
	}
	<-finished
	if f.started != 32 || f.stopped != 0 {
		t.Fatal("in-flight admission exceeded active capacity", f.started, f.stopped)
	}
}

func TestConnectionSDKActiveCapacityIncludesFailedCleanup(t *testing.T) {
	f := newSDKFixture(t, false)
	var selected connectorruntime.SDKOwner
	for i := range 32 {
		prepared, err := f.operations.selectSDK(t.Context(), sdkCapacityScope(f, "live-"+strconv.Itoa(i)), "")
		if err != nil {
			t.Fatal(err)
		}
		selected = prepared.Owner
	}
	cleanupFailure := errors.New("cleanup has not joined")
	f.operations.stop = func(context.Context, string) error { return cleanupFailure }
	if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: f.options.Registry, ParentPID: f.options.ParentPID, Handle: selected.ConnectionHandle}); !errors.Is(err, cleanupFailure) {
		t.Fatal("failed close lost its cleanup error", err)
	}
	if _, err := f.operations.selectSDK(t.Context(), sdkCapacityScope(f, "overflow"), ""); !errors.Is(err, connectorruntime.ErrUnavailable) {
		t.Fatal("failed cleanup released active capacity before joining", err)
	}
	if f.started != 32 || f.owners[selected.ConnectionHandle].closed {
		t.Fatal("failed cleanup lost its resource-bearing owner", f.started)
	}
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
		for _, record := range r.Owners {
			if record.Owner.ConnectionHandle == selected.ConnectionHandle && record.Failure != "" {
				return nil
			}
		}
		return errors.New("active capacity check discarded the failed cleanup capability")
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionSDKActiveCapacityAppliesToCompletedKeyRestart(t *testing.T) {
	f := newSDKFixture(t, false)
	options := sdkCapacityScope(f, "completed")
	first, err := f.operations.selectSDK(t.Context(), options, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, Handle: first.Owner.ConnectionHandle}); err != nil {
		t.Fatal(err)
	}
	var selected connectorruntime.SDKOwner
	for i := range 32 {
		prepared, err := f.operations.selectSDK(t.Context(), sdkCapacityScope(f, "live-"+strconv.Itoa(i)), "")
		if err != nil {
			t.Fatal(err)
		}
		selected = prepared.Owner
	}
	if _, err := f.operations.selectSDK(t.Context(), options, ""); !errors.Is(err, connectorruntime.ErrUnavailable) || f.started != 33 {
		t.Fatal("an existing completed key bypassed the active owner limit", err, f.started)
	}
	if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, Handle: selected.ConnectionHandle}); err != nil {
		t.Fatal(err)
	}
	current, err := f.operations.selectSDK(t.Context(), options, "")
	if err != nil || current.Owner.ConnectionHandle == first.Owner.ConnectionHandle || f.started != 34 || f.stopped != 2 {
		t.Fatal("joined peer did not permit one completed-key restart", err, f.started, f.stopped)
	}
}

func TestConnectionSDKCompletedRecordsHaveSeparateBound(t *testing.T) {
	for _, retained := range []bool{false, true} {
		name := "close fences"
		if retained {
			name = "retained startup failures"
		}
		t.Run(name, func(t *testing.T) {
			f := newSDKFixture(t, false)
			f.options.RetainStartFailure = retained
			options := sdkCapacityScope(f, "completed")
			first, err := f.operations.selectSDK(t.Context(), options, "")
			if err != nil {
				t.Fatal(err)
			}
			if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, Handle: first.Owner.ConnectionHandle}); err != nil {
				t.Fatal(err)
			}
			now := time.Now()
			record := sdkOwnerRecord{Failure: failure.ConnectionExpired, FinishedAt: now, ClosedAt: now}
			if retained {
				record = sdkOwnerRecord{Failure: failure.ConnectionHandleInvalid, FinishedAt: now.Add(-sdkRequestLifetime - time.Second), StartFailure: true}
			}
			if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
				for i := range 255 {
					r.Owners[sdkDigest("completed-"+strconv.Itoa(i))] = record
				}
				return nil
			}); err != nil {
				t.Fatal("could not retain 256 completed records independently of active capacity", err)
			}
			if _, err := f.operations.selectSDK(t.Context(), sdkCapacityScope(f, "overflow"), ""); !errors.Is(err, connectorruntime.ErrUnavailable) || f.started != 1 {
				t.Fatal("new key exceeded the completed-record bound", err, f.started)
			}
			if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
				if len(r.Owners) != 256 {
					t.Error("full bookkeeping discarded records to admit a new key", len(r.Owners))
				}
				for i := range 255 {
					current, present := r.Owners[sdkDigest("completed-"+strconv.Itoa(i))]
					if !present || current.Failure != record.Failure || current.StartFailure != record.StartFailure || !current.FinishedAt.Equal(record.FinishedAt) || !current.ClosedAt.Equal(record.ClosedAt) {
						t.Error("full bookkeeping changed a retained observation", i)
					}
				}
				return nil
			}); err != nil {
				t.Fatal("could not read the completed-record bound", err)
			}
			current, err := f.operations.selectSDK(t.Context(), options, "")
			if err != nil || current.Owner.ConnectionHandle == first.Owner.ConnectionHandle || f.started != 2 {
				t.Fatal("full bookkeeping blocked activation of an existing key", err, f.started)
			}
			warm, err := f.operations.selectSDK(t.Context(), options, "")
			if err != nil || warm.Owner.ConnectionHandle != current.Owner.ConnectionHandle || f.started != 2 {
				t.Fatal("full bookkeeping blocked the existing live owner", err, f.started)
			}
		})
	}
}

func TestConnectionSDKRegistryRejectsCapacityOverflow(t *testing.T) {
	for _, test := range []struct {
		name   string
		count  int
		active bool
	}{
		{name: "active owners", count: 33, active: true},
		{name: "total records", count: 257},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newSDKFixture(t, false)
			if err := sdkUpdate(t.Context(), f.options, func(*sdkRegistry) error { return nil }); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(f.options.Registry, "registry.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			owners := map[string]sdkOwnerRecord{}
			for i := range test.count {
				record := sdkOwnerRecord{}
				if !test.active {
					now := time.Now()
					record = sdkOwnerRecord{Failure: failure.ConnectionExpired, FinishedAt: now, ClosedAt: now}
				}
				owners[sdkDigest(strconv.Itoa(i))] = record
			}
			if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error { r.Owners = owners; return nil }); !errors.Is(err, connectorruntime.ErrInvalid) {
				t.Fatal("registry persisted a capacity overflow", err)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("rejected overflow changed the saved registry", err)
			}
			data, err := json.Marshal(sdkRegistry{Schema: 1, ParentPID: f.options.ParentPID, Owners: owners, Assertions: map[string]connectorruntime.AssertionVerification{}})
			if err != nil || len(data) > connectorruntime.MaxBytes {
				t.Fatal("capacity fixture exceeded the independent byte bound", err)
			}
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			called := false
			if err := sdkUpdate(t.Context(), f.options, func(*sdkRegistry) error { called = true; return nil }); !errors.Is(err, connectorruntime.ErrUnauthorized) || called {
				t.Fatal("registry accepted an on-disk capacity overflow", err, called)
			}
		})
	}
}
