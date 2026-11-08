package connector

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
)

func reserveSDKRequest(t *testing.T, options SDKOptions) SDKOptions {
	t.Helper()
	file, err := os.CreateTemp(options.Registry, "receipt-")
	if err != nil {
		t.Fatal(err)
	}
	name := filepath.Base(file.Name())
	file.Close()
	os.Remove(file.Name())
	options.RequestHandle = filepath.Join(options.Registry, "request-"+sdkDigest(name)[:32]+".json")
	data, _ := json.Marshal(sdkRequestRecord{Schema: 1, ParentPID: options.ParentPID})
	if err := os.WriteFile(options.RequestHandle, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return options
}

func TestConnectionSDKRequestLostReplyCloseIsExactAndRetryable(t *testing.T) {
	f := newSDKFixture(t, true)
	peer, err := f.prepare(t.Context(), "other", "db")
	if err != nil {
		t.Fatal(err)
	}
	options := reserveSDKRequest(t, f.options)
	prepared, err := f.operations.selectSDK(t.Context(), options, "first")
	if err != nil {
		t.Fatal(err)
	}
	record, err := readSDKRequest(options)
	if err != nil || record.OwnerHandle != prepared.Owner.ConnectionHandle {
		t.Fatal("reply loss lost its exact owner", record, err)
	}
	closeOptions := SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, RequestHandle: options.RequestHandle}
	f.stopGate = make(chan struct{})
	bounded, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	err = f.operations.closeSDK(bounded, closeOptions)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("failed cleanup did not retain request", err)
	}
	if f.owners[prepared.Owner.ConnectionHandle].closed || f.owners[peer.Owner.ConnectionHandle].closed {
		t.Fatal("failed cleanup claimed joined or stopped peer")
	}
	f.stopGate = nil
	if err := f.operations.closeSDK(t.Context(), closeOptions); err != nil {
		t.Fatal(err)
	}
	if !f.owners[prepared.Owner.ConnectionHandle].closed || f.owners[peer.Owner.ConnectionHandle].closed {
		t.Fatal("request close did not join exactly its owner")
	}
	replacement, err := f.prepare(t.Context(), "first", "db")
	if err != nil || replacement.Owner.ConnectionHandle == prepared.Owner.ConnectionHandle {
		t.Fatal("fresh request did not replace joined owner", err)
	}
	if err := f.operations.closeSDK(t.Context(), closeOptions); err != nil || f.owners[replacement.Owner.ConnectionHandle].closed {
		t.Fatal("old request stopped replacement", err)
	}
	if _, err := f.operations.selectSDK(t.Context(), options, "first"); !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("closed request selected replacement", err)
	}
}

func TestConnectionSDKRequestAdoptionRetainsTheObservedOwner(t *testing.T) {
	f := newSDKFixture(t, true)
	first, err := f.prepare(t.Context(), "first", "db")
	if err != nil {
		t.Fatal(err)
	}
	options := reserveSDKRequest(t, f.options)
	selected, err := f.operations.selectSDK(t.Context(), options, "rotated")
	if err != nil || selected.Owner.ConnectionHandle != first.Owner.ConnectionHandle {
		t.Fatal("adoption replaced owner", err)
	}
	if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, RequestHandle: options.RequestHandle}); err != nil || !f.owners[first.Owner.ConnectionHandle].closed {
		t.Fatal("lost adopted reply did not join observed owner", err)
	}
}

func TestConnectionSDKRequestCloseWaitsForSelectionAndFencesLateStartup(t *testing.T) {
	f := newSDKFixture(t, false)
	options := reserveSDKRequest(t, f.options)
	gate, err := beginSDKRequest(t.Context(), options)
	if err != nil {
		t.Fatal(err)
	}
	closeOptions := SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, RequestHandle: options.RequestHandle}
	bounded, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	err = f.operations.closeSDK(bounded, closeOptions)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close passed an in-flight selection", err)
	}
	directory, err := connectorruntime.NewDirectory(options.Registry)
	if err != nil {
		t.Fatal(err)
	}
	handle := filepath.Join(directory, "handle.json")
	key := strings.Repeat("a", 64)
	if err := bindSDKRequest(options, key, handle); err != nil {
		t.Fatal(err)
	}
	if err := sdkUpdate(t.Context(), options, func(r *sdkRegistry) error {
		r.Owners[key] = sdkOwnerRecord{RequestHandle: options.RequestHandle}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	owner, err := filelock.Acquire(filepath.Join(directory, "owner.lock"), filelock.Nonblocking, os.Getuid())
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	gate.Close() // simulate the launcher dying after recording its planned child.
	bounded, cancel = context.WithTimeout(t.Context(), 20*time.Millisecond)
	err = f.operations.closeSDK(bounded, closeOptions)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("close reported success with a pending child", err)
	}
	if err := checkSDKRequestStartup(t.Context(), options, handle); !errors.Is(err, connectorruntime.ErrExpired) {
		t.Fatal("late child crossed its request close fence", err)
	}
	owner.Close()
	if err := f.operations.closeSDK(t.Context(), closeOptions); err != nil {
		t.Fatal("retry did not join ended startup", err)
	}
	if err := sdkUpdate(t.Context(), options, func(r *sdkRegistry) error {
		if r.activeOwners() != 0 {
			t.Fatal("joined startup kept its active reservation")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestConnectionSDKRequestReceiptBoundsAndOwnership(t *testing.T) {
	f := newSDKFixture(t, false)
	options := reserveSDKRequest(t, f.options)
	original, _ := os.ReadFile(options.RequestHandle)
	for _, data := range [][]byte{
		[]byte(strings.Repeat("x", 4097)),
		[]byte(`{"schema":1,"parent_pid":0}`),
		[]byte(`{"schema":1,"parent_pid":1,"unknown":true}`),
	} {
		if err := os.WriteFile(options.RequestHandle, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readSDKRequest(options); err == nil {
			t.Fatal("invalid receipt accepted")
		}
	}
	os.WriteFile(options.RequestHandle, original, 0o600)
	os.Chmod(options.RequestHandle, 0o644)
	if _, err := readSDKRequest(options); err == nil {
		t.Fatal("unprotected receipt accepted")
	}
	os.Chmod(options.RequestHandle, 0o600)
	outside := options
	outside.RequestHandle = filepath.Join(t.TempDir(), filepath.Base(options.RequestHandle))
	if _, err := beginSDKRequest(t.Context(), outside); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("receipt outside registry accepted", err)
	}
}

func TestConnectionSDKRequestCannotRetireAReplacementStartupReservation(t *testing.T) {
	f := newSDKFixture(t, false)
	old := reserveSDKRequest(t, f.options)
	replacement := reserveSDKRequest(t, f.options)
	key := strings.Repeat("a", 64)
	for _, request := range []SDKOptions{old, replacement} {
		if err := bindSDKRequest(request, key, ""); err != nil {
			t.Fatal(err)
		}
	}
	if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
		r.Owners[key] = sdkOwnerRecord{RequestHandle: replacement.RequestHandle}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, request := range []SDKOptions{old, replacement} {
		if err := f.operations.closeSDK(t.Context(), SDKCloseOptions{Registry: request.Registry, ParentPID: request.ParentPID, RequestHandle: request.RequestHandle}); err != nil {
			t.Fatal(err)
		}
		if err := sdkUpdate(t.Context(), f.options, func(r *sdkRegistry) error {
			want := 1
			if request.RequestHandle == replacement.RequestHandle {
				want = 0
			}
			if r.activeOwners() != want {
				t.Fatal("request retired another startup reservation", r.activeOwners(), want)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
}
