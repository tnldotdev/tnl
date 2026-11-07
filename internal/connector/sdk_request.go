package connector

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
	"golang.org/x/sys/unix"
)

// the caller reserves one private receipt before dispatch. it contains no input
// or identity selector, only the exact cleanup reference acquired by this call.
type sdkRequestRecord struct {
	Schema        int    `json:"schema"`
	ParentPID     int    `json:"parent_pid"`
	OwnerKey      string `json:"owner_key,omitempty"`
	OwnerHandle   string `json:"owner_handle,omitempty"`
	FailureHandle string `json:"failure_handle,omitempty"`
	Closed        bool   `json:"closed,omitempty"`
}

func sdkRequestPath(registry, path string) bool {
	name := filepath.Base(path)
	id := strings.TrimSuffix(strings.TrimPrefix(name, "request-"), ".json")
	_, err := hex.DecodeString(id)
	return path == filepath.Join(registry, name) && len(id) == 32 && err == nil && name == "request-"+id+".json"
}

func readSDKRequest(options SDKOptions) (sdkRequestRecord, error) {
	var record sdkRequestRecord
	if !sdkRequestPath(options.Registry, options.RequestHandle) {
		return record, connectorruntime.ErrInvalid
	}
	fd, err := unix.Open(options.RequestHandle, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return record, err
	}
	f := os.NewFile(uintptr(fd), options.RequestHandle)
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return record, err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Getuid()) || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || info.Size() > 4096 || connectorruntime.ReadJSON(f, &record) != nil || record.Schema != 1 || record.ParentPID != options.ParentPID {
		return record, connectorruntime.ErrUnauthorized
	}
	if record.OwnerHandle != "" && (filepath.Dir(filepath.Dir(record.OwnerHandle)) != options.Registry || filepath.Base(record.OwnerHandle) != "handle.json") {
		return record, connectorruntime.ErrUnauthorized
	}
	if record.OwnerKey != "" {
		if _, err := hex.DecodeString(record.OwnerKey); err != nil || len(record.OwnerKey) != 64 {
			return record, connectorruntime.ErrInvalid
		}
	}
	return record, nil
}

func writeSDKRequest(options SDKOptions, record sdkRequestRecord) error {
	data, err := json.Marshal(record)
	if err != nil || len(data) > 4096 {
		return connectorruntime.ErrInvalid
	}
	f, err := os.CreateTemp(options.Registry, filepath.Base(options.RequestHandle)+".write-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return err
	}
	return os.Rename(f.Name(), options.RequestHandle)
}

// selection holds this receipt's gate until it has stopped doing native work.
// a lost command releases the gate in the kernel; close can then fence late work.
func beginSDKRequest(ctx context.Context, options SDKOptions) (*filelock.Lock, error) {
	if options.RequestHandle == "" {
		return nil, nil
	}
	if !sdkRequestPath(options.Registry, options.RequestHandle) {
		return nil, connectorruntime.ErrInvalid
	}
	if _, err := readSDKRequest(options); err != nil {
		return nil, err
	}
	gate, err := filelock.AcquireContext(ctx, options.RequestHandle+".lock", os.Getuid())
	if err != nil {
		return nil, err
	}
	record, err := readSDKRequest(options)
	if err == nil && record.Closed {
		err = connectorruntime.ErrExpired
	}
	if err == nil && record.OwnerHandle != "" {
		// replay cannot select a replacement after a lost reply.
		err = sdkOwnerError(connectorruntime.ErrUnavailable, connectorruntime.Status{ConnectionHandle: record.OwnerHandle})
	}
	if err == nil && record.FailureHandle != "" {
		err = &sdkStartFailure{error: connectorruntime.ErrUnavailable, retained: true, handle: record.FailureHandle}
	}
	if err != nil {
		gate.Close()
		return nil, err
	}
	return gate, nil
}

// callers hold the request gate. record the planned child before it can run,
// and record adoption before returning an existing owner to preparation.
func bindSDKRequest(options SDKOptions, key, handle string) error {
	if options.RequestHandle == "" {
		return nil
	}
	record, err := readSDKRequest(options)
	if err != nil {
		return err
	}
	if record.Closed || record.OwnerKey != "" && record.OwnerKey != key || record.OwnerHandle != "" && record.OwnerHandle != handle {
		return connectorruntime.ErrExpired
	}
	record.OwnerKey, record.OwnerHandle = key, handle
	return writeSDKRequest(options, record)
}

func finishSDKRequest(options SDKOptions, result error) error {
	if options.RequestHandle == "" {
		return nil
	}
	var failed interface{ SDKFailureHandle() string }
	if !errors.As(result, &failed) || failed.SDKFailureHandle() == "" {
		return nil
	}
	record, err := readSDKRequest(options)
	if err != nil {
		return err
	}
	record.OwnerHandle, record.FailureHandle = "", failed.SDKFailureHandle()
	return writeSDKRequest(options, record)
}

func (o sdkOperations) closeSDKRequest(ctx context.Context, options SDKOptions) error {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if !sdkRequestPath(options.Registry, options.RequestHandle) {
		return connectorruntime.ErrInvalid
	}
	if _, err := readSDKRequest(options); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	gate, err := filelock.AcquireContext(ctx, options.RequestHandle+".lock", os.Getuid())
	if err != nil {
		return err
	}
	defer gate.Close()
	record, err := readSDKRequest(options)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	record.Closed = true
	if err := writeSDKRequest(options, record); err != nil {
		return err
	}
	if record.FailureHandle != "" {
		return closeSDKFailure(ctx, options, record.FailureHandle)
	}
	retire := func() error { return retireSDKRequestReservation(ctx, options, record.OwnerKey) }
	if record.OwnerHandle == "" {
		return retire()
	}
	// a registered or adopted owner uses the existing exact-reference close path.
	if err := o.closeSDK(ctx, SDKCloseOptions{Registry: options.Registry, ParentPID: options.ParentPID, Handle: record.OwnerHandle}); err != nil {
		return err
	}
	// a killed launcher may not have published its planned child to the registry.
	// the child's startup fence is checked after it holds its owner lifetime lock.
	// wait for that exact child to become stoppable, or prove its lifetime ended.
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Lstat(record.OwnerHandle); err == nil {
			if err := o.stop(ctx, record.OwnerHandle); err != nil {
				return err
			}
			return retire()
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, err := os.Stat(filepath.Dir(record.OwnerHandle)); errors.Is(err, os.ErrNotExist) {
			return retire()
		}
		if err := o.stopped(record.OwnerHandle); err == nil {
			return retire()
		}
		select {
		case <-ctx.Done():
			return context.Cause(ctx)
		case <-tick.C:
		}
	}
}

func retireSDKRequestReservation(ctx context.Context, options SDKOptions, key string) error {
	if key == "" {
		return nil
	}
	gate, err := filelock.AcquireContext(ctx, filepath.Join(options.Registry, "owner-"+key+".lock"), os.Getuid())
	if err != nil {
		return err
	}
	defer gate.Close()
	return sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		record := r.Owners[key]
		if record.RequestHandle == options.RequestHandle && record.Owner.ConnectionHandle == "" {
			r.Owners[key] = sdkOwnerRecord{Failure: failure.ConnectionExpired, FinishedAt: time.Now(), ClosedAt: time.Now()}
		}
		return nil
	})
}

func checkSDKRequestStartup(ctx context.Context, options SDKOptions, ownerHandle string) error {
	if options.RequestHandle == "" {
		return nil
	}
	// do not take the selection gate: the launcher holds it while awaiting ready.
	// atomic receipts plus the already-held owner lock fence close versus startup.
	record, err := readSDKRequest(options)
	if err != nil {
		return err
	}
	if record.Closed || record.OwnerHandle != ownerHandle {
		return connectorruntime.ErrExpired
	}
	return ctx.Err()
}
