package connector

import (
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/filelock"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/failure"
)

type SDKCloseOptions struct {
	Registry      string
	ParentPID     int
	Handle        string
	FailureHandle string
}

// CloseSDK joins only the native-selected owner or failed-start observation.
// old references cannot close a replacement or another identity in the registry.
func CloseSDK(ctx context.Context, options SDKCloseOptions) error {
	return nativeSDKOperations().closeSDK(ctx, options)
}

func (o sdkOperations) closeSDK(ctx context.Context, options SDKCloseOptions) error {
	if options.ParentPID <= 0 || connectorruntime.VerifyDirectory(options.Registry) != nil || (options.Handle == "") == (options.FailureHandle == "") {
		return connectorruntime.ErrInvalid
	}
	registry := SDKOptions{Registry: options.Registry, OwnerStartOptions: OwnerStartOptions{ParentPID: options.ParentPID}}
	if options.FailureHandle != "" {
		return closeSDKFailure(ctx, registry, options.FailureHandle)
	}
	if filepath.Dir(filepath.Dir(options.Handle)) != options.Registry || filepath.Base(options.Handle) != "handle.json" {
		return connectorruntime.ErrUnauthorized
	}
	var key string
	if err := sdkUpdate(ctx, registry, func(r *sdkRegistry) error {
		for candidate, record := range r.Owners {
			if record.Owner.ConnectionHandle == options.Handle {
				key = candidate
				break
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if key == "" {
		return nil
	}
	gate, err := filelock.AcquireContext(ctx, filepath.Join(options.Registry, "owner-"+key+".lock"), os.Getuid())
	if err != nil {
		return err
	}
	defer gate.Close()
	var selected sdkOwnerRecord
	if err := sdkUpdate(ctx, registry, func(r *sdkRegistry) error {
		record := r.Owners[key]
		if record.Owner.ConnectionHandle != options.Handle {
			return nil
		}
		record.Failure = failure.ConnectionExpired
		record.ClosedAt = time.Now()
		selected = record
		r.Owners[key] = record
		return nil
	}); err != nil {
		return err
	}
	if selected.Owner.ConnectionHandle == "" {
		return nil
	}
	// retain failed cleanup for retry. a successful join leaves a completed
	// failure that fences requests begun before close, but permits a fresh await.
	return o.sdkRetire(ctx, registry, key, selected)
}

func closeSDKFailure(ctx context.Context, options SDKOptions, handle string) error {
	parts := strings.Split(handle, ".")
	if len(parts) != 2 || len(parts[0]) != 64 || len(parts[1]) != 16 {
		return connectorruntime.ErrInvalid
	}
	if _, err := hex.DecodeString(parts[0] + parts[1]); err != nil {
		return connectorruntime.ErrInvalid
	}
	gate, err := filelock.AcquireContext(ctx, filepath.Join(options.Registry, "owner-"+parts[0]+".lock"), os.Getuid())
	if err != nil {
		return err
	}
	defer gate.Close()
	return sdkUpdate(ctx, options, func(r *sdkRegistry) error {
		record, exists := r.Owners[parts[0]]
		if !exists || sdkFailureHandle(parts[0], record.FinishedAt) != handle {
			return nil
		}
		if !record.StartFailure || record.Owner.ConnectionHandle != "" {
			return connectorruntime.ErrUnauthorized
		}
		now := time.Now()
		r.Owners[parts[0]] = sdkOwnerRecord{Failure: failure.ConnectionExpired, FinishedAt: now, ClosedAt: now}
		return nil
	})
}
