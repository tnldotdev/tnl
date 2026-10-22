package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/naming"
)

func ReadPrepared(ctx context.Context, path, service string) (connectorruntime.Prepared, error) {
	return connectionSnapshot(ctx, path, service, "prepared")
}

func Prepare(ctx context.Context, path, service string) (connectorruntime.Prepared, error) {
	return connectionSnapshot(ctx, path, service, "prepare")
}

func connectionSnapshot(ctx context.Context, path, service, operation string) (connectorruntime.Prepared, error) {
	if !naming.ValidServiceName(service) {
		return connectorruntime.Prepared{}, connectorruntime.ErrInvalid
	}
	timeout := 5 * time.Second
	if operation == "prepare" {
		timeout = 30 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	handle, err := connectorruntime.ReadHandle(path)
	if err != nil {
		return connectorruntime.Prepared{}, err
	}
	var prepared connectorruntime.Prepared
	if err := connectorruntime.Call(bounded, path, operation, connectorruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest, Service: service}, &prepared); err != nil {
		return connectorruntime.Prepared{}, err
	}
	if prepared.Schema != connectorruntime.Schema || prepared.Connection.Schema != connectorruntime.Schema {
		return connectorruntime.Prepared{}, connectorruntime.ErrInvalid
	}
	if !prepared.Connection.ExpiresAt.After(time.Now()) {
		return connectorruntime.Prepared{}, connectorruntime.ErrExpired
	}
	return prepared, nil
}

func Attach(ctx context.Context, path string, input io.Reader) (json.RawMessage, error) {
	h, err := connectorruntime.ReadHandle(path)
	if err != nil {
		return nil, err
	}
	var request struct {
		Schema    int    `json:"schema"`
		Assertion string `json:"assertion"`
	}
	if connectorruntime.ReadJSON(input, &request) != nil || request.Schema != 1 {
		return nil, connectorruntime.ErrInvalid
	}
	var attached json.RawMessage
	err = connectorruntime.Call(ctx, path, "attach", connectorruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest, Assertion: request.Assertion}, &attached)
	return attached, err
}

func Status(ctx context.Context, path string) (json.RawMessage, error) {
	h, err := connectorruntime.ReadHandle(path)
	if err != nil {
		return nil, err
	}
	var status json.RawMessage
	err = connectorruntime.Call(ctx, path, "status", connectorruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest}, &status)
	return status, err
}

func Stop(ctx context.Context, path string) error {
	h, err := connectorruntime.ReadHandle(path)
	if err != nil {
		if _, missing := os.Lstat(path); errors.Is(missing, os.ErrNotExist) || errors.Is(err, connectorruntime.ErrExpired) {
			if connectorruntime.OwnerStopped(path) == nil {
				return nil
			}
			return waitConnectionsStopped(ctx, path)
		}
		return err
	}
	var result json.RawMessage
	err = connectorruntime.Call(ctx, path, "stop", connectorruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest}, &result)
	if err != nil {
		if connectorruntime.OwnerStopped(path) == nil {
			return nil
		}
		return err
	}
	return waitConnectionsStopped(ctx, path)
}

// wait for joined drain/revocation, not merely the stop acknowledgement.
func waitConnectionsStopped(ctx context.Context, path string) error {
	deadline := time.NewTimer(20 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(25 * time.Millisecond)
	defer tick.Stop()
	for {
		if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
			return connectorruntime.ReadStopResult(path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return connectorruntime.ErrUnavailable
		case <-tick.C:
		}
	}
}
