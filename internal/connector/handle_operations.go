package connector

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"

	connectionruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/naming"
)

func ReadPrepared(ctx context.Context, path, service string) (connectionruntime.Prepared, error) {
	return connectionSnapshot(ctx, path, service, "prepared")
}

func Prepare(ctx context.Context, path, service string) (connectionruntime.Prepared, error) {
	return connectionSnapshot(ctx, path, service, "prepare")
}

func connectionSnapshot(ctx context.Context, path, service, operation string) (connectionruntime.Prepared, error) {
	if !naming.ValidServiceName(service) {
		return connectionruntime.Prepared{}, connectionruntime.ErrInvalid
	}
	timeout := 5 * time.Second
	if operation == "prepare" {
		timeout = 30 * time.Second
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	handle, err := connectionruntime.ReadHandle(path)
	if err != nil {
		return connectionruntime.Prepared{}, err
	}
	var prepared connectionruntime.Prepared
	if err := connectionruntime.Call(bounded, path, operation, connectionruntime.Request{Schema: 1, Directory: handle.Directory, ConfigDigest: handle.ConfigDigest, Service: service}, &prepared); err != nil {
		return connectionruntime.Prepared{}, err
	}
	if prepared.Schema != connectionruntime.Schema || prepared.Connection.Schema != connectionruntime.Schema {
		return connectionruntime.Prepared{}, connectionruntime.ErrInvalid
	}
	if !prepared.Connection.ExpiresAt.After(time.Now()) {
		return connectionruntime.Prepared{}, connectionruntime.ErrExpired
	}
	return prepared, nil
}

func Attach(ctx context.Context, path string, input io.Reader) (json.RawMessage, error) {
	h, err := connectionruntime.ReadHandle(path)
	if err != nil {
		return nil, err
	}
	var request struct {
		Schema    int    `json:"schema"`
		Assertion string `json:"assertion"`
	}
	if connectionruntime.ReadJSON(input, &request) != nil || request.Schema != 1 {
		return nil, connectionruntime.ErrInvalid
	}
	var attached json.RawMessage
	err = connectionruntime.Call(ctx, path, "attach", connectionruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest, Assertion: request.Assertion}, &attached)
	return attached, err
}

func Status(ctx context.Context, path string) (json.RawMessage, error) {
	h, err := connectionruntime.ReadHandle(path)
	if err != nil {
		return nil, err
	}
	var status json.RawMessage
	err = connectionruntime.Call(ctx, path, "status", connectionruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest}, &status)
	return status, err
}

func Stop(ctx context.Context, path string) error {
	h, err := connectionruntime.ReadHandle(path)
	if err != nil {
		if _, missing := os.Lstat(path); errors.Is(missing, os.ErrNotExist) || errors.Is(err, connectionruntime.ErrExpired) {
			if connectionruntime.OwnerStopped(path) == nil {
				return nil
			}
			return waitConnectionsStopped(ctx, path)
		}
		return err
	}
	var result json.RawMessage
	err = connectionruntime.Call(ctx, path, "stop", connectionruntime.Request{Schema: 1, Directory: h.Directory, ConfigDigest: h.ConfigDigest}, &result)
	if err != nil {
		if connectionruntime.OwnerStopped(path) == nil {
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
			return connectionruntime.ReadStopResult(path)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return connectionruntime.ErrUnavailable
		case <-tick.C:
		}
	}
}
