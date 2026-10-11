package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func requestRoots(ctx context.Context, project string) (string, string, error) {
	worktree, err := projectconfig.ResolveWorktree(ctx, project)
	if err != nil {
		return "", "", fmt.Errorf("resolve request history checkout: %w", err)
	}
	return worktree.PrimaryCheckoutRoot(), projectconfig.SharedProjectIdentity(worktree, project), nil
}

func newRequestRecorder(ctx context.Context, tunnel *clientstate.Tunnel, project, service string) (*clientstate.RequestRecorder, error) {
	primary, shared, err := requestRoots(ctx, project)
	if err != nil {
		return nil, err
	}
	return tunnel.NewRequestRecorder(primary, project, shared, service), nil
}

func requestObservation(recorder *clientstate.RequestRecorder) func(publisher.RequestObservation) {
	return func(event publisher.RequestObservation) {
		var detail json.RawMessage
		if event.Detail != nil {
			detail, _ = json.Marshal(event.Detail)
		}
		recorder.Observe(clientstate.RequestRecord{
			ReceivedAt: event.ReceivedAt, Method: event.Method, Path: event.Path,
			Status: event.Status, DurationMS: event.Duration.Milliseconds(), Origin: event.Origin,
			CaptureMode: string(event.CaptureMode), Detail: detail,
		})
	}
}

func postgresObservation(recorder *clientstate.RequestRecorder, mode config.RequestInspectionMode) func(publisher.DatabaseObservation) {
	return func(event publisher.DatabaseObservation) {
		var detail json.RawMessage
		if mode == config.RequestInspectionDetailed && event.Statement != "" {
			detail, _ = json.Marshal(struct {
				Statement string `json:"statement"`
				Truncated bool   `json:"truncated,omitempty"`
			}{event.Statement, event.StatementTruncated})
		}
		recorder.Observe(clientstate.RequestRecord{
			ServiceProtocol: controlv1.Postgres, ReceivedAt: event.ReceivedAt,
			DurationMS: event.Duration.Milliseconds(), Origin: "tnl", CaptureMode: string(mode), Detail: detail,
			DatabaseOperation: event.Operation, DatabaseResult: event.Result, SQLState: event.SQLState,
			DatabaseRows: event.Rows,
		})
	}
}
