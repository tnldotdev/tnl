package main

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/inspection"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisher"
)

func inspectionRoots(ctx context.Context, project string) (string, string, error) {
	worktree, err := projectconfig.ResolveWorktree(ctx, project)
	if err != nil {
		return "", "", fmt.Errorf("resolve inspection history checkout: %w", err)
	}
	return worktree.PrimaryCheckoutRoot(), projectconfig.SharedProjectIdentity(worktree, project), nil
}

func newInspectionRecorder(ctx context.Context, tunnel *clientstate.Tunnel, project, service string) (*clientstate.InspectionRecorder, error) {
	primary, shared, err := inspectionRoots(ctx, project)
	if err != nil {
		return nil, err
	}
	policy := inspection.Policy{Retention: inspection.DefaultRetention, MaxBytes: inspection.DefaultMaxBytes}
	return tunnel.NewInspectionRecorder(primary, project, shared, service, policy), nil
}

func httpObservation(recorder *clientstate.InspectionRecorder) func(publisher.RequestObservation) {
	return func(event publisher.RequestObservation) {
		var detail json.RawMessage
		if event.Detail != nil {
			detail, _ = json.Marshal(event.Detail)
		}
		recorder.Observe(clientstate.InspectionRecord{
			ReceivedAt: event.ReceivedAt, Method: event.Method, Path: event.Path,
			Status: event.Status, DurationMS: event.Duration.Milliseconds(), Origin: event.Origin,
			CaptureMode: event.CaptureMode, Detail: detail,
		})
	}
}
