package main

import (
	"context"
	"fmt"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
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

func newInspectionRecorder(ctx context.Context, tunnel *clientstate.Tunnel, project, service string, mode config.InspectionMode) (*clientstate.InspectionRecorder, error) {
	if mode == config.InspectionNone {
		return nil, nil
	}
	primary, shared, err := inspectionRoots(ctx, project)
	if err != nil {
		return nil, err
	}
	policy := inspection.Policy{Retention: inspection.DefaultRetention, MaxBytes: inspection.DefaultMaxBytes}
	return tunnel.NewInspectionRecorder(primary, project, shared, service, policy), nil
}

func httpObservation(recorder *clientstate.InspectionRecorder) func(publisher.RequestObservation) {
	if recorder == nil {
		return nil
	}
	return func(event publisher.RequestObservation) {
		recorder.Observe(clientstate.InspectionRecord{
			ReceivedAt: event.ReceivedAt, Method: event.Method, Path: event.Path,
			Status: event.Status, DurationMS: event.Duration.Milliseconds(), Origin: event.Origin,
		})
	}
}
