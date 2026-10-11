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

func (flags tunnelFlags) inspectionPolicy() (inspection.Policy, error) {
	policy := inspection.Policy{Retention: flags.InspectionRetention, MaxBytes: inspection.DefaultMaxBytes}
	if policy.Retention == 0 {
		policy.Retention = inspection.DefaultRetention
	}
	if flags.InspectionMaxBytes != "" {
		size, err := config.ParseByteSize(flags.InspectionMaxBytes)
		if err != nil {
			return policy, fmt.Errorf("inspection max bytes: %w", err)
		}
		policy.MaxBytes = size.Value()
	}
	return policy, nil
}

func newInspectionRecorder(ctx context.Context, tunnel *clientstate.Tunnel, project, service string, flags tunnelFlags) (*clientstate.InspectionRecorder, error) {
	if flags.InspectionMode == config.InspectionNone {
		return nil, nil
	}
	primary, shared, err := inspectionRoots(ctx, project)
	if err != nil {
		return nil, err
	}
	policy, err := flags.inspectionPolicy()
	if err != nil {
		return nil, err
	}
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

func sqlObservation(recorder *clientstate.InspectionRecorder) func(publisher.DatabaseObservation) {
	if recorder == nil {
		return nil
	}
	return func(event publisher.DatabaseObservation) {
		recorder.Observe(clientstate.InspectionRecord{
			Protocol: event.Protocol, ReceivedAt: event.ReceivedAt, DurationMS: event.Duration.Milliseconds(),
			Origin:    "tnl",
			Operation: event.Operation, Result: event.Result, SQLState: event.SQLState, Rows: event.Rows,
			ResultSets: int64(event.ResultSets), MySQLErrorCode: int64(event.MySQLErrorCode),
		})
	}
}
