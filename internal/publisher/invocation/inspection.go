package invocation

import (
	"context"
	"fmt"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
)

func InspectionRoots(ctx context.Context, project string) (string, string, error) {
	worktree, err := clientproject.ResolveWorktree(ctx, project)
	if err != nil {
		return "", "", fmt.Errorf("resolve inspection history checkout: %w", err)
	}
	return worktree.PrimaryCheckoutRoot(), clientproject.SharedProjectIdentity(worktree, project), nil
}

func NewInspectionRecorder(ctx context.Context, tunnel *clientstate.Tunnel, project, service string, mode config.InspectionMode, settings ...*config.Inspection) (*clientstate.InspectionRecorder, error) {
	if mode == config.InspectionNone {
		return nil, nil
	}
	primary, shared, err := InspectionRoots(ctx, project)
	if err != nil {
		return nil, err
	}
	var configured *config.Inspection
	if len(settings) != 0 {
		configured = settings[0]
	}
	selected := config.MergeInspection(configured, &config.Inspection{Mode: &mode})
	policy, err := config.ResolveInspection(selected, "http")
	if err != nil {
		return nil, err
	}
	return tunnel.NewInspectionRecorder(primary, project, shared, service, policy), nil
}

func SummaryObservation(recorder *clientstate.InspectionRecorder) inspection.Observer {
	if recorder == nil {
		return nil
	}
	return func(event inspection.Summary) {
		record := clientstate.InspectionRecordFromSummary(event)
		if event.Protocol == inspection.HTTP {
			record.Result = ""
		}
		recorder.Observe(record)
	}
}
