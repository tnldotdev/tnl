package localpublisher

import (
	"context"
	"encoding/json"
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

func sqlObservation(recorder *clientstate.InspectionRecorder, mode config.InspectionMode) func(publisher.DatabaseObservation) {
	return func(event publisher.DatabaseObservation) {
		var detail json.RawMessage
		if mode == config.InspectionDetailed && event.Statement != "" {
			detail, _ = json.Marshal(struct {
				Statement string `json:"statement"`
				Truncated bool   `json:"truncated,omitempty"`
			}{event.Statement, event.StatementTruncated})
		}
		recorder.Observe(clientstate.InspectionRecord{
			Protocol: event.Protocol, ReceivedAt: event.ReceivedAt, DurationMS: event.Duration.Milliseconds(),
			Origin: "tnl", CaptureMode: mode, Detail: detail,
			Operation: event.Operation, Result: event.Result, SQLState: event.SQLState, Rows: event.Rows,
			ResultSets: int64(event.ResultSets), MySQLErrorCode: int64(event.MySQLErrorCode),
		})
	}
}
