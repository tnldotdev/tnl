package authority

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/httpjson"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
)

func (c *Client) GetWorkloadApproval(ctx context.Context, team, intent string) (authorityv1.WorkloadApproval, error) {
	return c.workloadApproval(ctx, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetWorkloadApproval(ctx, team, intent, editors...)
	})
}

func (c *Client) ApproveWorkload(ctx context.Context, team, intent string, body authorityv1.WorkloadApprovalRequest) (authorityv1.WorkloadApproval, error) {
	return c.workloadApproval(ctx, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ApproveWorkload(ctx, team, intent, body, editors...)
	})
}

func (c *Client) workloadApproval(ctx context.Context, call authorityRequest) (result authorityv1.WorkloadApproval, err error) {
	payload, err := requestPayload(ctx, c, c.access.String(), call)
	if err != nil {
		return result, err
	}
	if err = httpjson.DecodeNonNullObject(payload, &result, "intent_key", "request", "machine", "selection", "created_at"); err != nil {
		return result, failure.Wrap("decode workload approval", failure.ServerResponseInvalid, err)
	}
	return result, nil
}
