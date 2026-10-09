package authorityclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

type teamFeedbackPolicyResponse struct {
	RequireSignIn *bool `json:"require_sign_in"`
}

func (c *Client) GetTeamFeedbackPolicy(ctx context.Context, teamID string) (authorityv1.TeamFeedbackPolicy, error) {
	response, err := request[teamFeedbackPolicyResponse](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetTeamFeedbackPolicy(ctx, teamID, editors...)
	})
	if err != nil {
		return authorityv1.TeamFeedbackPolicy{}, err
	}
	if response.RequireSignIn == nil {
		return authorityv1.TeamFeedbackPolicy{}, failure.Wrap("read team feedback policy", failure.ServerResponseInvalid, errors.New("feedback policy response is missing require_sign_in"))
	}
	return authorityv1.TeamFeedbackPolicy{RequireSignIn: *response.RequireSignIn}, nil
}

func (c *Client) SetTeamFeedbackPolicy(ctx context.Context, teamID string, requireSignIn bool) (authorityv1.TeamFeedbackPolicy, error) {
	response, err := request[teamFeedbackPolicyResponse](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetTeamFeedbackPolicy(ctx, teamID, authorityv1.TeamFeedbackPolicy{RequireSignIn: requireSignIn}, editors...)
	})
	if err != nil {
		return authorityv1.TeamFeedbackPolicy{}, err
	}
	if response.RequireSignIn == nil || *response.RequireSignIn != requireSignIn {
		return authorityv1.TeamFeedbackPolicy{}, failure.Wrap("set team feedback policy", failure.ServerResponseInvalid, errors.New("feedback policy response does not match the requested require_sign_in"))
	}
	return authorityv1.TeamFeedbackPolicy{RequireSignIn: *response.RequireSignIn}, nil
}
