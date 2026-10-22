package authorityclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func (c *Client) GetTeamFeedbackPolicy(ctx context.Context, teamID string) (authorityv1.TeamFeedbackPolicy, error) {
	return request[authorityv1.TeamFeedbackPolicy](ctx, c, func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetTeamFeedbackPolicy(ctx, teamID, e...)
	})
}
func (c *Client) SetTeamFeedbackPolicy(ctx context.Context, teamID string, policy authorityv1.TeamFeedbackPolicy) (authorityv1.TeamFeedbackPolicy, error) {
	return request[authorityv1.TeamFeedbackPolicy](ctx, c, func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetTeamFeedbackPolicy(ctx, teamID, policy, e...)
	})
}
func (c *Client) IssueControlBrowserHandoff(ctx context.Context, urlID string, refresh credentials.RefreshToken) (string, error) {
	result, err := request[struct {
		URL string `json:"url"`
	}](ctx, c, func(ctx context.Context, e ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueControlBrowserHandoff(ctx, authorityv1.IssueControlBrowserHandoffJSONRequestBody{PublicUrlId: urlID, RefreshToken: refresh.String()}, e...)
	})
	return result.URL, err
}
