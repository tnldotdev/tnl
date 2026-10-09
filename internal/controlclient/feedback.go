package controlclient

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) ListFeedbackThreads(ctx context.Context, teamID string) ([]controlv1.FeedbackThreadSummary, uint64, error) {
	var threads []controlv1.FeedbackThreadSummary
	cursor := ""
	var snapshot uint64
	for {
		params := &controlv1.ListFeedbackThreadsParams{TeamId: teamID}
		if cursor != "" {
			params.Cursor = &cursor
		}
		page, err := requestWithAccess[controlv1.FeedbackThreadPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
			return c.api.ListFeedbackThreads(ctx, params, editors...)
		})
		if err != nil {
			return nil, 0, err
		}
		if cursor == "" {
			snapshot = uint64(page.EventCursor)
		}
		threads = append(threads, page.Threads...)
		if page.NextCursor == nil {
			return threads, snapshot, nil
		}
		if *page.NextCursor == cursor {
			return nil, 0, failure.Wrap("list feedback", failure.ServerResponseInvalid, errors.New("controlclient: repeated feedback cursor"))
		}
		cursor = *page.NextCursor
	}
}

func (c *Client) GetFeedbackThread(ctx context.Context, id string) (controlv1.FeedbackThread, error) {
	return requestWithAccess[controlv1.FeedbackThread](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetFeedbackThread(ctx, id, editors...)
	})
}

func (c *Client) ListFeedbackThreadEvents(ctx context.Context, id string, after uint64) (controlv1.FeedbackEventPage, error) {
	value := int64(after)
	params := &controlv1.ListFeedbackThreadEventsParams{AfterCursor: &value}
	return requestWithAccess[controlv1.FeedbackEventPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListFeedbackThreadEvents(ctx, id, params, editors...)
	})
}

func (c *Client) ListFeedbackEvents(ctx context.Context, teamID string, after uint64) (controlv1.FeedbackEventPage, error) {
	value := int64(after)
	params := &controlv1.ListFeedbackEventsParams{TeamId: teamID, AfterCursor: &value}
	return requestWithAccess[controlv1.FeedbackEventPage](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListFeedbackEvents(ctx, params, editors...)
	})
}

func (c *Client) AppendFeedbackEvent(ctx context.Context, id, key string, body controlv1.AppendFeedbackEventRequest) (controlv1.FeedbackEvent, error) {
	params := &controlv1.AppendFeedbackEventParams{IdempotencyKey: key}
	return requestWithAccess[controlv1.FeedbackEvent](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AppendFeedbackEvent(ctx, id, params, body, editors...)
	})
}

func (c *Client) CreatePublishRunPreview(ctx context.Context, runID string, version uint64, token credentials.PublishRunToken) (controlv1.Preview, error) {
	return request[controlv1.Preview](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePublishRunPreview(ctx, runID, controlv1.PublishRunVersionRequest{PublishRunNumber: int64(version)}, editors...)
	})
}

func (c *Client) CreateFeedbackReport(ctx context.Context, runID, key string, body controlv1.CreateFeedbackReportRequest, token credentials.PublishRunToken) (controlv1.FeedbackThread, error) {
	params := &controlv1.CreateFeedbackReportParams{IdempotencyKey: key}
	return request[controlv1.FeedbackThread](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateFeedbackReport(ctx, runID, params, body, editors...)
	})
}

func (c *Client) ListPreviewPageFeedback(ctx context.Context, runID string, body controlv1.PreviewPageFeedbackRequest, token credentials.PublishRunToken) (controlv1.FeedbackThreadPage, error) {
	return request[controlv1.FeedbackThreadPage](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListPreviewPageFeedback(ctx, runID, body, editors...)
	})
}

func (c *Client) GetFeedbackAccess(ctx context.Context, runID string, body controlv1.FeedbackAccessRequest, token credentials.PublishRunToken) (controlv1.FeedbackAccess, error) {
	response, err := request[struct {
		RequireSignIn *bool `json:"require_sign_in"`
	}](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetFeedbackAccess(ctx, runID, body, editors...)
	})
	if err != nil {
		return controlv1.FeedbackAccess{}, err
	}
	if response.RequireSignIn == nil {
		return controlv1.FeedbackAccess{}, failure.Wrap("read feedback access", failure.ServerResponseInvalid, errors.New("feedback access response is missing require_sign_in"))
	}
	return controlv1.FeedbackAccess{RequireSignIn: *response.RequireSignIn}, nil
}

func (c *Client) AppendReviewerFeedbackEvent(ctx context.Context, runID, id, key string, body controlv1.AppendReviewerFeedbackEventRequest, token credentials.PublishRunToken) (controlv1.FeedbackEvent, error) {
	params := &controlv1.AppendReviewerFeedbackEventParams{IdempotencyKey: key}
	return request[controlv1.FeedbackEvent](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AppendReviewerFeedbackEvent(ctx, runID, id, params, body, editors...)
	})
}

func (c *Client) GetReviewerFeedbackThread(ctx context.Context, runID, id string, body controlv1.ReviewerFeedbackReadRequest, token credentials.PublishRunToken) (controlv1.FeedbackThread, error) {
	return request[controlv1.FeedbackThread](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetReviewerFeedbackThread(ctx, runID, id, body, editors...)
	})
}

func (c *Client) ListReviewerFeedbackEvents(ctx context.Context, runID, id string, body controlv1.ReviewerFeedbackReadRequest, token credentials.PublishRunToken) (controlv1.FeedbackEventPage, error) {
	return request[controlv1.FeedbackEventPage](ctx, c, token.String(), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListReviewerFeedbackEvents(ctx, runID, id, body, editors...)
	})
}
