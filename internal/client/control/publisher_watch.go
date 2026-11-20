package control

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// WatchPublisherRuns waits on the caller's last applied connector bookmarks.
// the returned hints do not acknowledge a revision or authorize any work.
func (c *Client) WatchPublisherRuns(ctx context.Context, runs []controlv1.PublisherWatchRun) ([]controlv1.PublisherWatchChange, error) {
	body := controlv1.PublisherWatchRequest{Runs: runs}
	response, err := requestWithTimeout[controlv1.PublisherWatchResponse](ctx, c, 25*time.Second, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.WatchPublisherRuns(ctx, body, editors...)
	})
	if err != nil {
		return nil, err
	}
	invalid := failure.Wrap("read publisher watch", failure.ServerResponseInvalid, errors.New("controlclient: invalid publisher watch changes"))
	if response.Changes == nil || len(response.Changes) > len(runs) {
		return nil, invalid
	}
	awaiting := make(map[string]*int64, len(runs))
	for _, run := range runs {
		awaiting[run.ServiceRunId] = run.ConnectorRevision
	}
	for _, change := range response.Changes {
		seen, found := awaiting[change.ServiceRunId]
		if !found || change.ConnectorRevision < -1 || seen != nil && *seen == change.ConnectorRevision {
			return nil, invalid
		}
		delete(awaiting, change.ServiceRunId)
	}
	return response.Changes, nil
}
