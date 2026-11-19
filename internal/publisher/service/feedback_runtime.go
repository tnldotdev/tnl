//go:build !js || !wasm

package service

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/toolbar"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	maximumFeedbackBrowsers = 128
	maximumFailedRequests   = 20
)

type feedbackRuntime struct {
	client      FeedbackClient
	state       feedbackState
	previewID   string
	serviceID   string
	service     string
	projectRoot string
	runID       string
	number      int64
	token       credentials.ServiceRunToken
	mu          sync.Mutex
	browsers    map[[32]byte]*browserTrail
	asset       []byte
	assetPath   string
	demo        bool
	handlerOnce sync.Once
	handler     http.Handler
}

func newFeedbackRuntime(config HTTP) (*feedbackRuntime, error) {
	if !config.Feedback {
		return nil, nil
	}
	if config.State == nil || config.Control == nil || !opaqueid.Valid(config.PreviewID, opaqueid.PreviewPrefix) || config.ProjectService == "" || !config.Demo && config.ProjectRoot == "" {
		return nil, errors.New("service: feedback requires a configured preview, project service, and project root")
	}
	asset, assetPath := toolbar.Script()
	return &feedbackRuntime{
		demo:   config.Demo,
		client: config.Control, state: config.State, previewID: config.PreviewID, serviceID: config.Subject.ID,
		service: config.ProjectService, projectRoot: config.ProjectRoot,
		runID: config.RunID, number: config.Number, token: config.Token,
		browsers: make(map[[32]byte]*browserTrail), asset: asset, assetPath: assetPath,
	}, nil
}

func (f *feedbackRuntime) local(ctx context.Context, access controlv1.FeedbackReviewerAccess) (*clientstate.FeedbackStore, error) {
	if f.state == nil {
		return nil, errors.New("service: feedback client state is unavailable")
	}
	authorize := func(ctx context.Context, service, operation string) (controlv1.FeedbackAuthorization, error) {
		if service != f.serviceID {
			return controlv1.FeedbackAuthorization{}, clientstate.ErrFeedbackNotFound
		}
		return f.client.AuthorizeReviewerFeedback(ctx, service, f.runID, controlv1.AuthorizeReviewerFeedbackRequest{
			PreviewId: f.previewID, RunNumber: f.number, Operation: controlv1.FeedbackOperation(operation), Access: access,
		}, f.token)
	}
	if f.demo {
		return f.state.DemoFeedback(ctx, f.previewID, authorize)
	}
	return f.state.Feedback(ctx, f.projectRoot, f.previewID, authorize)
}

func (f *feedbackRuntime) close(ctx context.Context) error {
	if f == nil || !f.demo {
		return nil
	}
	cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer stop()
	return f.state.DiscardDemoFeedback(cleanup, f.previewID)
}
func (f *feedbackRuntime) responseHooks(hooks httpstream.ResponseHooks) httpstream.ResponseHooks {
	modify, observe := hooks.ModifyHTML, hooks.ObserveStatus
	hooks.ModifyHTML = func(response *http.Response) error {
		if modify != nil {
			if err := modify(response); err != nil {
				return err
			}
		}
		return toolbar.Inject(response)
	}
	hooks.ObserveStatus = func(request *http.Request, status int) {
		if observe != nil {
			observe(request, status)
		}
		f.observe(request, status)
	}
	return hooks
}
