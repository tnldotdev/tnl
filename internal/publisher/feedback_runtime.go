package publisher

import (
	"context"
	"errors"
	"net/http"
	"sync"

	"github.com/tnldotdev/tnl/internal/publisher/toolbar"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	feedbackBrowserCookieName = "__Host-tnl-feedback-browser"
	maximumFeedbackBrowsers   = 128
	maximumFailedRequests     = 20
)

type feedbackClient interface {
	CreateFeedbackReport(context.Context, string, string, controlv1.CreateFeedbackReportRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListPreviewPageFeedback(context.Context, string, controlv1.PreviewPageFeedbackRequest, credentials.PublishRunToken) (controlv1.FeedbackThreadPage, error)
	GetReviewerFeedbackThread(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackThread, error)
	ListReviewerFeedbackEvents(context.Context, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.PublishRunToken) (controlv1.FeedbackEventPage, error)
	AppendReviewerFeedbackEvent(context.Context, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, credentials.PublishRunToken) (controlv1.FeedbackEvent, error)
}

type feedbackRuntime struct {
	client      feedbackClient
	previewID   string
	publicURLID string
	service     string
	projectRoot string
	runID       string
	version     uint64
	token       credentials.PublishRunToken
	mu          sync.Mutex
	browsers    map[[32]byte]*browserTrail
	asset       []byte
	assetPath   string
	demo        bool
	handlerOnce sync.Once
	handler     http.Handler
}

func newFeedbackRuntime(config Config, setup controlv1.PublishRunSetup, token credentials.PublishRunToken) (*feedbackRuntime, error) {
	if !config.Feedback {
		return nil, nil
	}
	client, ok := config.Control.(feedbackClient)
	if !ok || config.PreviewID == "" || config.Service == "" || !config.Demo && config.ProjectRoot == "" {
		return nil, errors.New("publisher: feedback requires a configured preview, project service, and control client")
	}
	asset, assetPath := toolbar.Script()
	return &feedbackRuntime{
		demo:   config.Demo,
		client: client, previewID: config.PreviewID, publicURLID: setup.PublicUrl.Id,
		service: config.Service, projectRoot: config.ProjectRoot,
		runID: setup.PublishRun.Id, version: uint64(setup.PublishRun.PublishRunNumber), token: token,
		browsers: make(map[[32]byte]*browserTrail), asset: asset, assetPath: assetPath,
	}, nil
}

func (f *feedbackRuntime) modifyResponse(response *http.Response) error {
	return toolbar.Inject(response)
}
