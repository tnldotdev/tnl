package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/publisher/toolbar"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	maximumFeedbackBrowsers = 128
	maximumFailedRequests   = 20
)

type FeedbackClient interface {
	CreateFeedbackReport(context.Context, string, string, string, controlv1.CreateFeedbackReportRequest, credentials.ServiceRunToken) (controlv1.FeedbackThread, error)
	ListPreviewPageFeedback(context.Context, string, string, controlv1.PreviewPageFeedbackRequest, credentials.ServiceRunToken) (controlv1.FeedbackThreadPage, error)
	GetReviewerFeedbackThread(context.Context, string, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.ServiceRunToken) (controlv1.FeedbackThread, error)
	ListReviewerFeedbackEvents(context.Context, string, string, string, controlv1.ReviewerFeedbackReadRequest, credentials.ServiceRunToken) (controlv1.FeedbackEventPage, error)
	AppendReviewerFeedbackEvent(context.Context, string, string, string, string, controlv1.AppendReviewerFeedbackEventRequest, credentials.ServiceRunToken) (controlv1.FeedbackEvent, error)
}

// feedbackAuthorization is supplied by request admission, never browser input.
// only the control wire owner reveals its selected proof.
type feedbackAuthorization struct {
	permission visitortoken.VerifiedPermission
	allowed    bool
	proof      json.RawMessage
}

func (feedbackAuthorization) String() string   { return "feedback authorization" }
func (feedbackAuthorization) GoString() string { return "feedback authorization" }

func bearerFeedbackAuthorization(authorization httpaccess.Authorization) (feedbackAuthorization, error) {
	result := feedbackAuthorization{permission: authorization.Permission(), allowed: true}
	token, bearer := authorization.BearerToken()
	if !bearer {
		if result.permission.Valid() {
			return feedbackAuthorization{}, visitortoken.ErrBinding
		}
		return result, nil
	}
	proof, err := json.Marshal(controlv1.FeedbackBearerVisitProof{Kind: controlv1.FeedbackVisitBearer, Token: token.Reveal()})
	if err != nil {
		return feedbackAuthorization{}, err
	}
	result.proof = proof
	return result, nil
}

func connectorFeedbackAuthorization(authorization servicestream.ConnectorHTTPAuthorization) (feedbackAuthorization, error) {
	proof, err := json.Marshal(controlv1.FeedbackConnectorVisitProof{
		Kind: controlv1.FeedbackVisitConnector, PairId: authorization.PairID,
		DeliveryGeneration: authorization.DeliveryGeneration, PermissionToken: authorization.PermissionToken.Reveal(),
	})
	if err != nil {
		return feedbackAuthorization{}, err
	}
	return feedbackAuthorization{permission: authorization.Permission, allowed: true, proof: proof}, nil
}

type feedbackRuntime struct {
	client      FeedbackClient
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
	if config.Control == nil || !opaqueid.Valid(config.PreviewID, opaqueid.PreviewPrefix) || config.ProjectService == "" || !config.Demo && config.ProjectRoot == "" {
		return nil, errors.New("service: feedback requires a configured preview, project service, and project root")
	}
	asset, assetPath := toolbar.Script()
	return &feedbackRuntime{
		demo:   config.Demo,
		client: config.Control, previewID: config.PreviewID, serviceID: config.Subject.ID,
		service: config.ProjectService, projectRoot: config.ProjectRoot,
		runID: config.RunID, number: config.Number, token: config.Token,
		browsers: make(map[[32]byte]*browserTrail), asset: asset, assetPath: assetPath,
	}, nil
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
