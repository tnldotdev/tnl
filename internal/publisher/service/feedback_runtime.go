package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"time"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
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
	AuthorizeReviewerFeedback(context.Context, string, string, controlv1.AuthorizeReviewerFeedbackRequest, credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error)
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
	state       *clientstate.Store
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
