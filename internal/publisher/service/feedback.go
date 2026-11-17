package service

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/publisher/httpaccess"
	servicestream "github.com/tnldotdev/tnl/internal/publisher/service/stream"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/transport/httpstream"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrFeedbackUnsupported = errors.New("service: feedback and demo publication require native client state")

type FeedbackClient interface {
	AuthorizeReviewerFeedback(context.Context, string, string, controlv1.AuthorizeReviewerFeedbackRequest, credentials.ServiceRunToken) (controlv1.FeedbackAuthorization, error)
}

// feedbackFrontend is optional composition, not another HTTP authorization
// engine. native feedback retains its existing persistence and joined cleanup.
// hosts that cannot provide it reject the requested configuration, never install
// a substitute handler that accepts feedback or bypasses its access checks.
type feedbackFrontend interface {
	handle(http.ResponseWriter, *http.Request, feedbackAuthorization) bool
	prepareBrowser(http.ResponseWriter, *http.Request) *http.Request
	responseHooks(httpstream.ResponseHooks) httpstream.ResponseHooks
	close(context.Context) error
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
