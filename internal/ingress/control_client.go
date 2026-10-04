package ingress

import (
	"context"
	"errors"
	"net/http"

	"github.com/tnldotdev/tnl/internal/serviceapi"
	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

// HTTPControlClient adapts the generated private API client to ingress control operations.
type HTTPControlClient struct {
	client ingressv1.ClientWithResponsesInterface
}

func NewHTTPControlClient(client ingressv1.ClientWithResponsesInterface) (*HTTPControlClient, error) {
	if client == nil {
		return nil, errors.New("ingress: generated control client is required")
	}
	return &HTTPControlClient{client: client}, nil
}

func (c *HTTPControlClient) RegisterIngress(
	ctx context.Context,
	body ingressv1.IngressRegistration,
) (ingressv1.IngressLease, error) {
	response, err := c.client.RegisterIngressWithResponse(ctx, body)
	if err != nil {
		return ingressv1.IngressLease{}, err
	}
	if response == nil {
		return ingressv1.IngressLease{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.IngressLease{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) RenewIngress(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	body ingressv1.IngressRenewal,
) (ingressv1.IngressLease, error) {
	response, err := c.client.RenewIngressWithResponse(ctx, ingressID, body)
	if err != nil {
		return ingressv1.IngressLease{}, err
	}
	if response == nil {
		return ingressv1.IngressLease{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.IngressLease{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) DrainIngress(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	body ingressv1.IngressDrainRequest,
) (ingressv1.IngressLease, error) {
	response, err := c.client.DrainIngressWithResponse(ctx, ingressID, body)
	if err != nil {
		return ingressv1.IngressLease{}, err
	}
	if response == nil {
		return ingressv1.IngressLease{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.IngressLease{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) GetIngressRoutingTableSnapshot(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableSnapshotParams,
) (ingressv1.IngressRoutingTableSnapshot, error) {
	response, err := c.client.GetIngressRoutingTableSnapshotWithResponse(ctx, ingressID, &params)
	if err != nil {
		return ingressv1.IngressRoutingTableSnapshot{}, err
	}
	if response == nil {
		return ingressv1.IngressRoutingTableSnapshot{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.IngressRoutingTableSnapshot{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) GetIngressRoutingTableEvents(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	params ingressv1.GetIngressRoutingTableEventsParams,
) (ingressv1.IngressRoutingTablePage, error) {
	response, err := c.client.GetIngressRoutingTableEventsWithResponse(ctx, ingressID, &params)
	if err != nil {
		return ingressv1.IngressRoutingTablePage{}, err
	}
	if response != nil && response.JSON200 != nil {
		return *response.JSON200, nil
	}
	var problem *ingressv1.Problem
	if response != nil {
		problem = response.ApplicationproblemJSON409
		if problem == nil {
			problem = response.ApplicationproblemJSONDefault
		}
	}
	if response == nil {
		return ingressv1.IngressRoutingTablePage{}, ingressHTTPProblem(0, nil)
	}
	return ingressv1.IngressRoutingTablePage{}, ingressHTTPProblem(response.StatusCode(), problem)
}

func (c *HTTPControlClient) ReportIngressUsage(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	body ingressv1.IngressUsageReportBatch,
) error {
	response, err := c.client.ReportIngressUsageWithResponse(ctx, ingressID, body)
	if err != nil {
		return err
	}
	if response == nil {
		return ingressHTTPProblem(0, nil)
	}
	if response.StatusCode() != http.StatusNoContent {
		return ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return nil
}

func (c *HTTPControlClient) ObservePublicURLRecovery(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	recoveryEpisodeID int64,
	body ingressv1.PublicURLRecoveryObservationRequest,
) (ingressv1.PublicURLRecoveryObservation, error) {
	response, err := c.client.ObservePublicURLRecoveryWithResponse(ctx, ingressID, recoveryEpisodeID, body)
	if err != nil {
		return ingressv1.PublicURLRecoveryObservation{}, err
	}
	if response == nil {
		return ingressv1.PublicURLRecoveryObservation{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PublicURLRecoveryObservation{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func ingressHTTPProblem(status int, problem *ingressv1.Problem) error {
	result := &serviceapi.ProblemError{Status: status}
	if problem != nil {
		result.Type = problem.Type
		result.Title = problem.Title
		result.Code = string(problem.Code)
		result.Detail = problem.Detail
		result.RequestID = problem.RequestId
	}
	return result
}
