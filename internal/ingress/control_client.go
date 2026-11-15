package ingress

import (
	"context"
	"errors"

	serverhttp "github.com/tnldotdev/tnl/internal/serverhttp"
	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
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

func (c *HTTPControlClient) ObserveServiceRecovery(
	ctx context.Context,
	ingressID ingressv1.IngressID,
	recoveryEpisodeID int64,
	body ingressv1.ServiceRecoveryObservationRequest,
) (ingressv1.ServiceRecoveryObservation, error) {
	response, err := c.client.ObserveServiceRecoveryWithResponse(ctx, ingressID, recoveryEpisodeID, body)
	if err != nil {
		return ingressv1.ServiceRecoveryObservation{}, err
	}
	if response == nil {
		return ingressv1.ServiceRecoveryObservation{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.ServiceRecoveryObservation{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func ingressHTTPProblem(status int, problem *ingressv1.Problem) error {
	result := &serverhttp.ProblemError{Status: status}
	if problem != nil {
		result.Type = problem.Type
		result.Title = problem.Title
		result.Code = string(problem.Code)
		result.Detail = problem.Detail
		result.RequestID = problem.RequestId
	}
	return result
}
