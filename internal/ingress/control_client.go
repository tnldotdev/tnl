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

func (c *HTTPControlClient) GetIngressTransportCertificate(ctx context.Context, id string, body ingressv1.GetIngressTransportCertificateJSONRequestBody) (ingressv1.IngressTransportCertificate, error) {
	response, err := c.client.GetIngressTransportCertificateWithResponse(ctx, id, body)
	if err != nil {
		return ingressv1.IngressTransportCertificate{}, err
	}
	if response == nil {
		return ingressv1.IngressTransportCertificate{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.IngressTransportCertificate{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) ClaimPrivateConnectorSession(ctx context.Context, ingressID string, body ingressv1.PrivateConnectorSessionClaim) (ingressv1.PrivateConnectorSessionResult, error) {
	response, err := c.client.ClaimPrivateConnectorSessionWithResponse(ctx, ingressID, body)
	if err != nil {
		return ingressv1.PrivateConnectorSessionResult{}, err
	}
	if response == nil {
		return ingressv1.PrivateConnectorSessionResult{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PrivateConnectorSessionResult{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) AuthorizePrivateServiceStream(ctx context.Context, ingressID string, body ingressv1.PrivateServiceStreamClaim) (ingressv1.PrivateServiceStreamResult, error) {
	response, err := c.client.AuthorizePrivateServiceStreamWithResponse(ctx, ingressID, body)
	if err != nil {
		return ingressv1.PrivateServiceStreamResult{}, err
	}
	if response == nil {
		return ingressv1.PrivateServiceStreamResult{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PrivateServiceStreamResult{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) ClosePrivateServiceStream(ctx context.Context, ingressID, visitorID string, body ingressv1.ClosePrivateServiceStreamJSONRequestBody) error {
	response, err := c.client.ClosePrivateServiceStreamWithResponse(ctx, ingressID, visitorID, body)
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

func (c *HTTPControlClient) RecheckPrivateServiceVisitor(ctx context.Context, ingressID string, body ingressv1.PrivateServiceVisitorRecheck) (ingressv1.PrivateServiceVisitorRecheckResult, error) {
	response, err := c.client.RecheckPrivateServiceVisitorWithResponse(ctx, ingressID, body)
	if err != nil {
		return ingressv1.PrivateServiceVisitorRecheckResult{}, err
	}
	if response == nil {
		return ingressv1.PrivateServiceVisitorRecheckResult{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PrivateServiceVisitorRecheckResult{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) GetPrivateServiceSnapshot(ctx context.Context, ingressID string, params ingressv1.GetPrivateServiceSnapshotParams) (ingressv1.PrivateServiceSnapshot, error) {
	response, err := c.client.GetPrivateServiceSnapshotWithResponse(ctx, ingressID, &params)
	if err != nil {
		return ingressv1.PrivateServiceSnapshot{}, err
	}
	if response == nil {
		return ingressv1.PrivateServiceSnapshot{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PrivateServiceSnapshot{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) GetPrivateServiceEvents(ctx context.Context, ingressID string, params ingressv1.GetPrivateServiceEventsParams) (ingressv1.PrivateServiceSnapshot, error) {
	response, err := c.client.GetPrivateServiceEventsWithResponse(ctx, ingressID, &params)
	if err != nil {
		return ingressv1.PrivateServiceSnapshot{}, err
	}
	if response == nil {
		return ingressv1.PrivateServiceSnapshot{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PrivateServiceSnapshot{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
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
