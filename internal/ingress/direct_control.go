package ingress

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/ingressv1"
)

type DirectControl interface {
	AdmitDirectServiceVisitor(context.Context, string, ingressv1.DirectServiceVisitorClaim) (ingressv1.DirectServiceVisitorAdmission, error)
	DirectServiceVisitorStatus(context.Context, string, ingressv1.DirectServiceVisitorLookup) (ingressv1.DirectServiceVisitorStatus, error)
	CloseDirectServiceVisitor(context.Context, string, ingressv1.DirectServiceVisitorLookup) error
	PromoteDirectServiceVisitor(context.Context, string, ingressv1.DirectServiceVisitorLookup) error
}

func (c *HTTPControlClient) AdmitDirectServiceVisitor(ctx context.Context, id string, body ingressv1.DirectServiceVisitorClaim) (ingressv1.DirectServiceVisitorAdmission, error) {
	response, err := c.client.AdmitDirectServiceVisitorWithResponse(ctx, id, body)
	if err != nil {
		return ingressv1.DirectServiceVisitorAdmission{}, err
	}
	if response == nil {
		return ingressv1.DirectServiceVisitorAdmission{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.DirectServiceVisitorAdmission{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) DirectServiceVisitorStatus(ctx context.Context, id string, body ingressv1.DirectServiceVisitorLookup) (ingressv1.DirectServiceVisitorStatus, error) {
	response, err := c.client.DirectServiceVisitorStatusWithResponse(ctx, id, body)
	if err != nil {
		return ingressv1.DirectServiceVisitorStatus{}, err
	}
	if response == nil {
		return ingressv1.DirectServiceVisitorStatus{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.DirectServiceVisitorStatus{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) CloseDirectServiceVisitor(ctx context.Context, id string, body ingressv1.DirectServiceVisitorLookup) error {
	response, err := c.client.CloseDirectServiceVisitorWithResponse(ctx, id, body)
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

func (c *HTTPControlClient) PromoteDirectServiceVisitor(ctx context.Context, id string, body ingressv1.DirectServiceVisitorLookup) error {
	response, err := c.client.PromoteDirectServiceVisitorWithResponse(ctx, id, body)
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
