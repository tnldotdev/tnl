package ingress

import (
	"context"
	"net/http"

	ingressv1 "github.com/tnldotdev/tnl/pkg/api/control/private/ingress/v1"
)

type PublicServiceControl interface {
	AdmitPublicServiceVisitor(context.Context, string, ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error)
	PublicServiceVisitorStatus(context.Context, string, ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error)
	ClosePublicServiceVisitor(context.Context, string, ingressv1.PublicServiceVisitorLookup) error
	PromotePublicServiceVisitor(context.Context, string, ingressv1.PublicServiceVisitorLookup) error
}

func (c *HTTPControlClient) AdmitPublicServiceVisitor(ctx context.Context, id string, body ingressv1.PublicServiceVisitorClaim) (ingressv1.PublicServiceVisitorAdmission, error) {
	response, err := c.client.AdmitPublicServiceVisitorWithResponse(ctx, id, body)
	if err != nil {
		return ingressv1.PublicServiceVisitorAdmission{}, err
	}
	if response == nil {
		return ingressv1.PublicServiceVisitorAdmission{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PublicServiceVisitorAdmission{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) PublicServiceVisitorStatus(ctx context.Context, id string, body ingressv1.PublicServiceVisitorLookup) (ingressv1.PublicServiceVisitorStatus, error) {
	response, err := c.client.PublicServiceVisitorStatusWithResponse(ctx, id, body)
	if err != nil {
		return ingressv1.PublicServiceVisitorStatus{}, err
	}
	if response == nil {
		return ingressv1.PublicServiceVisitorStatus{}, ingressHTTPProblem(0, nil)
	}
	if response.JSON200 == nil {
		return ingressv1.PublicServiceVisitorStatus{}, ingressHTTPProblem(response.StatusCode(), response.ApplicationproblemJSONDefault)
	}
	return *response.JSON200, nil
}

func (c *HTTPControlClient) ClosePublicServiceVisitor(ctx context.Context, id string, body ingressv1.PublicServiceVisitorLookup) error {
	response, err := c.client.ClosePublicServiceVisitorWithResponse(ctx, id, body)
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

func (c *HTTPControlClient) PromotePublicServiceVisitor(ctx context.Context, id string, body ingressv1.PublicServiceVisitorLookup) error {
	response, err := c.client.PromotePublicServiceVisitorWithResponse(ctx, id, body)
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
