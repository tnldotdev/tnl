package control

import (
	"context"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) ListWorkloadServices(ctx context.Context, credential string) (controlv1.WorkloadServices, error) {
	return request[controlv1.WorkloadServices](ctx, c, credential, c.api.ListWorkloadServices)
}
func (c *Client) CheckWorkloadService(ctx context.Context, credential, service string) (controlv1.WorkloadServiceAuthorization, error) {
	return request[controlv1.WorkloadServiceAuthorization](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CheckWorkloadService(ctx, service, editors...)
	})
}
func (c *Client) SelectWorkloadServiceRun(ctx context.Context, credential, service string) (controlv1.ServiceSelection, error) {
	return request[controlv1.ServiceSelection](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SelectWorkloadServiceRun(ctx, service, editors...)
	})
}
func (c *Client) IssueWorkloadServiceClientCertificate(ctx context.Context, credential, service string, csr []byte) (controlv1.ServiceClientCertificate, error) {
	return request[controlv1.ServiceClientCertificate](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueWorkloadServiceClientCertificate(ctx, service, controlv1.IssueWorkloadServiceClientCertificateJSONRequestBody{Csr: csr}, editors...)
	})
}
