package controlclient

import (
	"context"
	"net/http"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) ListWorkloadServices(ctx context.Context, credential string) (controlv1.WorkloadServices, error) {
	return request[controlv1.WorkloadServices](ctx, c, credential, c.api.ListWorkloadServices)
}
func (c *Client) CheckWorkloadService(ctx context.Context, credential, service string) (controlv1.WorkloadServiceAuthorization, error) {
	return request[controlv1.WorkloadServiceAuthorization](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CheckWorkloadService(ctx, service, editors...)
	})
}
func (c *Client) CreateWorkloadIngressAssignments(ctx context.Context, credential, service, key string) (controlv1.WorkloadIngressAssignments, error) {
	return request[controlv1.WorkloadIngressAssignments](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateWorkloadIngressAssignments(ctx, service, controlv1.CreateWorkloadIngressAssignmentsJSONRequestBody{IdempotencyKey: key}, editors...)
	})
}
func (c *Client) IssueWorkloadServiceClientCertificate(ctx context.Context, credential, service string, csr []byte) (controlv1.ServiceClientCertificate, error) {
	return request[controlv1.ServiceClientCertificate](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueWorkloadServiceClientCertificate(ctx, service, controlv1.IssueWorkloadServiceClientCertificateJSONRequestBody{Csr: csr}, editors...)
	})
}
