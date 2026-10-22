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
func (c *Client) CreateWorkloadIngressAssignments(ctx context.Context, credential, service, key string) (controlv1.WorkloadIngressAssignments, error) {
	return c.CreateWorkloadIngressAssignmentSet(ctx, credential, service, key, 2, "")
}
func (c *Client) CreateWorkloadIngressAssignmentSet(ctx context.Context, credential, service, key string, count int, exclude string) (controlv1.WorkloadIngressAssignments, error) {
	return request[controlv1.WorkloadIngressAssignments](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		body := controlv1.CreateWorkloadIngressAssignmentsJSONRequestBody{IdempotencyKey: key, Count: &count}
		if exclude != "" {
			body.ExcludeIngressId = &exclude
		}
		return c.api.CreateWorkloadIngressAssignments(ctx, service, body, editors...)
	})
}

func (c *Client) SelectWorkloadServiceRun(ctx context.Context, credential, service string) (controlv1.ServiceSelection, error) {
	return request[controlv1.ServiceSelection](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SelectWorkloadServiceRun(ctx, service, editors...)
	})
}
func (c *Client) GetWorkloadIngressTransportTrust(ctx context.Context, credential, session string) (controlv1.IngressTransportTrust, error) {
	return request[controlv1.IngressTransportTrust](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetWorkloadIngressTransportTrust(ctx, session, editors...)
	})
}
func (c *Client) ReleaseWorkloadIngressAssignment(ctx context.Context, credential, session string) error {
	_, err := request[struct{}](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReleaseWorkloadIngressAssignment(ctx, session, editors...)
	})
	return err
}
func (c *Client) IssueWorkloadServiceClientCertificate(ctx context.Context, credential, service string, csr []byte) (controlv1.ServiceClientCertificate, error) {
	return request[controlv1.ServiceClientCertificate](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueWorkloadServiceClientCertificate(ctx, service, controlv1.IssueWorkloadServiceClientCertificateJSONRequestBody{Csr: csr}, editors...)
	})
}
