package control

import (
	"context"
	"encoding/json"
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
func (c *Client) CreateWorkloadIngressAssignments(ctx context.Context, credential, service, key string, preferred ...string) (controlv1.WorkloadIngressAssignments, error) {
	return c.CreateWorkloadIngressAssignmentSet(ctx, credential, service, key, 2, "", preferred...)
}
func (c *Client) CreateWorkloadIngressAssignmentSet(ctx context.Context, credential, service, key string, count int, exclude string, preferred ...string) (controlv1.WorkloadIngressAssignments, error) {
	body := controlv1.CreateWorkloadIngressAssignmentsJSONRequestBody{IdempotencyKey: key, Count: &count}
	if exclude != "" {
		body.ExcludeIngressId = &exclude
	}
	if len(preferred) > 0 {
		values := controlv1.LocationPreferences(append([]string(nil), preferred...))
		body.PreferredRegions = &values
	}
	return request[controlv1.WorkloadIngressAssignments](ctx, c, credential, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
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
	source, err := json.Marshal(controlv1.VisitorTokenWorkloadSource{Kind: controlv1.VisitorTokenWorkload, Credential: credential})
	if err != nil {
		return controlv1.ServiceClientCertificate{}, err
	}
	return request[controlv1.ServiceClientCertificate](ctx, c, "", func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueVisitorClientCertificate(ctx, controlv1.VisitorCertificateRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Source: source, Csr: csr}, editors...)
	})
}
