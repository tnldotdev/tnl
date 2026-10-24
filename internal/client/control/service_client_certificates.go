package control

import (
	"context"
	"encoding/json"
	"net/http"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) IssueServiceClientCertificate(ctx context.Context, service, device string, csr []byte) (controlv1.ServiceClientCertificate, error) {
	source, err := json.Marshal(controlv1.VisitorTokenDeviceSource{Kind: controlv1.VisitorTokenDevice, DeviceId: device})
	if err != nil {
		return controlv1.ServiceClientCertificate{}, err
	}
	return requestWithAccess[controlv1.ServiceClientCertificate](ctx, c, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueVisitorClientCertificate(ctx, controlv1.VisitorCertificateRequest{Resource: controlv1.VisitorResourceScope{Kind: "service", Id: service}, Source: source, Csr: csr}, editors...)
	})
}
