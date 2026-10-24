package control

import (
	"context"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/security/credentials"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (c *Client) CreateServiceCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.ServiceRunToken, csr []byte, key string) (controlv1.ServiceCertificateIssuance, error) {
	return request[controlv1.ServiceCertificateIssuance](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateServiceCertificateIssuance(ctx, service, run, &controlv1.CreateServiceCertificateIssuanceParams{IdempotencyKey: key}, controlv1.CreateServiceCertificateIssuanceRequest{RunNumber: number, Csr: csr}, editors...)
	})
}

func (c *Client) StartServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.ServiceRunSetup, error) {
	return c.StartServiceRunInRegions(ctx, service, run, access, number, nil)
}

func (c *Client) StartServiceRunInRegions(ctx context.Context, service, run, access string, number int64, preferred []string) (controlv1.ServiceRunSetup, error) {
	body := controlv1.StartServiceRunJSONRequestBody{RunNumber: number}
	if len(preferred) > 0 {
		values := controlv1.LocationPreferences(append([]string(nil), preferred...))
		body.PreferredRegions = &values
	}
	return request[controlv1.ServiceRunSetup](ctx, c, access, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.StartServiceRun(ctx, service, run, body, editors...)
	})
}

func (c *Client) GetServiceCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.ServiceRunToken) (controlv1.ServiceCertificateIssuance, error) {
	return request[controlv1.ServiceCertificateIssuance](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetServiceCertificateIssuance(ctx, service, run, issuance, editors...)
	})
}

func (c *Client) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.ServiceRunToken) error {
	_, err := request[struct{}](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkServiceCertificateInstalled(ctx, service, run, controlv1.ServiceCertificateInstalledRequest{RunNumber: number, IssuanceId: issuance, NotAfter: expires}, editors...)
	})
	return err
}
