package controlclient

import (
	"context"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) CreatePrivateCertificateIssuance(ctx context.Context, service, run string, number int64, token credentials.PublishRunToken, csr []byte, key string) (controlv1.PrivateCertificateIssuance, error) {
	return request[controlv1.PrivateCertificateIssuance](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreatePrivateCertificateIssuance(ctx, service, run, &controlv1.CreatePrivateCertificateIssuanceParams{IdempotencyKey: key}, controlv1.CreatePrivateCertificateIssuanceRequest{RunNumber: number, Csr: csr}, editors...)
	})
}

func (c *Client) StartManagedServiceRun(ctx context.Context, service, run, access string, number int64) (controlv1.PrivateServiceRunSetup, error) {
	return request[controlv1.PrivateServiceRunSetup](ctx, c, access, func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.StartManagedServiceRun(ctx, service, run, controlv1.StartManagedServiceRunJSONRequestBody{RunNumber: number}, editors...)
	})
}

func (c *Client) GetPrivateCertificateIssuance(ctx context.Context, service, run, issuance string, token credentials.PublishRunToken) (controlv1.PrivateCertificateIssuance, error) {
	return request[controlv1.PrivateCertificateIssuance](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetPrivateCertificateIssuance(ctx, service, run, issuance, editors...)
	})
}

func (c *Client) MarkPrivateCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.PublishRunToken) error {
	_, err := request[struct{}](ctx, c, string(token), func(ctx context.Context, editors ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.MarkPrivateCertificateInstalled(ctx, service, run, controlv1.PrivateCertificateInstalledRequest{RunNumber: number, IssuanceId: issuance, NotAfter: expires}, editors...)
	})
	return err
}
