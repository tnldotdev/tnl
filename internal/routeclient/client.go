// Package routeclient is the publisher-facing client for control route operations.
package routeclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type Client struct {
	control *controlclient.Client
}

func New(control *controlclient.Client) (*Client, error) {
	if control == nil {
		return nil, errors.New("routeclient: control client is required")
	}
	return &Client{control: control}, nil
}

func (c *Client) CreateRoute(ctx context.Context, body controlv1.CreateRouteRequest, idempotencyKey string) (controlv1.Route, error) {
	canonical, err := canonicalizeIPPrefixes(body.AllowedIpPrefixes)
	if err != nil {
		return controlv1.Route{}, err
	}
	body.AllowedIpPrefixes = canonical
	return c.control.CreateRoute(ctx, body, idempotencyKey)
}

func (c *Client) ListRoutes(ctx context.Context, teamID string) ([]controlv1.Route, error) {
	return c.control.ListRoutes(ctx, teamID)
}

func (c *Client) UpdateRoute(ctx context.Context, routeID string, body controlv1.UpdateRouteRequest) (controlv1.Route, error) {
	canonical, err := authorization.CanonicalizeIPPrefixes(body.AllowedIpPrefixes)
	if err != nil {
		return controlv1.Route{}, fmt.Errorf("routeclient: canonicalize allowed IP prefixes: %w", err)
	}
	if canonical == nil {
		canonical = []string{}
	}
	body.AllowedIpPrefixes = canonical
	return c.control.UpdateRoute(ctx, routeID, body)
}

func (c *Client) CreateRouteSession(ctx context.Context, routeID, idempotencyKey string) (controlv1.RouteSessionSetup, error) {
	return c.control.CreateRouteSession(ctx, routeID, idempotencyKey)
}

func (c *Client) DeleteRoute(ctx context.Context, route controlv1.Route) error {
	return c.control.DeleteRoute(ctx, route.Id)
}

func (c *Client) MarkRouteSessionReady(ctx context.Context, routeSessionID string, version uint64, token credentials.RouteSessionToken) error {
	return c.control.MarkRouteSessionReady(ctx, routeSessionID, version, token)
}

func (c *Client) HeartbeatRouteSession(ctx context.Context, routeSessionID string, version uint64, token credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
	return c.control.HeartbeatRouteSession(ctx, routeSessionID, version, token)
}

func (c *Client) CloseRouteSession(ctx context.Context, routeSessionID string, token credentials.RouteSessionToken) error {
	return c.control.CloseRouteSession(ctx, routeSessionID, token)
}

func (c *Client) CreateCertificateIssuance(ctx context.Context, routeSessionID string, version uint64, token credentials.RouteSessionToken, csr []byte, idempotencyKey string) (controlv1.CertificateIssuance, error) {
	return c.control.CreateCertificateIssuance(ctx, routeSessionID, version, token, csr, idempotencyKey)
}

func (c *Client) GetCertificateIssuance(ctx context.Context, issuanceID string, token credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	return c.control.GetCertificateIssuance(ctx, issuanceID, token)
}

func (c *Client) MarkCertificateChallengeReady(ctx context.Context, issuanceID string, token credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	return c.control.MarkCertificateChallengeReady(ctx, issuanceID, token)
}

func (c *Client) MarkCertificateChallengeRemoved(ctx context.Context, issuanceID string, token credentials.RouteSessionToken) error {
	return c.control.MarkCertificateChallengeRemoved(ctx, issuanceID, token)
}

func (c *Client) MarkRouteSessionCertificateInstalled(ctx context.Context, routeSessionID string, version uint64, issuanceID string, notAfter time.Time, token credentials.RouteSessionToken) error {
	return c.control.MarkRouteSessionCertificateInstalled(ctx, routeSessionID, version, issuanceID, notAfter, token)
}

func canonicalizeIPPrefixes(prefixes *[]string) (*[]string, error) {
	if prefixes == nil {
		return nil, nil
	}
	canonical, err := authorization.CanonicalizeIPPrefixes(*prefixes)
	if err != nil {
		return nil, fmt.Errorf("routeclient: canonicalize allowed IP prefixes: %w", err)
	}
	return &canonical, nil
}
