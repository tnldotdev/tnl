// Package routeclient coordinates authority authorization with control route mutations.
package routeclient

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type Client struct {
	control              *controlclient.Client
	authority            *authorityclient.Client
	signedAuthorizations bool
}

func New(control *controlclient.Client, authority *authorityclient.Client, signedAuthorizations bool) (*Client, error) {
	if control == nil || authority == nil {
		return nil, errors.New("routeclient: control and authority clients are required")
	}
	return &Client{control: control, authority: authority, signedAuthorizations: signedAuthorizations}, nil
}

func (c *Client) CreateRoute(ctx context.Context, body controlv1.CreateRouteRequest, idempotencyKey string) (controlv1.Route, error) {
	canonical, err := canonicalizeIPPrefixes(body.AllowedIpPrefixes)
	if err != nil {
		return controlv1.Route{}, err
	}
	body.AllowedIpPrefixes = canonical
	operation := authorization.OperationRequest{
		Operation: authorization.OperationRouteCreate, TeamID: body.TeamId, DomainID: body.DomainId,
		CanonicalHostname: body.CanonicalHostname, RouteScope: string(body.RouteScope), Target: body.Target,
		AllowedIPPrefixes: prefixValues(body.AllowedIpPrefixes),
	}
	if body.MembershipId != nil {
		operation.MembershipID = *body.MembershipId
	}
	if !c.signedAuthorizations {
		return c.control.CreateRoute(ctx, body, idempotencyKey)
	}
	envelope, err := c.issueAuthorization(ctx, operation)
	if err != nil {
		return controlv1.Route{}, err
	}
	return c.control.CreateRouteAuthorized(ctx, body, idempotencyKey, envelope.Authorization)
}

func (c *Client) ListRoutes(ctx context.Context, teamID string) ([]controlv1.Route, error) {
	return c.control.ListRoutes(ctx, teamID)
}

func (c *Client) CreateRouteSession(ctx context.Context, route controlv1.Route, body controlv1.CreateRouteSessionRequest, routeVersion uint64, idempotencyKey string) (controlv1.RouteSessionSetup, error) {
	if body.AllowedIpPrefixes == nil {
		return controlv1.RouteSessionSetup{}, errors.New("routeclient: allowed IP prefixes are required")
	}
	canonical, err := authorization.CanonicalizeIPPrefixes(body.AllowedIpPrefixes)
	if err != nil {
		return controlv1.RouteSessionSetup{}, fmt.Errorf("routeclient: canonicalize allowed IP prefixes: %w", err)
	}
	body.AllowedIpPrefixes = canonical
	plan := authorization.CertificatePlan{
		CacheKey: body.CertificatePlan.CacheKey, Scope: body.CertificatePlan.Scope,
		Identifiers: slices.Clone(body.CertificatePlan.Identifiers), ChallengeMethod: string(body.CertificatePlan.ChallengeMethod),
	}
	operation := authorization.OperationRequest{
		Operation: authorization.OperationRouteSessionCreate, TeamID: route.TeamId, DomainID: route.DomainId,
		CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope), RouteID: route.Id,
		RouteVersion: routeVersion, PolicyRevision: uint64(body.PolicyRevision), CertificatePlan: &plan,
		AllowedIPPrefixes: body.AllowedIpPrefixes,
	}
	if body.MembershipId != nil {
		operation.MembershipID = *body.MembershipId
	}
	if !c.signedAuthorizations {
		return c.control.CreateRouteSession(ctx, route.Id, body, idempotencyKey)
	}
	envelope, err := c.issueAuthorization(ctx, operation)
	if err != nil {
		return controlv1.RouteSessionSetup{}, err
	}
	return c.control.CreateRouteSessionAuthorized(ctx, route.Id, body, idempotencyKey, envelope.Authorization)
}

func (c *Client) DeleteRoute(ctx context.Context, route controlv1.Route) error {
	operation := authorization.OperationRequest{
		Operation: authorization.OperationRouteDelete, TeamID: route.TeamId, DomainID: route.DomainId,
		CanonicalHostname: route.CanonicalHostname, RouteScope: string(route.RouteScope), RouteID: route.Id,
	}
	if route.MembershipId != nil {
		operation.MembershipID = *route.MembershipId
	}
	if !c.signedAuthorizations {
		return c.control.DeleteRoute(ctx, route.Id)
	}
	envelope, err := c.issueAuthorization(ctx, operation)
	if err != nil {
		return err
	}
	return c.control.DeleteRouteAuthorized(ctx, route.Id, envelope.Authorization)
}

func (c *Client) Ready(ctx context.Context, routeSessionID string, version uint64, token credentials.SessionToken) error {
	return c.control.Ready(ctx, routeSessionID, version, token)
}

func (c *Client) Heartbeat(ctx context.Context, routeSessionID string, version uint64, token credentials.SessionToken) (controlv1.RouteSessionHeartbeat, error) {
	return c.control.Heartbeat(ctx, routeSessionID, version, token)
}

func (c *Client) CloseRouteSession(ctx context.Context, routeSessionID string, token credentials.SessionToken) error {
	return c.control.CloseRouteSession(ctx, routeSessionID, token)
}

func (c *Client) CreateCertificateIssuance(ctx context.Context, routeSessionID string, version uint64, token credentials.SessionToken, csr []byte, idempotencyKey string) (controlv1.CertificateIssuance, error) {
	return c.control.CreateCertificateIssuance(ctx, routeSessionID, version, token, csr, idempotencyKey)
}

func (c *Client) CertificateIssuance(ctx context.Context, issuanceID string, token credentials.SessionToken) (controlv1.CertificateIssuance, error) {
	return c.control.CertificateIssuance(ctx, issuanceID, token)
}

func (c *Client) CertificateChallengeReady(ctx context.Context, issuanceID string, token credentials.SessionToken) (controlv1.CertificateIssuance, error) {
	return c.control.CertificateChallengeReady(ctx, issuanceID, token)
}

func (c *Client) CertificateChallengeRemoved(ctx context.Context, issuanceID string, token credentials.SessionToken) error {
	return c.control.CertificateChallengeRemoved(ctx, issuanceID, token)
}

func (c *Client) CertificateInstalled(ctx context.Context, routeSessionID string, version uint64, issuanceID string, notAfter time.Time, token credentials.SessionToken) error {
	return c.control.CertificateInstalled(ctx, routeSessionID, version, issuanceID, notAfter, token)
}

func (c *Client) issueAuthorization(ctx context.Context, operation authorization.OperationRequest) (authorityv1.AuthorizationEnvelope, error) {
	digest, err := authorization.CanonicalRequestHash(operation)
	if err != nil {
		return authorityv1.AuthorizationEnvelope{}, fmt.Errorf("routeclient: hash authorized request: %w", err)
	}
	ipDigest, err := authorization.IPPolicyHash(operation.AllowedIPPrefixes)
	if err != nil {
		return authorityv1.AuthorizationEnvelope{}, fmt.Errorf("routeclient: hash IP policy: %w", err)
	}
	retryID, err := opaqueid.New("retry_")
	if err != nil {
		return authorityv1.AuthorizationEnvelope{}, fmt.Errorf("routeclient: generate retry ID: %w", err)
	}
	idempotencyKey, err := opaqueid.New("random_")
	if err != nil {
		return authorityv1.AuthorizationEnvelope{}, fmt.Errorf("routeclient: generate idempotency key: %w", err)
	}
	request := authorityv1.IssueAuthorizationRequest{
		Operation: authorityv1.AuthorizationOperation(operation.Operation), TeamId: operation.TeamID,
		DomainId: operation.DomainID, CanonicalHostname: operation.CanonicalHostname,
		RouteScope: authorityv1.RouteScope(operation.RouteScope), RequestDigest: digest.String(), RetryId: retryID,
	}
	if operation.MembershipID != "" {
		request.MembershipId = &operation.MembershipID
	}
	if operation.RouteID != "" {
		request.RouteId = &operation.RouteID
	}
	if operation.RouteVersion != 0 {
		version := int64(operation.RouteVersion)
		request.RouteVersion = &version
	}
	if operation.CertificatePlan != nil {
		request.CertificatePlan = &authorityv1.CertificatePlan{
			CacheKey: operation.CertificatePlan.CacheKey, Scope: operation.CertificatePlan.Scope,
			Identifiers:     slices.Clone(operation.CertificatePlan.Identifiers),
			ChallengeMethod: authorityv1.CertificateChallengeMethod(operation.CertificatePlan.ChallengeMethod),
		}
	}
	if ipDigest != nil {
		value := ipDigest.String()
		request.IpPolicyDigest = &value
	}
	envelope, err := c.authority.IssueAuthorization(ctx, request, idempotencyKey)
	if err != nil {
		return authorityv1.AuthorizationEnvelope{}, mapAuthorityError(err)
	}
	if envelope.Authorization == "" || envelope.AuthorizationId == "" ||
		envelope.TeamPolicyRevision < 1 || !envelope.ExpiresAt.After(time.Now().Add(30*time.Second)) {
		return authorityv1.AuthorizationEnvelope{}, errors.New("routeclient: authority returned an invalid authorization")
	}
	return envelope, nil
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

func prefixValues(prefixes *[]string) []string {
	if prefixes == nil {
		return nil
	}
	return *prefixes
}

func mapAuthorityError(err error) error {
	var limited *authorityclient.RateLimitError
	if errors.Is(err, authorityclient.ErrUnavailable) {
		return fmt.Errorf("%w: %v", controlclient.ErrUnavailable, err)
	}
	if errors.As(err, &limited) {
		return &controlclient.RateLimitError{RetryAfter: limited.RetryAfter}
	}
	return err
}
