// Package routeclient adapts local and signed-authority route APIs for publishers.
package routeclient

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/authorityv1"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"github.com/tnldotdev/tnl/pkg/protocol/transportv1"
)

var authorizationRenewalInterval = 15 * time.Minute

type Client struct {
	server                *serverclient.Client
	authority             *authorityclient.Client
	authorityCapabilities *authorityv1.Capabilities
	authorizationReceiver string

	mu      sync.Mutex
	routes  map[string]routeAuthorization
	pending map[string]pendingAuthorization
}

type pendingAuthorization struct {
	idempotencyKey string
	envelope       *authorityv1.AuthorizationEnvelope
}

type routeAuthorization struct {
	hostname       string
	version        int
	allowed        *serverv1.AllowedIPPrefixes
	authorization  authorityv1.AuthorizationEnvelope
	nextRenewal    time.Time
	pendingRenewal *pendingAuthorization
	routeToken     credentials.RouteToken
}

func NewLocal(server *serverclient.Client) (*Client, error) {
	if server == nil {
		return nil, errors.New("routeclient: server client is required")
	}
	return &Client{server: server}, nil
}

func NewSigned(
	authorizationReceiver string,
	server *serverclient.Client,
	authority *authorityclient.Client,
	capabilities authorityv1.Capabilities,
) (*Client, error) {
	if server == nil || authority == nil || authorizationReceiver == "" || capabilities.AuthorizationIssuer == "" {
		return nil, errors.New("routeclient: signed route configuration is incomplete")
	}
	return &Client{
		server: server, authority: authority, authorityCapabilities: &capabilities,
		authorizationReceiver: authorizationReceiver,
		routes:                make(map[string]routeAuthorization), pending: make(map[string]pendingAuthorization),
	}, nil
}

func (c *Client) CreateRoute(ctx context.Context, body serverv1.CreateRouteRequest) (serverv1.SessionSetup, error) {
	if c.authority == nil {
		return c.server.CreateRoute(ctx, body)
	}
	body.SignedAuthorization = nil
	allowed, err := canonicalizeIPPrefixes(body.AllowedIpPrefixes)
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	body.AllowedIpPrefixes = allowed
	hash, err := canonicalHash(body)
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	ipHash, err := ipPolicyHash(body.AllowedIpPrefixes)
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	cacheKey := "route.create\x00" + hash
	authorization, err := c.authorization(ctx, cacheKey, authorityv1.IssueAuthorizationRequest{
		Operation: authorityv1.IssueAuthorizationRequestOperationRouteCreate,
		Hostname:  body.Hostname, CanonicalRequestHash: hash, IpPolicyHash: ipHash,
	})
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	setup, err := c.server.CreateRouteAuthorized(ctx, body, authorization.Authorization)
	if err != nil {
		c.finishServerAuthorization(cacheKey, err)
		return setup, err
	}
	c.finishServerAuthorization(cacheKey, nil)
	if setup.Route.Id == "" || setup.Route.Hostname != body.Hostname || setup.Route.LocalTarget != body.LocalTarget ||
		setup.Route.RouteVersion != setup.Session.RouteVersion || setup.Session.RouteId != setup.Route.Id || setup.Route.RouteVersion < 1 {
		return serverv1.SessionSetup{}, errors.New("routeclient: server returned an invalid signed route setup")
	}
	routeToken := credentials.RouteToken(body.RouteToken)
	if _, _, err := credentials.ParseRouteToken(routeToken); err != nil {
		return serverv1.SessionSetup{}, errors.New("routeclient: invalid route credential")
	}
	c.mu.Lock()
	c.routes[setup.Route.Id] = routeAuthorization{
		hostname: body.Hostname, version: setup.Session.RouteVersion, allowed: clonePrefixes(body.AllowedIpPrefixes),
		authorization: authorization, nextRenewal: nextRenewal(authorization), routeToken: routeToken,
	}
	c.mu.Unlock()
	return setup, nil
}

func (c *Client) ListRoutes(ctx context.Context) ([]serverv1.Route, error) {
	if c.authority == nil {
		return c.server.ListRoutes(ctx)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	routes := make([]serverv1.Route, 0, len(c.routes))
	for routeID, route := range c.routes {
		routes = append(routes, serverv1.Route{Id: routeID, Hostname: route.hostname, RouteVersion: route.version})
	}
	return routes, nil
}

func (c *Client) CreateRouteSession(
	ctx context.Context,
	routeID string,
	routeToken credentials.RouteToken,
	allowedIPPrefixes []string,
) (serverv1.SessionSetup, error) {
	allowed, err := canonicalizeIPPrefixes(allowedPrefixesPointer(allowedIPPrefixes))
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	if c.authority == nil {
		return c.server.CreateRouteSession(ctx, routeID, routeToken, allowedIPPrefixes)
	}
	c.mu.Lock()
	route, found := c.routes[routeID]
	c.mu.Unlock()
	if !found || route.routeToken != routeToken {
		return serverv1.SessionSetup{}, errors.New("routeclient: signed route credential is unavailable")
	}
	nextVersion := route.version + 1
	body := serverv1.CreateRouteSessionRequest{
		RouteToken: routeToken.String(), AllowedIpPrefixes: allowed,
	}
	hash, err := canonicalHash(body)
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	ipHash, err := ipPolicyHash(body.AllowedIpPrefixes)
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	cacheKey := fmt.Sprintf("route_session.create\x00%s\x00%d\x00%s", routeID, nextVersion, hash)
	authorization, err := c.authorization(ctx, cacheKey, authorityv1.IssueAuthorizationRequest{
		Operation: authorityv1.IssueAuthorizationRequestOperationRouteSessionCreate,
		Hostname:  route.hostname, RouteId: &routeID, RouteVersion: &nextVersion,
		CanonicalRequestHash: hash, IpPolicyHash: ipHash,
	})
	if err != nil {
		return serverv1.SessionSetup{}, err
	}
	setup, err := c.server.CreateRouteSessionAuthorized(ctx, routeID, body, authorization.Authorization)
	if err != nil {
		c.finishServerAuthorization(cacheKey, err)
		return setup, err
	}
	c.finishServerAuthorization(cacheKey, nil)
	if setup.Route.Id != routeID || setup.Route.Hostname != route.hostname || setup.Route.RouteVersion != nextVersion ||
		setup.Session.RouteId != routeID || setup.Session.RouteVersion != nextVersion {
		return serverv1.SessionSetup{}, errors.New("routeclient: server returned an invalid signed route session")
	}
	c.mu.Lock()
	route.version, route.allowed = nextVersion, clonePrefixes(allowed)
	route.authorization, route.nextRenewal = authorization, nextRenewal(authorization)
	c.routes[routeID] = route
	c.mu.Unlock()
	return setup, nil
}

func (c *Client) DeleteRoute(ctx context.Context, routeID string) error {
	if c.authority == nil {
		return c.server.DeleteRoute(ctx, routeID)
	}
	c.mu.Lock()
	route, found := c.routes[routeID]
	c.mu.Unlock()
	if !found {
		return errors.New("routeclient: signed route credential is unavailable")
	}
	if err := c.server.DeleteRouteAuthorized(ctx, routeID, route.routeToken); err != nil {
		return err
	}
	c.mu.Lock()
	delete(c.routes, routeID)
	c.mu.Unlock()
	return nil
}

func (c *Client) AttachRouteTransport(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	endpoint transportv1.TailcatDescriptor,
) error {
	return c.server.AttachRouteTransport(ctx, routeID, version, sessionToken, endpoint)
}

func (c *Client) Ready(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
) error {
	return c.server.Ready(ctx, routeID, version, sessionToken)
}

func (c *Client) Heartbeat(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
) (serverv1.HeartbeatResponse, error) {
	if c.authority == nil {
		return c.server.Heartbeat(ctx, routeID, version, sessionToken)
	}
	authorization, renewed, err := c.routeAuthorization(ctx, routeID, int(version))
	if err != nil {
		return serverv1.HeartbeatResponse{}, err
	}
	if !renewed {
		return c.server.Heartbeat(ctx, routeID, version, sessionToken)
	}
	response, err := c.server.HeartbeatAuthorized(ctx, routeID, version, sessionToken, authorization)
	if err != nil {
		if !errors.Is(err, serverclient.ErrUnavailable) {
			c.mu.Lock()
			route, found := c.routes[routeID]
			if found && route.pendingRenewal != nil && route.pendingRenewal.envelope != nil &&
				route.pendingRenewal.envelope.Authorization == authorization {
				route.pendingRenewal = nil
				c.routes[routeID] = route
			}
			c.mu.Unlock()
		}
		return serverv1.HeartbeatResponse{}, err
	}
	c.mu.Lock()
	route, found := c.routes[routeID]
	if found && route.pendingRenewal != nil && route.pendingRenewal.envelope != nil &&
		route.pendingRenewal.envelope.Authorization == authorization {
		route.authorization = *route.pendingRenewal.envelope
		route.nextRenewal = nextRenewal(route.authorization)
		route.pendingRenewal = nil
		c.routes[routeID] = route
	}
	c.mu.Unlock()
	return response, nil
}

func (c *Client) CreateCertificateIssuance(
	ctx context.Context,
	routeID string,
	version uint64,
	sessionToken credentials.SessionToken,
	profile string,
	csr []byte,
) (serverv1.CertificateIssuance, error) {
	return c.server.CreateCertificateIssuance(ctx, routeID, version, sessionToken, profile, csr)
}

func (c *Client) CertificateChallengeReady(
	ctx context.Context,
	issuanceID string,
	sessionToken credentials.SessionToken,
) (serverv1.CertificateIssuance, error) {
	return c.server.CertificateChallengeReady(ctx, issuanceID, sessionToken)
}

func (c *Client) CertificateChallengeRemoved(
	ctx context.Context,
	issuanceID string,
	sessionToken credentials.SessionToken,
) error {
	return c.server.CertificateChallengeRemoved(ctx, issuanceID, sessionToken)
}

func (c *Client) CertificateInstalled(
	ctx context.Context,
	routeID string,
	version uint64,
	issuanceID string,
	sessionToken credentials.SessionToken,
) error {
	return c.server.CertificateInstalled(ctx, routeID, version, issuanceID, sessionToken)
}

func (c *Client) routeAuthorization(ctx context.Context, routeID string, version int) (string, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	route, found := c.routes[routeID]
	if !found || route.version != version {
		return "", false, errors.New("routeclient: signed route authorization is unavailable")
	}
	if route.pendingRenewal != nil && route.pendingRenewal.envelope != nil {
		return route.pendingRenewal.envelope.Authorization, true, nil
	}
	if route.pendingRenewal == nil && time.Now().Before(route.nextRenewal) {
		return "", false, nil
	}
	body := serverv1.HeartbeatRouteSessionRequest{RouteVersion: version}
	hash, err := canonicalHash(body)
	if err != nil {
		return "", false, err
	}
	ipHash, err := ipPolicyHash(route.allowed)
	if err != nil {
		return "", false, err
	}
	request := authorityv1.IssueAuthorizationRequest{
		Operation: authorityv1.IssueAuthorizationRequestOperationAuthorizationRenew,
		Hostname:  route.hostname, RouteId: &routeID, RouteVersion: &version,
		CanonicalRequestHash: hash, IpPolicyHash: ipHash,
	}
	if route.pendingRenewal == nil {
		idempotencyKey, err := randomIdempotencyKey()
		if err != nil {
			return "", false, err
		}
		route.pendingRenewal = &pendingAuthorization{idempotencyKey: idempotencyKey}
		c.routes[routeID] = route
	}
	issued, err := c.authority.IssueAuthorization(ctx, request, route.pendingRenewal.idempotencyKey)
	if err != nil {
		if !errors.Is(err, authorityclient.ErrUnavailable) {
			route.pendingRenewal = nil
			c.routes[routeID] = route
		}
		return "", false, mapAuthorityError(err)
	}
	if err := c.validateAuthorization(issued, request); err != nil {
		route.pendingRenewal = nil
		c.routes[routeID] = route
		return "", false, err
	}
	if issued.Claims.AuthorizationId == route.authorization.Claims.AuthorizationId ||
		issued.Claims.RetryId == route.authorization.Claims.RetryId ||
		issued.Claims.Kid != route.authorization.Claims.Kid ||
		issued.Claims.Revision < route.authorization.Claims.Revision ||
		!issued.Claims.ExpiresAt.After(route.authorization.Claims.ExpiresAt) {
		route.pendingRenewal = nil
		c.routes[routeID] = route
		return "", false, errors.New("routeclient: authorization authority returned an invalid renewal")
	}
	route.pendingRenewal.envelope = &issued
	c.routes[routeID] = route
	return issued.Authorization, true, nil
}

func (c *Client) authorization(
	ctx context.Context,
	cacheKey string,
	request authorityv1.IssueAuthorizationRequest,
) (authorityv1.AuthorizationEnvelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	pending, found := c.pending[cacheKey]
	if found && pending.envelope != nil && pending.envelope.Claims.ExpiresAt.After(time.Now().Add(30*time.Second)) {
		return *pending.envelope, nil
	}
	if !found || pending.envelope != nil {
		idempotencyKey, err := randomIdempotencyKey()
		if err != nil {
			return authorityv1.AuthorizationEnvelope{}, err
		}
		pending = pendingAuthorization{idempotencyKey: idempotencyKey}
		c.pending[cacheKey] = pending
	}
	issued, err := c.authority.IssueAuthorization(ctx, request, pending.idempotencyKey)
	if err != nil {
		if !errors.Is(err, authorityclient.ErrUnavailable) {
			delete(c.pending, cacheKey)
		}
		return authorityv1.AuthorizationEnvelope{}, mapAuthorityError(err)
	}
	if err := c.validateAuthorization(issued, request); err != nil {
		delete(c.pending, cacheKey)
		return authorityv1.AuthorizationEnvelope{}, err
	}
	pending.envelope = &issued
	c.pending[cacheKey] = pending
	return issued, nil
}

func (c *Client) finishServerAuthorization(cacheKey string, err error) {
	if err != nil && errors.Is(err, serverclient.ErrUnavailable) {
		return
	}
	c.mu.Lock()
	delete(c.pending, cacheKey)
	c.mu.Unlock()
}

func (c *Client) validateAuthorization(
	envelope authorityv1.AuthorizationEnvelope,
	request authorityv1.IssueAuthorizationRequest,
) error {
	claims := envelope.Claims
	if len(envelope.Authorization) == 0 || len(envelope.Authorization) > 4096 ||
		claims.Version != authorityv1.N1 || claims.Alg != authorityv1.AuthorizationClaimsAlgEdDSA ||
		claims.Kid != c.authorityCapabilities.AuthorizationKey.Kid ||
		string(claims.Operation) != string(request.Operation) || claims.Issuer != c.authorityCapabilities.AuthorizationIssuer ||
		claims.Receiver != c.authorizationReceiver || claims.Hostname != request.Hostname ||
		claims.CanonicalRequestHash != request.CanonicalRequestHash || !equalDigest(claims.IpPolicyHash, request.IpPolicyHash) ||
		!equalOptional(claims.RouteId, request.RouteId) || !equalOptionalInt(claims.RouteVersion, request.RouteVersion) ||
		claims.IssuedAt.IsZero() || claims.IssuedAt.After(time.Now().Add(30*time.Second)) ||
		!claims.ExpiresAt.After(time.Now().Add(30*time.Second)) ||
		!claims.ExpiresAt.After(claims.IssuedAt) || claims.ExpiresAt.Sub(claims.IssuedAt) > time.Hour || claims.Revision < 1 ||
		!validID(claims.AuthorizationId, "authorization_") || !validID(claims.RetryId, "retry_") {
		return errors.New("routeclient: authorization authority returned an invalid authorization")
	}
	return nil
}

func canonicalHash(value any) (string, error) {
	canonical, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("routeclient: canonicalize authorized operation request: %w", err)
	}
	digest := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(digest[:]), nil
}

func ipPolicyHash(prefixes *serverv1.AllowedIPPrefixes) (*authorityv1.SHA256Digest, error) {
	if prefixes == nil {
		return nil, nil
	}
	digest, err := canonicalHash(*prefixes)
	if err != nil {
		return nil, err
	}
	return &digest, nil
}

func canonicalizeIPPrefixes(prefixes *serverv1.AllowedIPPrefixes) (*serverv1.AllowedIPPrefixes, error) {
	if prefixes == nil {
		return nil, nil
	}
	canonical, err := authorization.CanonicalizeIPPrefixes([]string(*prefixes))
	if err != nil {
		return nil, fmt.Errorf("routeclient: canonicalize allowed IP prefixes: %w", err)
	}
	result := serverv1.AllowedIPPrefixes(canonical)
	return &result, nil
}

func allowedPrefixesPointer(prefixes []string) *serverv1.AllowedIPPrefixes {
	if prefixes == nil {
		return nil
	}
	allowed := serverv1.AllowedIPPrefixes(prefixes)
	return &allowed
}

func nextRenewal(envelope authorityv1.AuthorizationEnvelope) time.Time {
	renew := envelope.Claims.IssuedAt.Add(authorizationRenewalInterval)
	expiryMargin := envelope.Claims.ExpiresAt.Add(-30 * time.Second)
	if expiryMargin.Before(renew) {
		return expiryMargin
	}
	return renew
}

func mapAuthorityError(err error) error {
	var limited *authorityclient.RateLimitError
	if errors.Is(err, authorityclient.ErrUnavailable) {
		return fmt.Errorf("%w: %v", serverclient.ErrUnavailable, err)
	}
	if errors.As(err, &limited) {
		return &serverclient.RateLimitError{RetryAfter: limited.RetryAfter}
	}
	return err
}

func clonePrefixes(prefixes *serverv1.AllowedIPPrefixes) *serverv1.AllowedIPPrefixes {
	if prefixes == nil {
		return nil
	}
	cloned := slices.Clone(*prefixes)
	return &cloned
}

func equalDigest(left, right *authorityv1.SHA256Digest) bool {
	return equalOptional(left, right)
}

func equalOptional(left, right *string) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func equalOptionalInt(left, right *int) bool {
	return left == nil && right == nil || left != nil && right != nil && *left == *right
}

func validID(value, prefix string) bool {
	return opaqueid.Valid(value, prefix)
}

func randomIdempotencyKey() (string, error) {
	key, err := opaqueid.New("random_")
	if err != nil {
		return "", fmt.Errorf("routeclient: generate idempotency key: %w", err)
	}
	return key, nil
}
