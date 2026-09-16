// Package authorityclient calls the authority API.
//
// Responses cannot exceed 64 KiB. A nonempty successful response must contain
// one JSON value that matches the generated schema. Numbers in open objects stay
// as json.Number. Requests time out after 20 seconds. Network and read failures
// wrap ErrUnavailable, but invalid or oversized responses do not. HTTP 429 and
// 503 are handled before the client reads a problem response.
package authorityclient

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

const (
	maxResponseBytes      = 64 << 10
	defaultRequestTimeout = 20 * time.Second
)

var (
	ErrUnauthenticated = errors.New("authorityclient: unauthenticated")
	ErrNotFound        = errors.New("authorityclient: not found")
	ErrDNSProofPending = errors.New("authorityclient: DNS proof pending")
	ErrRateLimited     = errors.New("authorityclient: rate limited")
	ErrUnavailable     = errors.New("authorityclient: temporarily unavailable")
)

type Client struct {
	api     *authorityv1.Client
	access  credentials.AccessToken
	timeout time.Duration
}

func New(endpoint string, httpClient *http.Client, access credentials.AccessToken) (*Client, error) {
	canonical, err := clientstate.CanonicalServer(endpoint)
	if err != nil || canonical != endpoint {
		return nil, errors.New("authorityclient: endpoint must be a canonical HTTPS origin")
	}
	if httpClient == nil {
		httpClient = &http.Client{}
	}
	apiClient, err := authorityv1.NewClient(
		canonical,
		authorityv1.WithHTTPClient(httpClient),
		authorityv1.WithRequestEditorFn(func(_ context.Context, request *http.Request) error {
			request.Header.Set("Accept", "application/json, application/problem+json")
			return nil
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("authorityclient: configure generated client: %w", err)
	}
	return &Client{api: apiClient, access: access, timeout: defaultRequestTimeout}, nil
}

func (c *Client) Exchange(ctx context.Context, token credentials.LoginToken) (authorityv1.ControlSessionResponse, error) {
	body := authorityv1.LoginTokenExchangeRequest{LoginToken: token.String()}
	return request[authorityv1.ControlSessionResponse](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ExchangeLoginToken(ctx, body, editors...)
	})
}

func (c *Client) ExchangeOIDC(ctx context.Context, token string) (authorityv1.ControlSessionResponse, error) {
	body := authorityv1.OIDCTokenExchangeRequest{IdToken: token}
	return request[authorityv1.ControlSessionResponse](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ExchangeOIDCToken(ctx, body, editors...)
	})
}

func (c *Client) Refresh(ctx context.Context, token credentials.RefreshToken) (authorityv1.ControlSessionResponse, error) {
	body := authorityv1.RefreshControlSessionRequest{RefreshToken: token.String()}
	return request[authorityv1.ControlSessionResponse](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RefreshControlSession(ctx, body, editors...)
	})
}

func (c *Client) LogoutWithAccessToken(ctx context.Context, token credentials.AccessToken) error {
	_, err := requestWithToken[struct{}](ctx, c, token.String(), c.api.LogoutControlSession)
	return err
}

func (c *Client) IdentityContext(ctx context.Context) (authorityv1.IdentityContext, error) {
	return request[authorityv1.IdentityContext](ctx, c, c.api.GetIdentityContext)
}

func (c *Client) IdentityContextWithAccessToken(
	ctx context.Context,
	token credentials.AccessToken,
) (authorityv1.IdentityContext, error) {
	return requestWithToken[authorityv1.IdentityContext](ctx, c, token.String(), c.api.GetIdentityContext)
}

func (c *Client) ListTeams(ctx context.Context) (authorityv1.TeamPage, error) {
	return request[authorityv1.TeamPage](ctx, c, c.api.ListTeams)
}

func (c *Client) CreateTeam(ctx context.Context, body authorityv1.CreateTeamRequest, idempotencyKey string) (authorityv1.Team, error) {
	params := &authorityv1.CreateTeamParams{IdempotencyKey: idempotencyKey}
	return request[authorityv1.Team](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateTeam(ctx, params, body, editors...)
	})
}

func (c *Client) GetTeam(ctx context.Context, teamID string) (authorityv1.Team, error) {
	return request[authorityv1.Team](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.GetTeam(ctx, teamID, editors...)
	})
}

func (c *Client) ListTeamMemberships(ctx context.Context, teamID string) (authorityv1.MembershipPage, error) {
	return request[authorityv1.MembershipPage](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListTeamMemberships(ctx, teamID, editors...)
	})
}

func (c *Client) SetMembershipRole(ctx context.Context, teamID, membershipID string, role authorityv1.TeamRole) (authorityv1.Membership, error) {
	body := authorityv1.SetMembershipRoleRequest{Role: role}
	return request[authorityv1.Membership](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetMembershipRole(ctx, teamID, membershipID, body, editors...)
	})
}

func (c *Client) RemoveMembership(ctx context.Context, teamID, membershipID string) error {
	_, err := request[struct{}](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RemoveMembership(ctx, teamID, membershipID, editors...)
	})
	return err
}

func (c *Client) ListTeamInvitations(ctx context.Context, teamID string) (authorityv1.InvitationPage, error) {
	return request[authorityv1.InvitationPage](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListTeamInvitations(ctx, teamID, editors...)
	})
}

func (c *Client) CreateTeamInvitation(ctx context.Context, teamID string, body authorityv1.CreateInvitationRequest, idempotencyKey string) (authorityv1.InvitationSecret, error) {
	params := &authorityv1.CreateTeamInvitationParams{IdempotencyKey: idempotencyKey}
	return request[authorityv1.InvitationSecret](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateTeamInvitation(ctx, teamID, params, body, editors...)
	})
}

func (c *Client) RevokeTeamInvitation(ctx context.Context, teamID, invitationID string) error {
	_, err := request[struct{}](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeTeamInvitation(ctx, teamID, invitationID, editors...)
	})
	return err
}

func (c *Client) AcceptInvitation(ctx context.Context, secret string) (authorityv1.Membership, error) {
	body := authorityv1.AcceptInvitationRequest{Secret: secret}
	return request[authorityv1.Membership](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcceptInvitation(ctx, body, editors...)
	})
}

func (c *Client) ListTeamDomains(ctx context.Context, teamID string) (authorityv1.DomainPage, error) {
	return request[authorityv1.DomainPage](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListTeamDomains(ctx, teamID, editors...)
	})
}

func (c *Client) ClaimTeamDomain(ctx context.Context, teamID, domain, idempotencyKey string, makeDefault bool) (authorityv1.Domain, error) {
	params := &authorityv1.ClaimTeamDomainParams{IdempotencyKey: idempotencyKey}
	body := authorityv1.ClaimDomainRequest{Domain: domain, MakeDefault: &makeDefault}
	return request[authorityv1.Domain](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ClaimTeamDomain(ctx, teamID, params, body, editors...)
	})
}

func (c *Client) SetTeamDefaultDomain(ctx context.Context, teamID, domainID string) (authorityv1.Team, error) {
	return request[authorityv1.Team](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.SetTeamDefaultDomain(ctx, teamID, domainID, editors...)
	})
}

func (c *Client) ReleaseTeamDomain(ctx context.Context, teamID, domainID string) error {
	_, err := request[struct{}](ctx, c, func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReleaseTeamDomain(ctx, teamID, domainID, editors...)
	})
	return err
}

// AuthorizeServiceOperation asks the external authority to authorize an
// operation. It uses the hosted secret instead of the user's access token.
func (c *Client) AuthorizeServiceOperation(
	ctx context.Context,
	serviceSecret string,
	body authorityv1.ServiceAuthorizationRequest,
) (authorityv1.ServiceAuthorizationDecision, error) {
	return requestWithToken[authorityv1.ServiceAuthorizationDecision](
		ctx,
		c,
		serviceSecret,
		func(ctx context.Context, editors ...authorityv1.RequestEditorFn) (*http.Response, error) {
			return c.api.AuthorizeServiceOperation(ctx, body, editors...)
		},
	)
}

type authorityRequest func(context.Context, ...authorityv1.RequestEditorFn) (*http.Response, error)

func request[T any](ctx context.Context, client *Client, call authorityRequest) (T, error) {
	return requestWithToken[T](ctx, client, client.access.String(), call)
}

func requestWithToken[T any](ctx context.Context, client *Client, token string, call authorityRequest) (T, error) {
	var zero T
	requestCtx, cancel := context.WithTimeout(ctx, client.timeout)
	defer cancel()
	response, err := call(requestCtx, func(_ context.Context, request *http.Request) error {
		if token != "" {
			request.Header.Set("Authorization", "Bearer "+token)
		}
		return nil
	})
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	defer response.Body.Close()
	payload, err := httpjson.ReadAll(response.Body, maxResponseBytes)
	if errors.Is(err, httpjson.ErrTooLarge) {
		return zero, errors.New("authorityclient: response exceeds limit")
	}
	if err != nil {
		return zero, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return zero, responseError(response.StatusCode, response.Header, payload)
	}
	if len(payload) == 0 {
		return zero, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.UseNumber()
	var result T
	err = httpjson.Decode(decoder, &result)
	if errors.Is(err, httpjson.ErrTrailingContent) {
		return zero, errors.New("authorityclient: response contains trailing JSON")
	}
	if err != nil {
		return zero, fmt.Errorf("authorityclient: decode response: %w", err)
	}
	return result, nil
}

// ValidateControlSessionResponse checks credentials and session data returned by the authority.
func ValidateControlSessionResponse(response authorityv1.ControlSessionResponse, expectedSessionID string, expectedRefreshExpiry time.Time) (clientstate.ControlSession, error) {
	access := credentials.AccessToken(response.AccessToken)
	refresh := credentials.RefreshToken(response.RefreshToken)
	if _, _, err := credentials.ParseAccessToken(access); err != nil {
		return clientstate.ControlSession{}, errors.New("authorityclient: authority returned an invalid access token")
	}
	if _, _, err := credentials.ParseRefreshToken(refresh); err != nil {
		return clientstate.ControlSession{}, errors.New("authorityclient: authority returned an invalid refresh token")
	}
	if !opaqueid.Valid(response.SessionId, "control_session_") || expectedSessionID != "" && response.SessionId != expectedSessionID ||
		!response.AccessExpiresAt.After(time.Now()) || response.RefreshExpiresAt.Before(response.AccessExpiresAt) ||
		!expectedRefreshExpiry.IsZero() && !response.RefreshExpiresAt.Equal(expectedRefreshExpiry) {
		return clientstate.ControlSession{}, errors.New("authorityclient: authority returned an invalid control session")
	}
	return clientstate.ControlSession{
		SessionID: response.SessionId, AccessToken: access.String(), AccessExpiresAt: response.AccessExpiresAt,
		RefreshToken: refresh.String(), RefreshExpiresAt: response.RefreshExpiresAt,
	}, nil
}

func responseError(status int, header http.Header, payload []byte) error {
	var problem authorityv1.Problem
	if status == http.StatusTooManyRequests {
		seconds, err := strconv.ParseInt(header.Get("Retry-After"), 10, 64)
		if err != nil || seconds < 1 {
			seconds = 1
		}
		return &RateLimitError{RetryAfter: time.Duration(min(seconds, 86400)) * time.Second}
	}
	if status == http.StatusServiceUnavailable {
		return ErrUnavailable
	}
	if json.Unmarshal(payload, &problem) != nil {
		return fmt.Errorf("authorityclient: HTTP %d", status)
	}
	switch problem.Code {
	case authorityv1.Unauthenticated:
		return ErrUnauthenticated
	case authorityv1.NotFound:
		return ErrNotFound
	case authorityv1.DnsSetupPending:
		return ErrDNSProofPending
	case authorityv1.Unavailable:
		return ErrUnavailable
	}
	return &ProblemError{Status: status, Problem: problem}
}

type RateLimitError struct{ RetryAfter time.Duration }

func (e *RateLimitError) Error() string { return "authorityclient: rate limited" }
func (e *RateLimitError) Unwrap() error { return ErrRateLimited }

type ProblemError struct {
	Status  int
	Problem authorityv1.Problem
}

func (e *ProblemError) Error() string {
	return "authorityclient: HTTP " + strconv.Itoa(e.Status) + ": " + e.Problem.Title
}
