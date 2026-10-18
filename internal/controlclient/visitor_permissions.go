package controlclient

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func (c *Client) ListAvailablePublicURLs(ctx context.Context, teamID, cursor string) (controlv1.AvailablePublicURLPage, error) {
	p := &controlv1.ListAvailablePublicURLsParams{}
	if teamID != "" {
		p.TeamId = &teamID
	}
	if cursor != "" {
		p.Cursor = &cursor
	}
	return requestWithAccess[controlv1.AvailablePublicURLPage](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListAvailablePublicURLs(ctx, p, e...)
	})
}
func (c *Client) CreateTeamVisitorGrant(ctx context.Context, id, key string, body controlv1.CreateTeamVisitorGrantRequest) (controlv1.VisitorGrant, error) {
	return requestWithAccess[controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateTeamVisitorGrant(ctx, id, &controlv1.CreateTeamVisitorGrantParams{IdempotencyKey: key}, body, e...)
	})
}

func (c *Client) ListVisitorGrants(ctx context.Context, id string) ([]controlv1.VisitorGrant, error) {
	return requestWithAccess[[]controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListVisitorGrants(ctx, id, e...)
	})
}
func (c *Client) RevokeVisitorGrant(ctx context.Context, id, grantID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeVisitorGrant(ctx, id, grantID, e...)
	})
	return err
}
func (c *Client) CreateVisitorInvitation(ctx context.Context, id, key string, body controlv1.CreateVisitorInvitationRequest) (controlv1.VisitorInvitation, error) {
	return requestWithAccess[controlv1.VisitorInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateVisitorInvitation(ctx, id, &controlv1.CreateVisitorInvitationParams{IdempotencyKey: key}, body, e...)
	})
}
func (c *Client) ListVisitorInvitations(ctx context.Context, id string) ([]controlv1.VisitorInvitation, error) {
	return requestWithAccess[[]controlv1.VisitorInvitation](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ListVisitorInvitations(ctx, id, e...)
	})
}
func (c *Client) RevokeVisitorInvitation(ctx context.Context, id, inviteID string) error {
	_, err := requestWithAccess[struct{}](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.RevokeVisitorInvitation(ctx, id, inviteID, e...)
	})
	return err
}
func (c *Client) AcceptVisitorInvitation(ctx context.Context, secret string) (controlv1.VisitorGrant, error) {
	return requestWithAccess[controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AcceptVisitorInvitation(ctx, controlv1.AcceptVisitorInvitationJSONRequestBody{Secret: secret}, e...)
	})
}
func (c *Client) ReplaceVisitorAccess(ctx context.Context, id string, body controlv1.ReplaceVisitorAccessRequest) (controlv1.PublicURL, error) {
	return requestWithAccess[controlv1.PublicURL](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.ReplaceVisitorAccess(ctx, id, body, e...)
	})
}
func (c *Client) IssueVisitorCertificate(ctx context.Context, id string, csr []byte) (controlv1.VisitorCertificate, error) {
	return requestWithAccess[controlv1.VisitorCertificate](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.IssueVisitorCertificate(ctx, id, controlv1.IssueVisitorCertificateJSONRequestBody{Csr: base64.StdEncoding.EncodeToString(csr)}, e...)
	})
}

// VisitorCertificateScope must come from the active publisher run, never from
// SNI, database startup fields, or HTTP input. the token remains control-only.
type VisitorCertificateScope struct {
	PublishRunID, PublicURLID string
	PublishRunNumber          uint64
	PublishRunToken           credentials.PublishRunToken
	SourceIP                  netip.Addr
}

func (c *Client) AuthorizeVisitorCertificate(ctx context.Context, scope VisitorCertificateScope, state tls.ConnectionState) error {
	_, err := c.AuthorizeVisitorCertificateDecision(ctx, scope, state)
	return err
}

// AuthorizeVisitorCertificateDecision returns the current decision's hard
// deadline for subsequent connections with the same scoped proof.
func (c *Client) AuthorizeVisitorCertificateDecision(ctx context.Context, scope VisitorCertificateScope, state tls.ConnectionState) (time.Time, error) {
	if !state.HandshakeComplete || len(state.PeerCertificates) > 4 || scope.PublicURLID == "" || scope.PublishRunID == "" || scope.PublishRunNumber == 0 || scope.PublishRunNumber > 1<<63-1 || scope.PublishRunToken == "" || !scope.SourceIP.IsValid() || scope.SourceIP.Zone() != "" {
		return time.Time{}, errors.New("visitor certificate proof is missing")
	}
	body := controlv1.AuthorizeVisitorCertificateJSONRequestBody{PublishRunNumber: int64(scope.PublishRunNumber), SourceIp: scope.SourceIP.Unmap().String()}
	if len(state.PeerCertificates) > 0 {
		encoded := base64.StdEncoding.EncodeToString(state.PeerCertificates[0].Raw)
		body.Certificate = &encoded
	}
	result, err := request[struct {
		IdentityID  string     `json:"identity_id,omitempty"`
		PublicURLID string     `json:"public_url_id"`
		ValidUntil  *time.Time `json:"valid_until,omitempty"`
	}](ctx, c, scope.PublishRunToken.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeVisitorCertificate(ctx, scope.PublishRunID, body, e...)
	})
	if err != nil {
		return time.Time{}, err
	}
	if result.PublicURLID != scope.PublicURLID || body.Certificate != nil && result.IdentityID == "" {
		return time.Time{}, errors.New("visitor certificate decision has a different scope")
	}
	if result.ValidUntil != nil {
		return *result.ValidUntil, nil
	}
	return time.Time{}, nil
}
