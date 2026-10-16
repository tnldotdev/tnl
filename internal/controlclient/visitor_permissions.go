package controlclient

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
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

func (c *Client) CreateIdentityVisitorGrant(ctx context.Context, id, key string, body controlv1.CreateIdentityVisitorGrantRequest) (controlv1.VisitorGrant, error) {
	return requestWithAccess[controlv1.VisitorGrant](ctx, c, func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.CreateIdentityVisitorGrant(ctx, id, &controlv1.CreateIdentityVisitorGrantParams{IdempotencyKey: key}, body, e...)
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
	result, err := c.authorizeVisitorCertificate(ctx, scope, state, nil)
	if err != nil {
		return time.Time{}, err
	}
	if result.ValidUntil != nil {
		return *result.ValidUntil, nil
	}
	return time.Time{}, nil
}

// SSHVisitorDecision is a current identity and optional exact-account decision.
// an empty SSHUser permits only proceeding to account authentication.
type SSHVisitorDecision struct {
	IdentityID, PublicURLID, SSHUser string
	ValidUntil                       time.Time
}

// AuthorizeSSHVisitor requires a visitor certificate even for an allowed IP.
// an empty username checks for any explicit SSH grant, never shell access.
func (c *Client) AuthorizeSSHVisitor(ctx context.Context, scope VisitorCertificateScope, state tls.ConnectionState, username string) (SSHVisitorDecision, error) {
	if len(state.PeerCertificates) == 0 || username != "" && !authorization.SSHUserValid(username) {
		return SSHVisitorDecision{}, errors.New("SSH visitor certificate and valid account are required")
	}
	var user *string
	if username != "" {
		user = &username
	}
	result, err := c.authorizeVisitorCertificate(ctx, scope, state, user)
	if err != nil {
		return SSHVisitorDecision{}, err
	}
	if result.IdentityID == "" || result.SSHUser != username || result.ValidUntil == nil ||
		!result.ValidUntil.After(time.Now()) || result.ValidUntil.After(state.PeerCertificates[0].NotAfter) {
		return SSHVisitorDecision{}, errors.New("SSH visitor decision has an invalid scope or deadline")
	}
	return SSHVisitorDecision{IdentityID: result.IdentityID, PublicURLID: result.PublicURLID, SSHUser: result.SSHUser, ValidUntil: *result.ValidUntil}, nil
}

type visitorCertificateDecision struct {
	IdentityID  string     `json:"identity_id,omitempty"`
	PublicURLID string     `json:"public_url_id"`
	SSHUser     string     `json:"ssh_user,omitempty"`
	ValidUntil  *time.Time `json:"valid_until,omitempty"`
}

func (c *Client) authorizeVisitorCertificate(ctx context.Context, scope VisitorCertificateScope, state tls.ConnectionState, username *string) (visitorCertificateDecision, error) {
	if !state.HandshakeComplete || len(state.PeerCertificates) > 4 || len(state.PeerCertificates) > 0 && state.PeerCertificates[0] == nil || scope.PublicURLID == "" || scope.PublishRunID == "" || scope.PublishRunNumber == 0 || scope.PublishRunNumber > 1<<63-1 || scope.PublishRunToken == "" || !scope.SourceIP.IsValid() || scope.SourceIP.Zone() != "" {
		return visitorCertificateDecision{}, errors.New("visitor certificate proof is missing")
	}
	body := controlv1.AuthorizeVisitorCertificateJSONRequestBody{PublishRunNumber: int64(scope.PublishRunNumber), SourceIp: scope.SourceIP.Unmap().String(), SshUser: username}
	if len(state.PeerCertificates) > 0 {
		encoded := base64.StdEncoding.EncodeToString(state.PeerCertificates[0].Raw)
		body.Certificate = &encoded
	}
	result, err := request[visitorCertificateDecision](ctx, c, scope.PublishRunToken.String(), func(ctx context.Context, e ...controlv1.RequestEditorFn) (*http.Response, error) {
		return c.api.AuthorizeVisitorCertificate(ctx, scope.PublishRunID, body, e...)
	})
	if err != nil {
		return visitorCertificateDecision{}, err
	}
	if result.PublicURLID != scope.PublicURLID || body.Certificate != nil && result.IdentityID == "" {
		return visitorCertificateDecision{}, errors.New("visitor certificate decision has a different scope")
	}
	return result, nil
}
