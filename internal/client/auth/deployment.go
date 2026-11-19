package auth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

const deploymentTokenPrefix = "tnc_"

var ErrDeploymentCredential = failure.Wrap("read deployment credential", failure.Authentication, errors.New("deployment credential is invalid or expired; create a current credential with tnl auth credential create"))

// the portable value selects a signing key and server, not authority. control
// checks the current key, grant, deployments and service approvals on every use.
type DeploymentCredential struct {
	Version    int                            `json:"version"`
	ControlURL string                         `json:"control_url"`
	Team       string                         `json:"team"`
	Approval   controlv1.DeploymentCredential `json:"approval"`
	PrivateKey string                         `json:"private_key"`
}

func (DeploymentCredential) String() string   { return "private deployment credential" }
func (DeploymentCredential) GoString() string { return "private deployment credential" }

func (c DeploymentCredential) key() (ed25519.PrivateKey, error) {
	server, err := naming.CanonicalControlURL(c.ControlURL)
	a := c.Approval
	if err != nil || c.Version != 1 || server != c.ControlURL || !naming.ValidAuthorityLabel(c.Team) || !naming.ValidProjectKey(a.ProjectKey) ||
		!opaqueid.Valid(a.TeamId, opaqueid.TeamPrefix) || !opaqueid.Valid(a.ClientId, opaqueid.PublisherIdentityPrefix) ||
		!opaqueid.Valid(a.KeyId, opaqueid.PublisherIdentityKeyPrefix) || !opaqueid.Valid(a.GrantId, opaqueid.PublisherGrantPrefix) || !a.ExpiresAt.After(time.Now()) {
		return nil, ErrDeploymentCredential
	}
	key, err := base64.RawURLEncoding.DecodeString(c.PrivateKey)
	if err != nil || len(key) != ed25519.PrivateKeySize || base64.RawURLEncoding.EncodeToString(key) != c.PrivateKey || !bytes.Equal(ed25519.NewKeyFromSeed(key[:ed25519.SeedSize]), key) {
		return nil, ErrDeploymentCredential
	}
	return ed25519.PrivateKey(key), nil
}

func (c DeploymentCredential) Encode() (string, error) {
	if _, err := c.key(); err != nil {
		return "", err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return "", ErrDeploymentCredential
	}
	return deploymentTokenPrefix + base64.RawURLEncoding.EncodeToString(data), nil
}

func ParseDeploymentCredential(token string) (DeploymentCredential, error) {
	var c DeploymentCredential
	if !strings.HasPrefix(token, deploymentTokenPrefix) || len(token) > 32<<10 {
		return c, ErrDeploymentCredential
	}
	encoded := strings.TrimPrefix(token, deploymentTokenPrefix)
	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(data) != encoded || jsonv2.Unmarshal(data, &c, jsonv2.RejectUnknownMembers(true)) != nil {
		return DeploymentCredential{}, ErrDeploymentCredential
	}
	if _, err := c.key(); err != nil {
		return DeploymentCredential{}, err
	}
	return c, nil
}

// matches friendly project selection without a checkout or a team-list request.
// the exact team ID in approval is used on the wire; a matching name grants nothing.
func (c DeploymentCredential) SelectProject(project string) error {
	team, key, ok := strings.Cut(project, "/")
	if !ok || (team != c.Team && team != c.Approval.TeamId) || key != c.Approval.ProjectKey {
		return ErrDeploymentCredential
	}
	return nil
}

func (c DeploymentCredential) Subject() tunnelv1.VisitorSubject {
	return tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorRegisteredKey, GrantID: c.Approval.GrantId, KeyID: c.Approval.KeyId}
}

func (c DeploymentCredential) PublicKey() (ed25519.PublicKey, error) {
	key, err := c.key()
	if err != nil {
		return nil, err
	}
	return key.Public().(ed25519.PublicKey), nil
}

func (c DeploymentCredential) Sign(message []byte) ([]byte, error) {
	key, err := c.key()
	if err != nil {
		return nil, err
	}
	return ed25519.Sign(key, message), nil
}

// each application owner has a bounded token cache. no signing key or bearer is
// written to connection snapshots, registry records, command arguments or logs.
type DeploymentTokenSource struct {
	Credential DeploymentCredential
	authority  *clientauthority.Client
	mu         sync.Mutex
	token      string
	until      time.Time
}

func (*DeploymentTokenSource) String() string   { return "private deployment token source" }
func (*DeploymentTokenSource) GoString() string { return "private deployment token source" }

func NewDeploymentTokenSource(c DeploymentCredential, httpClient *http.Client) (*DeploymentTokenSource, error) {
	if _, err := c.key(); err != nil {
		return nil, err
	}
	authority, err := clientauthority.New(c.ControlURL, httpClient, "")
	if err != nil {
		return nil, err
	}
	return &DeploymentTokenSource{Credential: c, authority: authority}, nil
}

func (s *DeploymentTokenSource) Token(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key, err := s.Credential.key()
	if err != nil {
		return "", err
	}
	if s.until.After(time.Now().Add(30 * time.Second)) {
		return s.token, nil
	}
	a := s.Credential.Approval
	started := time.Now()
	value, err := s.authority.ExchangePublisherToken(ctx, a.ClientId, a.GrantId, a.KeyId, key)
	if err != nil {
		return "", err
	}
	s.token, s.until = value.AccessToken, minDeadline(started.Add(time.Duration(value.ExpiresIn)*time.Second), a.ExpiresAt)
	return s.token, nil
}

func (s *DeploymentTokenSource) ExpiresAt() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.until
}

func minDeadline(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
