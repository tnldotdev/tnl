package oidcauth

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tnldotdev/tnl/internal/httpclient"
)

const GitHubIssuer = "https://token.actions.githubusercontent.com"
const githubJWKS = GitHubIssuer + "/.well-known/jwks"

var githubNumericID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)

// GitHubExecution contains issuer-signed job provenance, never a human identity.
// check_run_id is GitHub's signed job boundary; GITHUB_JOB is not an identity.
type GitHubExecution struct {
	Subject           string   `json:"sub"`
	JTI               string   `json:"jti"`
	Repository        string   `json:"repository"`
	RepositoryID      string   `json:"repository_id"`
	RepositoryOwnerID string   `json:"repository_owner_id"`
	WorkflowRef       string   `json:"workflow_ref"`
	Ref               string   `json:"ref"`
	Event             string   `json:"event_name"`
	Environment       string   `json:"environment,omitempty"`
	JobWorkflowRef    string   `json:"job_workflow_ref,omitempty"`
	RunID             string   `json:"run_id"`
	RunAttempt        string   `json:"run_attempt"`
	CheckRunID        string   `json:"check_run_id"`
	IssuedAt          int64    `json:"iat"`
	NotBefore         int64    `json:"nbf"`
	ExpiresAt         int64    `json:"exp"`
	AssertionDigest   [32]byte `json:"-"`
}

type GitHubWorkloadVerifier struct {
	keys     oidc.KeySet
	client   *http.Client
	audience string
}

// the canonical control origin is the audience. issuer and key URL are fixed;
// local tests inject an HTTP transport, never a runtime issuer override.
func NewGitHubWorkloadVerifier(controlOrigin string, client *http.Client) (*GitHubWorkloadVerifier, error) {
	u, err := url.Parse(controlOrigin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, errors.New("workload audience requires a canonical HTTPS control origin")
	}
	audience := "https://" + strings.ToLower(u.Host)
	audience = strings.TrimSuffix(audience, ":443")
	c := httpclient.NoRedirects(client)
	if c.Timeout <= 0 || c.Timeout > 10*time.Second {
		c.Timeout = 10 * time.Second
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = keyFetchTransport{base: base}
	return &GitHubWorkloadVerifier{audience: audience, client: c, keys: oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), c), githubJWKS)}, nil
}

func (v *GitHubWorkloadVerifier) Verify(ctx context.Context, raw string) (GitHubExecution, error) {
	var c GitHubExecution
	if raw == "" || len(raw) > 32<<10 || strings.TrimSpace(raw) != raw {
		return c, ErrUnauthenticated
	}
	keys := &observedKeySet{KeySet: v.keys}
	token, err := oidc.NewVerifier(GitHubIssuer, keys, &oidc.Config{ClientID: v.audience, SupportedSigningAlgs: []string{"RS256"}}).Verify(oidc.ClientContext(ctx, v.client), raw)
	if err != nil {
		if cause := context.Cause(ctx); cause != nil {
			return c, cause
		}
		var fetch *keyFetchError
		if errors.As(keys.err, &fetch) {
			return c, fmt.Errorf("%w: %w", ErrUnavailable, fetch)
		}
		return c, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if err = token.Claims(&c); err != nil {
		return c, fmt.Errorf("%w: %w", ErrUnauthenticated, err)
	}
	if len(token.Audience) != 1 || token.Audience[0] != v.audience || c.Validate(time.Now()) != nil {
		return c, ErrUnauthenticated
	}
	c.AssertionDigest = sha256.Sum256([]byte(raw))
	return c, nil
}

func (c GitHubExecution) Validate(now time.Time) error {
	for _, id := range []string{c.RepositoryID, c.RepositoryOwnerID, c.RunID, c.RunAttempt, c.CheckRunID} {
		if !githubNumericID.MatchString(id) {
			return ErrUnauthenticated
		}
	}
	for _, field := range []struct {
		value string
		max   int
	}{{c.Subject, 1024}, {c.JTI, 128}, {c.Repository, 256}, {c.WorkflowRef, 1024}, {c.Ref, 512}, {c.Event, 64}} {
		if !validClaim(field.value, field.max) {
			return ErrUnauthenticated
		}
	}
	for _, s := range []string{c.Environment, c.JobWorkflowRef} {
		if s != "" && !validClaim(s, 1024) {
			return ErrUnauthenticated
		}
	}
	if c.IssuedAt <= 0 || c.NotBefore <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 10*60 || c.IssuedAt > now.Unix()+30 || c.NotBefore > now.Unix()+30 || c.NotBefore > c.ExpiresAt || c.ExpiresAt <= now.Unix() || c.IssuedAt < now.Unix()-5*60 {
		return ErrUnauthenticated
	}
	return nil
}
