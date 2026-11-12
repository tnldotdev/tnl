package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/httpclient"
	"github.com/tnldotdev/tnl/internal/naming"
)

// workload trust is supplied by saved manager policy, never assertion claims.
type WorkloadTrust struct {
	Provider string            `json:"provider"`
	Issuer   string            `json:"issuer"`
	JWKSURL  string            `json:"jwks_url"`
	Audience string            `json:"audience"`
	Claims   map[string]string `json:"claims"`
	Events   []string          `json:"events,omitempty"`
}

type VercelExecution struct {
	Owner       string `json:"owner"`
	OwnerID     string `json:"owner_id"`
	Project     string `json:"project"`
	ProjectID   string `json:"project_id"`
	Environment string `json:"environment"`
}
type FlyExecution struct {
	Org       string `json:"org_name"`
	OrgID     string `json:"org_id"`
	App       string `json:"app_name"`
	AppID     string `json:"app_id"`
	Machine   string `json:"machine_name"`
	MachineID string `json:"machine_id"`
}

type KubernetesObjectIdentity struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

// KubernetesExecution retains only immutable service-account and pod identity,
// not rotating token timestamps, kubeconfig, or optional node metadata.
type KubernetesExecution struct {
	Namespace      string                   `json:"namespace"`
	ServiceAccount KubernetesObjectIdentity `json:"serviceaccount"`
	Pod            KubernetesObjectIdentity `json:"pod"`
}

type WorkloadExecution struct {
	RegisteredMachine *RegisteredMachineExecution `json:"registered_machine,omitempty"`
	Provider          string                      `json:"provider"`
	Issuer            string                      `json:"issuer"`
	Subject           string                      `json:"subject"`
	Audience          string                      `json:"audience"`
	TrustDigest       string                      `json:"trust_digest"`
	IssuedAt          int64                       `json:"iat"`
	NotBefore         int64                       `json:"nbf"`
	ExpiresAt         int64                       `json:"exp"`
	GitHub            *GitHubExecution            `json:"github,omitempty"`
	Vercel            *VercelExecution            `json:"vercel,omitempty"`
	Fly               *FlyExecution               `json:"fly,omitempty"`
	Kubernetes        *KubernetesExecution        `json:"kubernetes,omitempty"`
	GitLab            *GitLabExecution            `json:"gitlab,omitempty"`
	Claims            map[string]string           `json:"claims,omitempty"`
	AssertionDigest   [32]byte                    `json:"-"`
}

// registered machine executions are constructed only after checking the current
// registered key and a separate workload permission, never from OIDC claims.
type RegisteredMachineExecution struct {
	ID           string `json:"id"`
	KeyID        string `json:"key_id"`
	PermissionID string `json:"permission_id"`
	Revision     int64  `json:"revision"`
}

func (c WorkloadExecution) Validate(now time.Time) error {
	if !validClaim(c.Subject, 1024) || !config.WorkloadHTTPS(c.Issuer) {
		return ErrUnauthenticated
	}
	if m := c.RegisteredMachine; m != nil {
		if c.Provider != "oidc" || c.Subject != m.ID || !validClaim(m.ID, 128) || !validClaim(m.KeyID, 128) || !validClaim(m.PermissionID, 128) || m.Revision < 1 || c.GitHub != nil || c.Fly != nil || c.Vercel != nil || c.Kubernetes != nil || c.GitLab != nil || len(c.Claims) != 0 || c.IssuedAt <= 0 || c.NotBefore != c.IssuedAt || c.ExpiresAt <= now.Unix() || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 60 || c.IssuedAt > now.Unix()+5 {
			return ErrUnauthenticated
		}
		return nil
	}
	if c.Provider == "github" {
		if c.GitHub == nil || c.Vercel != nil || c.Fly != nil || c.Kubernetes != nil || c.GitLab != nil || len(c.Claims) > 0 || c.Issuer != GitHubIssuer || c.Subject != c.GitHub.Subject {
			return ErrUnauthenticated
		}
		if c.IssuedAt != c.GitHub.IssuedAt || c.NotBefore != c.GitHub.NotBefore || c.ExpiresAt != c.GitHub.ExpiresAt {
			return ErrUnauthenticated
		}
		return c.GitHub.Validate(now)
	}
	if c.GitHub != nil || c.IssuedAt <= 0 || c.NotBefore <= 0 || c.ExpiresAt <= c.IssuedAt || c.ExpiresAt-c.IssuedAt > 12*60*60 || c.IssuedAt > now.Unix()+30 || c.NotBefore > now.Unix()+30 || c.NotBefore > c.ExpiresAt || c.ExpiresAt <= now.Unix() {
		return ErrUnauthenticated
	}
	var fields []string
	if c.Provider != "kubernetes" && c.Kubernetes != nil {
		return ErrUnauthenticated
	}
	if c.Provider != "gitlab" && c.GitLab != nil {
		return ErrUnauthenticated
	}
	switch c.Provider {
	case "gitlab":
		if c.GitLab == nil || c.Vercel != nil || c.Fly != nil || len(c.Claims) != 0 || !c.GitLab.valid(c.Subject) {
			return ErrUnauthenticated
		}
	case "kubernetes":
		k := c.Kubernetes
		if k == nil || c.Vercel != nil || c.Fly != nil || len(c.Claims) != 0 || !naming.ValidAuthorityLabel(k.Namespace) || !config.ValidKubernetesName(k.ServiceAccount.Name) || !config.ValidKubernetesUID(k.ServiceAccount.UID) || !config.ValidKubernetesName(k.Pod.Name) || !config.ValidKubernetesUID(k.Pod.UID) || c.Subject != "system:serviceaccount:"+k.Namespace+":"+k.ServiceAccount.Name {
			return ErrUnauthenticated
		}
	case "vercel":
		if c.Vercel == nil || c.Fly != nil || len(c.Claims) > 0 {
			return ErrUnauthenticated
		}
		v := c.Vercel
		fields = []string{v.Owner, v.OwnerID, v.Project, v.ProjectID, v.Environment}
		if c.Subject != "owner:"+v.Owner+":project:"+v.Project+":environment:"+v.Environment {
			return ErrUnauthenticated
		}
	case "fly":
		if c.Fly == nil || c.Vercel != nil || len(c.Claims) > 0 {
			return ErrUnauthenticated
		}
		f := c.Fly
		fields = []string{f.Org, f.OrgID, f.App, f.AppID, f.Machine, f.MachineID}
		if c.Subject != f.Org+":"+f.App+":"+f.Machine || c.Issuer != "https://oidc.fly.io/"+f.Org {
			return ErrUnauthenticated
		}
	case "oidc", "google":
		if c.Fly != nil || c.Vercel != nil || len(c.Claims) > 32 {
			return ErrUnauthenticated
		}
		for k, v := range c.Claims {
			fields = append(fields, k, v)
		}
	default:
		return ErrUnauthenticated
	}
	for _, s := range fields {
		if !validClaim(s, 1024) {
			return ErrUnauthenticated
		}
	}
	return nil
}

func (c WorkloadExecution) Matches(p WorkloadTrust) bool {
	if c.RegisteredMachine != nil {
		return false
	}
	if c.Provider != p.Provider || c.Issuer != p.Issuer || c.Audience != p.Audience || c.TrustDigest != p.Digest() {
		return false
	}
	claims := c.Claims
	if c.GitHub != nil {
		g := c.GitHub
		if !slices.Contains(p.Events, g.Event) {
			return false
		}
		claims = map[string]string{"repository": g.Repository, "repository_id": g.RepositoryID, "repository_owner_id": g.RepositoryOwnerID, "workflow_ref": g.WorkflowRef, "ref": g.Ref, "environment": g.Environment, "job_workflow_ref": g.JobWorkflowRef}
	}
	if c.Vercel != nil {
		v := c.Vercel
		claims = map[string]string{"owner": v.Owner, "owner_id": v.OwnerID, "project": v.Project, "project_id": v.ProjectID, "environment": v.Environment}
	}
	if c.Fly != nil {
		f := c.Fly
		claims = map[string]string{"org_name": f.Org, "org_id": f.OrgID, "app_name": f.App, "app_id": f.AppID, "machine_id": f.MachineID}
	}
	if c.Kubernetes != nil {
		claims = map[string]string{"service_account_uid": c.Kubernetes.ServiceAccount.UID}
	}
	if c.GitLab != nil {
		claims = c.GitLab.claims()
	}
	for k, v := range p.Claims {
		if k == "sub" {
			if c.Subject != v {
				return false
			}
		} else if claims[k] != v {
			return false
		}
	}
	return true
}

type WorkloadVerifier struct {
	github *GitHubWorkloadVerifier
	client *http.Client
	mu     sync.Mutex
	keys   map[string]oidc.KeySet
}

func NewWorkloadVerifier(origin string, client *http.Client) (*WorkloadVerifier, error) {
	g, e := NewGitHubWorkloadVerifier(origin, client)
	if e != nil {
		return nil, e
	}
	c := httpclient.NoRedirects(client)
	if c.Timeout <= 0 || c.Timeout > 10*time.Second {
		c.Timeout = 10 * time.Second
	}
	base := c.Transport
	if base == nil {
		base = http.DefaultTransport
	}
	c.Transport = keyFetchTransport{base: base, algorithms: []string{"RS256", "ES256", "EdDSA"}}
	return &WorkloadVerifier{github: g, client: c, keys: map[string]oidc.KeySet{}}, nil
}

func (v *WorkloadVerifier) Verify(ctx context.Context, p WorkloadTrust, raw string) (c WorkloadExecution, err error) {
	if p.Validate() != nil {
		return c, ErrUnauthenticated
	}
	if p.Provider == "github" {
		if p.Audience != v.github.audience {
			return c, ErrUnauthenticated
		}
		g, e := v.github.Verify(ctx, raw)
		if e != nil {
			return c, e
		}
		c = WorkloadExecution{Provider: "github", Issuer: GitHubIssuer, Subject: g.Subject, Audience: p.Audience, TrustDigest: p.Digest(), IssuedAt: g.IssuedAt, NotBefore: g.NotBefore, ExpiresAt: g.ExpiresAt, GitHub: &g, AssertionDigest: g.AssertionDigest}
		if !c.Matches(p) {
			return WorkloadExecution{}, ErrUnauthenticated
		}
		return c, nil
	}
	if !config.WorkloadHTTPS(p.Issuer) || !config.WorkloadHTTPS(p.JWKSURL) || !validClaim(p.Audience, 1024) || len(raw) == 0 || len(raw) > 32<<10 || strings.TrimSpace(raw) != raw {
		return c, ErrUnauthenticated
	}
	v.mu.Lock()
	keys := v.keys[p.JWKSURL]
	if keys == nil {
		// bound the cache even for many separately managed generic issuers.
		if len(v.keys) >= 128 {
			clear(v.keys)
		}
		keys = oidc.NewRemoteKeySet(oidc.ClientContext(context.Background(), v.client), p.JWKSURL)
		v.keys[p.JWKSURL] = keys
	}
	v.mu.Unlock()
	observed := &observedKeySet{KeySet: keys}
	algs := []string{"RS256"}
	if p.Provider == "oidc" || p.Provider == "kubernetes" {
		algs = []string{"RS256", "ES256", "EdDSA"}
	}
	t, e := oidc.NewVerifier(p.Issuer, observed, &oidc.Config{ClientID: p.Audience, SupportedSigningAlgs: algs}).Verify(oidc.ClientContext(ctx, v.client), raw)
	if e != nil {
		if cause := context.Cause(ctx); cause != nil {
			return c, cause
		}
		var fetch *keyFetchError
		if errors.As(observed.err, &fetch) {
			return c, fmt.Errorf("%w: %w", ErrUnavailable, fetch)
		}
		return c, fmt.Errorf("%w: %w", ErrUnauthenticated, e)
	}
	var times struct {
		IssuedAt  int64           `json:"iat"`
		NotBefore json.RawMessage `json:"nbf"`
		ExpiresAt int64           `json:"exp"`
	}
	if t.Claims(&times) != nil || len(t.Audience) != 1 || t.Audience[0] != p.Audience {
		return c, ErrUnauthenticated
	}
	// nbf is optional in generic OIDC. retain an effective start time in the
	// verified execution, but reject present null, malformed, or zero values.
	notBefore := times.IssuedAt
	if len(times.NotBefore) != 0 || p.Provider != "oidc" && p.Provider != "google" && p.Provider != "kubernetes" {
		if json.Unmarshal(times.NotBefore, &notBefore) != nil || string(times.NotBefore) == "null" || notBefore <= 0 {
			return c, ErrUnauthenticated
		}
	}
	c = WorkloadExecution{Provider: p.Provider, Issuer: t.Issuer, Subject: t.Subject, Audience: p.Audience, TrustDigest: p.Digest(), IssuedAt: times.IssuedAt, NotBefore: notBefore, ExpiresAt: times.ExpiresAt, AssertionDigest: sha256.Sum256([]byte(raw))}
	switch p.Provider {
	case "gitlab":
		c.GitLab = &GitLabExecution{}
		err = t.Claims(c.GitLab)
	case "kubernetes":
		var claims struct {
			Kubernetes KubernetesExecution `json:"kubernetes.io"`
		}
		err = t.Claims(&claims)
		c.Kubernetes = &claims.Kubernetes
	case "vercel":
		c.Vercel = &VercelExecution{}
		err = t.Claims(c.Vercel)
	case "fly":
		c.Fly = &FlyExecution{}
		err = t.Claims(c.Fly)
	case "oidc", "google":
		var claims map[string]json.RawMessage
		err = t.Claims(&claims)
		c.Claims = map[string]string{}
		for k := range p.Claims {
			if k == "sub" {
				continue
			}
			var s string
			if json.Unmarshal(claims[k], &s) != nil {
				return c, ErrUnauthenticated
			}
			c.Claims[k] = s
		}
	default:
		return c, ErrUnauthenticated
	}
	if err != nil || c.Validate(time.Now()) != nil || !c.Matches(p) {
		return WorkloadExecution{}, ErrUnauthenticated
	}
	return c, nil
}

func (p WorkloadTrust) Digest() string {
	b, _ := json.Marshal(p)
	return fmt.Sprintf("%x", sha256.Sum256(b))
}
