// package workloadclient is the native visitor authentication adapter for a
// provider workload. the caller owns its in-memory lifetime and renewal loop.
package workloadclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"sync"
	"time"

	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrNoSession = errors.New("workload exchange has not succeeded")
var ErrSessionExpired = errors.New("workload session expired")
var githubExecutionID = regexp.MustCompile(`^[1-9][0-9]{0,19}$`)
var bindingID = regexp.MustCompile(`^[0-9a-f]{64}$`)

type Client struct {
	mu         sync.RWMutex
	operations sync.Mutex
	key        ed25519.PrivateKey
	authority  *authorityclient.Client
	control    *controlclient.Client
	session    authorityv1.WorkloadSession
	nonce      string
}

func (*Client) String() string   { return "workload visitor client" }
func (*Client) GoString() string { return "workload visitor client" }

// New creates one ephemeral execution key. retain this adapter across exchange
// retries: a replacement key cannot take over an already-started execution.
func New(server string, httpClient *http.Client) (*Client, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewWithKey(server, httpClient, key)
}

// NewWithKey lets a native connection owner retain its own ephemeral key for
// protected SDK snapshots. the client copies the key and never exports it.
func NewWithKey(server string, httpClient *http.Client, key ed25519.PrivateKey) (*Client, error) {
	if len(key) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(key.Seed()).Equal(key) {
		return nil, invalidSession()
	}
	authority, err := authorityclient.New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	control, err := controlclient.New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Client{key: slices.Clone(key), authority: authority, control: control, nonce: base64.RawURLEncoding.EncodeToString(nonce)}, nil
}

func (c *Client) Exchange(ctx context.Context, team, project, source, workload, assertion string, services []string) (authorityv1.WorkloadSession, error) {
	c.operations.Lock()
	defer c.operations.Unlock()
	digest := sha256.Sum256([]byte(assertion))
	body := authorityv1.WorkloadExchange{TeamId: team, ProjectKey: project, SourceFingerprint: source, Workload: workload, Nonce: c.nonce, Assertion: assertion, PublicKey: base64.RawURLEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey)), Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, workloadproof.Exchange(team, project, workload, source, c.nonce, digest, services)))}
	if services != nil {
		selected := slices.Clone(services)
		body.Services = &selected
	}
	r, err := c.authority.ExchangeWorkload(ctx, body)
	if err != nil {
		var problem *authorityclient.ProblemError
		if errors.As(err, &problem) && problem.Status == http.StatusGone {
			return r, errors.Join(ErrSessionExpired, err)
		}
		return r, err
	}
	if err = validateSession(r); err != nil {
		return authorityv1.WorkloadSession{}, err
	}
	if opaqueid.Valid(team, opaqueid.TeamPrefix) && r.TeamId != team || r.ProjectKey != project || r.Workload != workload {
		return authorityv1.WorkloadSession{}, invalidSession()
	}
	c.mu.Lock()
	c.session = cloneSession(r)
	c.mu.Unlock()
	return r, nil
}

func validateSession(r authorityv1.WorkloadSession) error {
	if r.AssertionExpiresAt != nil && (!r.AssertionExpiresAt.After(time.Now()) || r.AssertionExpiresAt.After(time.Now().Add(12*time.Hour+time.Minute))) {
		return invalidSession()
	}
	if r.Provider == controlv1.WorkloadGitHub {
		g := r.Github
		if g == nil {
			return invalidSession()
		}
		for _, id := range []string{g.RepositoryId, g.RepositoryOwnerId, g.RunId, g.RunAttempt, g.CheckRunId} {
			if !githubExecutionID.MatchString(id) {
				return invalidSession()
			}
		}
	} else if r.Github != nil {
		return invalidSession()
	}
	if !bindingID.MatchString(r.Binding) || !naming.ValidServiceName(r.Workload) || !slices.Contains([]string{"github", "vercel", "fly", "oidc"}, string(r.Provider)) || r.LeaseExpiresAt.After(time.Now().Add(91*time.Second)) || r.ExpiresAt.After(time.Now().Add(6*time.Hour+time.Second)) {
		return invalidSession()
	}
	subject := tunnelv1.VisitorSubject{Kind: string(r.Subject.Kind), WorkloadSessionID: r.Id}
	if subject.Validate() != nil || r.Subject.WorkloadSessionId == nil || *r.Subject.WorkloadSessionId != r.Id || string(r.Subject.Kind) != tunnelv1.VisitorWorkloadSession || r.Subject.IdentityId != nil || r.Subject.DeviceId != nil || len(r.Credential) != 47 || r.Credential[:4] != "wlc_" || !r.LeaseExpiresAt.After(time.Now()) || r.LeaseExpiresAt.After(r.ExpiresAt) || len(r.ServiceIds) > 32 {
		return invalidSession()
	}
	seen := map[string]bool{}
	for _, id := range r.ServiceIds {
		if !opaqueid.Valid(id, opaqueid.PrivateServicePrefix) || seen[id] {
			return invalidSession()
		}
		seen[id] = true
	}
	return nil
}
func invalidSession() error {
	return failure.Wrap("read workload session", failure.ServerResponseInvalid, errors.New("invalid workload session response"))
}
func (c *Client) Session() (authorityv1.WorkloadSession, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.session.Id == "" {
		return authorityv1.WorkloadSession{}, ErrNoSession
	}
	r := c.session
	return cloneSession(r), nil
}
func (c *Client) Renew(ctx context.Context) (authorityv1.WorkloadSession, error) {
	c.operations.Lock()
	defer c.operations.Unlock()
	r, err := c.Session()
	if err != nil {
		return r, err
	}
	next, err := c.authority.RenewWorkloadSession(ctx, r.Id, r.Credential)
	if err != nil {
		return next, err
	}
	if err = validateSessionUpdate(r, next); err != nil {
		return authorityv1.WorkloadSession{}, err
	}
	c.mu.Lock()
	c.session = cloneSession(next)
	c.mu.Unlock()
	return next, nil
}

func (c *Client) Identify(ctx context.Context, team, project, source, workload, assertion string) (string, error) {
	r, err := c.IdentifyPolicy(ctx, team, project, source, workload, assertion)
	if err != nil {
		return "", err
	}
	if len(r.Binding) != 64 {
		return "", invalidSession()
	}
	return r.Binding, nil
}

func (c *Client) IdentifyPolicy(ctx context.Context, team, project, source, workload, assertion string) (authorityv1.WorkloadIdentity, error) {
	r, err := c.authority.IdentifyWorkload(ctx, authorityv1.WorkloadIdentityRequest{TeamId: team, ProjectKey: project, SourceFingerprint: source, Workload: workload, Assertion: assertion})
	if err != nil {
		return r, err
	}
	if !bindingID.MatchString(r.Binding) || len(r.Services) == 0 || len(r.Services) > 32 || !r.AssertionExpiresAt.After(time.Now()) || r.AssertionExpiresAt.After(time.Now().Add(12*time.Hour+time.Minute)) {
		return authorityv1.WorkloadIdentity{}, invalidSession()
	}
	seen := map[string]bool{}
	for _, name := range r.Services {
		if !naming.ValidServiceName(name) || seen[name] {
			return authorityv1.WorkloadIdentity{}, invalidSession()
		}
		seen[name] = true
	}
	return r, nil
}

func (c *Client) Attach(ctx context.Context, assertion string) (authorityv1.WorkloadSession, error) {
	c.operations.Lock()
	defer c.operations.Unlock()
	r, err := c.Session()
	if err != nil {
		return r, err
	}
	digest := sha256.Sum256([]byte(assertion))
	next, err := c.authority.AttachWorkloadAssertion(ctx, r.Id, r.Credential, authorityv1.WorkloadAssertion{Assertion: assertion, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, workloadproof.Attach(r.Id, digest)))})
	if err != nil {
		var problem *authorityclient.ProblemError
		if errors.As(err, &problem) && problem.Status == http.StatusGone {
			return next, errors.Join(ErrSessionExpired, err)
		}
		return next, err
	}
	if err = validateSessionUpdate(r, next); err != nil {
		return authorityv1.WorkloadSession{}, err
	}
	c.mu.Lock()
	c.session = cloneSession(next)
	c.mu.Unlock()
	return next, nil
}

// renewals and assertion attachments may shorten the execution and narrow its
// services, but cannot change its binding or extend its original expiry.
func validateSessionUpdate(current, next authorityv1.WorkloadSession) error {
	if err := validateSession(next); err != nil {
		return err
	}
	if next.Binding != current.Binding || next.Id != current.Id || next.Credential != current.Credential ||
		next.ExpiresAt.After(current.ExpiresAt) || next.TeamId != current.TeamId || next.ProjectKey != current.ProjectKey ||
		next.Workload != current.Workload || next.Provider != current.Provider || !reflect.DeepEqual(next.Github, current.Github) {
		return invalidSession()
	}
	for _, id := range next.ServiceIds {
		if !slices.Contains(current.ServiceIds, id) {
			return invalidSession()
		}
	}
	return nil
}

func (c *Client) Revoke(ctx context.Context) error {
	r, err := c.Session()
	if err != nil {
		return err
	}
	return c.authority.RevokeWorkloadSession(ctx, r.Id, r.Credential)
}
func (c *Client) ListServices(ctx context.Context) (controlv1.WorkloadServices, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.WorkloadServices{}, err
	}
	inventory, err := c.control.ListWorkloadServices(ctx, r.Credential)
	if err != nil {
		return inventory, err
	}
	if len(inventory.Services) > len(r.ServiceIds) {
		return controlv1.WorkloadServices{}, invalidSession()
	}
	ids, names := map[string]bool{}, map[string]bool{}
	for _, service := range inventory.Services {
		if !slices.Contains(r.ServiceIds, service.Id) || ids[service.Id] || names[service.Service] || !naming.ValidServiceName(service.Service) {
			return controlv1.WorkloadServices{}, invalidSession()
		}
		ids[service.Id], names[service.Service] = true, true
	}
	return inventory, nil
}
func (c *Client) CheckService(ctx context.Context, service string) (controlv1.WorkloadServiceAuthorization, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.WorkloadServiceAuthorization{}, err
	}
	return c.control.CheckWorkloadService(ctx, r.Credential, service)
}
func (c *Client) CreateIngressAssignments(ctx context.Context, service, key string) (controlv1.WorkloadIngressAssignments, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.WorkloadIngressAssignments{}, err
	}
	return c.control.CreateWorkloadIngressAssignments(ctx, r.Credential, service, key)
}

func (c *Client) CreateIngressAssignment(ctx context.Context, service, key, exclude string) (controlv1.WorkloadIngressAssignments, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.WorkloadIngressAssignments{}, err
	}
	return c.control.CreateWorkloadIngressAssignmentSet(ctx, r.Credential, service, key, 1, exclude)
}
func (c *Client) SelectServiceRun(ctx context.Context, service string) (controlv1.PrivateServiceSelection, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.PrivateServiceSelection{}, err
	}
	return c.control.SelectWorkloadServiceRun(ctx, r.Credential, service)
}
func (c *Client) IngressTransportTrust(ctx context.Context, session string) (controlv1.IngressTransportTrust, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.IngressTransportTrust{}, err
	}
	return c.control.GetWorkloadIngressTransportTrust(ctx, r.Credential, session)
}
func (c *Client) ReleaseIngressAssignment(ctx context.Context, session string) error {
	r, err := c.Session()
	if err != nil {
		return err
	}
	return c.control.ReleaseWorkloadIngressAssignment(ctx, r.Credential, session)
}
func (c *Client) ServiceClientCertificate(ctx context.Context, service string) (controlv1.ServiceClientCertificate, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.ServiceClientCertificate{}, err
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, c.key)
	if err != nil {
		return controlv1.ServiceClientCertificate{}, err
	}
	return c.control.IssueWorkloadServiceClientCertificate(ctx, r.Credential, service, csr)
}

// ClientTLSCertificate pairs the short service certificate with the same
// in-memory workload key. no human enrollment or filesystem key is involved.
func (c *Client) ClientTLSCertificate(ctx context.Context, service string) (tls.Certificate, error) {
	issued, err := c.ServiceClientCertificate(ctx, service)
	if err != nil {
		return tls.Certificate{}, err
	}
	if issued.PrivateServiceId != service {
		return tls.Certificate{}, invalidSession()
	}
	block, rest := pem.Decode([]byte(issued.CertificatePem))
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return tls.Certificate{}, invalidSession()
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return tls.Certificate{}, failure.Wrap("read workload client certificate", failure.ServerResponseInvalid, err)
	}
	public, ok := leaf.PublicKey.(ed25519.PublicKey)
	if !ok || !public.Equal(c.key.Public()) || !leaf.NotAfter.Equal(issued.ExpiresAt) {
		return tls.Certificate{}, invalidSession()
	}
	return tls.Certificate{Certificate: [][]byte{block.Bytes}, PrivateKey: workloadSigner{c}, Leaf: leaf}, nil
}

// TLS gets a signing operation, not an exportable raw private key.
type workloadSigner struct{ client *Client }

func (s workloadSigner) Public() crypto.PublicKey { return s.client.PublicKey() }
func (s workloadSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("unsupported workload signature hash")
	}
	return s.client.Sign(digest), nil
}
func (workloadSigner) String() string   { return "workload TLS signer" }
func (workloadSigner) GoString() string { return "workload TLS signer" }

func cloneSession(r authorityv1.WorkloadSession) authorityv1.WorkloadSession {
	if r.AssertionExpiresAt != nil {
		r.AssertionExpiresAt = new(*r.AssertionExpiresAt)
	}
	if r.Github != nil {
		r.Github = new(*r.Github)
	}
	r.ServiceIds = slices.Clone(r.ServiceIds)
	if r.Subject.WorkloadSessionId != nil {
		r.Subject.WorkloadSessionId = new(*r.Subject.WorkloadSessionId)
	}
	if r.Subject.IdentityId != nil {
		r.Subject.IdentityId = new(*r.Subject.IdentityId)
	}
	if r.Subject.DeviceId != nil {
		r.Subject.DeviceId = new(*r.Subject.DeviceId)
	}
	return r
}
func (c *Client) Subject() (tunnelv1.VisitorSubject, error) {
	r, err := c.Session()
	if err != nil {
		return tunnelv1.VisitorSubject{}, err
	}
	return tunnelv1.VisitorSubject{Kind: tunnelv1.VisitorWorkloadSession, WorkloadSessionID: r.Id}, nil
}

// Sign proves workload key possession for the private connector hello digest.
func (c *Client) Sign(digest []byte) []byte { return ed25519.Sign(c.key, digest) }

// PublicKey returns only the proof verifier, never the ephemeral signing key.
func (c *Client) PublicKey() ed25519.PublicKey {
	return slices.Clone(c.key.Public().(ed25519.PublicKey))
}
