// package workload owns the environment visitor adapter and its retained leased
// visitor transport. the caller owns its in-memory lifetime and renewal loop.
package workload

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/workloadproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

var ErrNoSession = errors.New("environment visitor preparation has not succeeded")
var ErrSessionExpired = errors.New("environment visitor session expired")

type Client struct {
	mu         sync.RWMutex
	operations sync.Mutex
	key        ed25519.PrivateKey
	server     string
	authority  *clientauthority.Client
	control    *clientcontrol.Client
	session    authorityv1.EnvironmentVisitorSession
	selection  authorityv1.EnvironmentVisitorPreparation
	reference  controlv1.EnvironmentReference
	admitted   map[string]authorityv1.EnvironmentVisitorService
	permission string
	expected   map[string]string
	nonce      string
}

func (*Client) String() string   { return "environment visitor client" }
func (*Client) GoString() string { return "environment visitor client" }

// new creates one ephemeral session key. retain this adapter across preparation
// retries: a replacement key cannot take over an already-started session.
func New(server string, httpClient *http.Client) (*Client, error) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return NewWithKey(server, httpClient, key)
}

// NewWithKey lets a connector owner retain its own ephemeral key for
// protected SDK snapshots. the client copies the key and never exports it.
func NewWithKey(server string, httpClient *http.Client, key ed25519.PrivateKey) (*Client, error) {
	if len(key) != ed25519.PrivateKeySize || !ed25519.NewKeyFromSeed(key.Seed()).Equal(key) {
		return nil, invalidSession()
	}
	authority, err := clientauthority.New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	control, err := clientcontrol.New(server, httpClient, "")
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, 24)
	if _, err = rand.Read(nonce); err != nil {
		return nil, err
	}
	return &Client{key: slices.Clone(key), server: server, authority: authority, control: control, nonce: base64.RawURLEncoding.EncodeToString(nonce)}, nil
}

func (c *Client) Prepare(ctx context.Context, environment controlv1.EnvironmentReference, permission, assertion string, services map[string]string) (authorityv1.EnvironmentVisitorPreparation, error) {
	c.operations.Lock()
	defer c.operations.Unlock()
	services = maps.Clone(services)
	if environment.Server != c.server || !naming.ValidProjectKey(environment.ProjectKey) || !opaqueid.Valid(environment.EnvironmentId, opaqueid.EnvironmentPrefix) || !opaqueid.Valid(permission, "mwp_") || len(services) < 1 || len(services) > 32 {
		return authorityv1.EnvironmentVisitorPreparation{}, invalidSession()
	}
	digest := sha256.Sum256([]byte(assertion))
	public := base64.RawURLEncoding.EncodeToString(c.PublicKey())
	protocols := make(map[string]controlv1.ServiceProtocol, len(services))
	for name, protocol := range services {
		if !naming.ValidServiceName(name) || !controlv1.ServiceProtocol(protocol).Valid() {
			return authorityv1.EnvironmentVisitorPreparation{}, invalidSession()
		}
		protocols[name] = controlv1.ServiceProtocol(protocol)
	}
	// pin the complete intent before the first network attempt, including a
	// response that might be lost. a narrowed current view never rewrites it.
	c.mu.Lock()
	if c.expected != nil {
		if c.reference != environment || c.permission != permission || !maps.Equal(c.expected, services) {
			c.mu.Unlock()
			return authorityv1.EnvironmentVisitorPreparation{}, invalidSession()
		}
	} else {
		c.reference, c.permission, c.expected = environment, permission, maps.Clone(services)
	}
	c.mu.Unlock()
	body := authorityv1.EnvironmentVisitorPrepareRequest{PermissionId: permission, Nonce: c.nonce, Assertion: assertion, PublicKey: public, Services: protocols, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, machineproof.EnvironmentVisitorPossession(environment.ProjectKey, permission, environment.EnvironmentId, "prepare", public, c.nonce, services, digest)))}
	r, err := c.authority.PrepareEnvironmentVisitor(ctx, environment.ProjectKey, environment.EnvironmentId, body)
	if err != nil {
		var problem *clientauthority.ProblemError
		if errors.As(err, &problem) && problem.Status == http.StatusGone {
			return r, errors.Join(ErrSessionExpired, err)
		}
		return r, err
	}
	if err = validatePreparation(environment, services, r); err != nil {
		return authorityv1.EnvironmentVisitorPreparation{}, err
	}
	if err := context.Cause(ctx); err != nil {
		return authorityv1.EnvironmentVisitorPreparation{}, err
	}
	if current, err := c.Session(); err == nil {
		if err := validateSessionUpdate(current, r.Session); err != nil {
			return authorityv1.EnvironmentVisitorPreparation{}, err
		}
		for name, service := range r.Services {
			original, known := c.admitted[name]
			if !known || service.ServiceId != original.ServiceId || service.Protocol != original.Protocol {
				return authorityv1.EnvironmentVisitorPreparation{}, invalidSession()
			}
		}
	}
	c.mu.Lock()
	c.session = cloneSession(r.Session)
	c.selection = clonePreparation(r)
	if c.admitted == nil {
		c.admitted = clonePreparation(r).Services
	}
	c.mu.Unlock()
	return r, nil
}

func validateSession(r authorityv1.EnvironmentVisitorSession) error {
	if !r.IdentityExpiresAt.After(time.Now()) || r.IdentityExpiresAt.After(time.Now().Add(12*time.Hour+time.Minute)) || r.LeaseExpiresAt.After(r.IdentityExpiresAt) {
		return invalidSession()
	}
	if r.RenewalSequence < 0 {
		return invalidSession()
	}
	if r.LeaseExpiresAt.After(time.Now().Add(91 * time.Second)) {
		return invalidSession()
	}
	if r.ExpiresAt != nil && (!r.ExpiresAt.After(time.Now()) || r.LeaseExpiresAt.After(*r.ExpiresAt)) {
		return invalidSession()
	}
	subject := tunnelv1.VisitorSubject{Kind: string(r.Subject.Kind), WorkloadSessionID: r.Id}
	if subject.Validate() != nil || r.Subject.WorkloadSessionId == nil || *r.Subject.WorkloadSessionId != r.Id || string(r.Subject.Kind) != tunnelv1.VisitorWorkloadSession || r.Subject.IdentityId != nil || r.Subject.DeviceId != nil || len(r.Credential) != 47 || r.Credential[:4] != "wlc_" || !r.LeaseExpiresAt.After(time.Now()) || len(r.ServiceIds) > 32 {
		return invalidSession()
	}
	seen := map[string]bool{}
	for _, id := range r.ServiceIds {
		if !opaqueid.Valid(id, opaqueid.ServicePrefix) || seen[id] {
			return invalidSession()
		}
		seen[id] = true
	}
	return nil
}
func invalidSession() error {
	return failure.Wrap("read environment visitor session", failure.ServerResponseInvalid, errors.New("invalid environment visitor response"))
}

func validatePreparation(environment controlv1.EnvironmentReference, expected map[string]string, r authorityv1.EnvironmentVisitorPreparation) error {
	if r.Environment != environment || r.AppliedDefinitionRevision < 1 || r.MutationRevision < 1 || len(expected) < 1 || len(expected) > 32 || len(r.Services) > len(expected) || len(r.Session.ServiceIds) != len(r.Services) {
		return invalidSession()
	}
	if err := validateSession(r.Session); err != nil {
		return err
	}
	seen := map[string]bool{}
	for name, s := range r.Services {
		protocol, ok := expected[name]
		host, hostErr := naming.CanonicalizeHostname(s.Endpoint.Hostname)
		if !ok || !naming.ValidServiceName(name) || string(s.Protocol) != protocol || !opaqueid.Valid(s.ServiceId, opaqueid.ServicePrefix) || !slices.Contains(r.Session.ServiceIds, s.ServiceId) || seen[s.ServiceId] || hostErr != nil || host != s.Endpoint.Hostname || s.Endpoint.Port < 1 || s.Endpoint.Port > 65535 || (protocol != "kubernetes" && s.KubernetesAuth != nil) {
			return invalidSession()
		}
		seen[s.ServiceId] = true
	}
	return nil
}

func clonePreparation(r authorityv1.EnvironmentVisitorPreparation) authorityv1.EnvironmentVisitorPreparation {
	r.Session = cloneSession(r.Session)
	r.Services = maps.Clone(r.Services)
	for name, service := range r.Services {
		if service.KubernetesAuth != nil {
			service.KubernetesAuth = new(*service.KubernetesAuth)
		}
		r.Services[name] = service
	}
	return r
}

// preparation is a detached snapshot of the exact admission, never a name lookup.
func (c *Client) Preparation() (authorityv1.EnvironmentVisitorPreparation, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.session.Id == "" {
		return authorityv1.EnvironmentVisitorPreparation{}, ErrNoSession
	}
	r := clonePreparation(c.selection)
	r.Session = cloneSession(c.session)
	return r, nil
}

// proofScope is the defining registered-key JWT grant_id and exact audience.
// the caller signs with its source key; the ephemeral key never leaves native.
func (c *Client) ProofScope(environment controlv1.EnvironmentReference, permission, operation string, services map[string]string) (string, string) {
	nonce := c.nonce
	if operation == "attach" {
		c.mu.RLock()
		nonce = c.session.Id
		c.mu.RUnlock()
	}
	public := base64.RawURLEncoding.EncodeToString(c.PublicKey())
	audience := c.server + "/v1/projects/" + environment.ProjectKey + "/environments/" + environment.EnvironmentId + "/visitors/prepare"
	if operation == "attach" {
		audience = c.server + "/v1/environment-visitor-sessions/" + nonce + "/assertions"
	}
	return machineproof.EnvironmentVisitor(permission, environment.EnvironmentId, operation, public, nonce, services), audience
}

func (c *Client) Binding() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	b, _ := json.Marshal([]any{c.reference, c.permission, c.expected, c.session.Id})
	digest := sha256.Sum256(b)
	return fmt.Sprintf("%x", digest)
}
func (c *Client) Session() (authorityv1.EnvironmentVisitorSession, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.session.Id == "" {
		return authorityv1.EnvironmentVisitorSession{}, ErrNoSession
	}
	r := c.session
	return cloneSession(r), nil
}

// callers hold mu. keep the current response view coherent without changing
// the original complete intent or the immutable IDs already admitted.
func (c *Client) acceptSessionLocked(next authorityv1.EnvironmentVisitorSession) {
	c.session = cloneSession(next)
	c.selection.Session = cloneSession(next)
	for name, service := range c.selection.Services {
		if !slices.Contains(next.ServiceIds, service.ServiceId) { delete(c.selection.Services, name) }
	}
}
func (c *Client) Renew(ctx context.Context) (authorityv1.EnvironmentVisitorSession, error) {
	c.operations.Lock()
	defer c.operations.Unlock()
	r, err := c.Session()
	if err != nil {
		return r, err
	}
	if r.RenewalSequence == math.MaxInt64 {
		return authorityv1.EnvironmentVisitorSession{}, invalidSession()
	}
	sequence := r.RenewalSequence + 1
	body := authorityv1.EnvironmentVisitorRenewal{Sequence: sequence, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, workloadproof.Renew(r.Id, sequence)))}
	next, err := c.authority.RenewEnvironmentVisitorSession(ctx, r.Id, r.Credential, body)
	if err != nil {
		return next, err
	}
	if err = validateSessionUpdate(r, next); err != nil {
		return authorityv1.EnvironmentVisitorSession{}, err
	}
	if next.RenewalSequence != sequence {
		return authorityv1.EnvironmentVisitorSession{}, invalidSession()
	}
	if err := context.Cause(ctx); err != nil {
		return authorityv1.EnvironmentVisitorSession{}, err
	}
	c.mu.Lock()
	c.acceptSessionLocked(next)
	c.mu.Unlock()
	return next, nil
}

func (c *Client) Attach(ctx context.Context, assertion string) (authorityv1.EnvironmentVisitorSession, error) {
	c.operations.Lock()
	defer c.operations.Unlock()
	r, err := c.Session()
	if err != nil {
		return r, err
	}
	digest := sha256.Sum256([]byte(assertion))
	c.mu.RLock()
	environment, permission, services := c.selection.Environment, c.permission, c.expected
	c.mu.RUnlock()
	public := base64.RawURLEncoding.EncodeToString(c.PublicKey())
	next, err := c.authority.AttachEnvironmentVisitorAssertion(ctx, r.Id, r.Credential, authorityv1.EnvironmentVisitorAssertion{Assertion: assertion, Signature: base64.RawURLEncoding.EncodeToString(ed25519.Sign(c.key, machineproof.EnvironmentVisitorPossession(environment.ProjectKey, permission, environment.EnvironmentId, "attach", public, r.Id, services, digest)))})
	if err != nil {
		var problem *clientauthority.ProblemError
		if errors.As(err, &problem) && problem.Status == http.StatusGone {
			return next, errors.Join(ErrSessionExpired, err)
		}
		return next, err
	}
	if err = validateSessionUpdate(r, next); err != nil {
		return authorityv1.EnvironmentVisitorSession{}, err
	}
	if err := context.Cause(ctx); err != nil {
		return authorityv1.EnvironmentVisitorSession{}, err
	}
	c.mu.Lock()
	c.acceptSessionLocked(next)
	c.mu.Unlock()
	return next, nil
}

// current authority can narrow monotonically to a subset of original IDs.
// this response view does not rewrite the original intent or admitted ID pin;
// replacing IDs or restoring a previously narrowed view is never accepted.
func validateSessionUpdate(current, next authorityv1.EnvironmentVisitorSession) error {
	if err := validateSession(next); err != nil {
		return err
	}
	if current.ExpiresAt != nil && (next.ExpiresAt == nil || next.ExpiresAt.After(*current.ExpiresAt)) {
		return invalidSession()
	}
	if next.IdentityExpiresAt.Before(current.IdentityExpiresAt) || next.RenewalSequence < current.RenewalSequence || next.Id != current.Id || next.Credential != current.Credential || !reflect.DeepEqual(next.Subject, current.Subject) {
		return invalidSession()
	}
	// an attachment or preparation retry may observe one renewal whose reply was
	// lost. serialized operations can never have more than one outstanding step.
	if next.RenewalSequence > current.RenewalSequence && (current.RenewalSequence == math.MaxInt64 || next.RenewalSequence != current.RenewalSequence+1) {
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
	return c.authority.RevokeEnvironmentVisitorSession(ctx, r.Id, r.Credential)
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
	c.mu.RLock()
	admitted := maps.Clone(c.admitted)
	c.mu.RUnlock()
	for _, service := range inventory.Services {
		approved, found := admitted[service.Service]
		if !found || approved.ServiceId != service.Id || approved.Protocol != service.Protocol || !slices.Contains(r.ServiceIds, service.Id) || ids[service.Id] || names[service.Service] || !naming.ValidServiceName(service.Service) {
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
func (c *Client) SelectServiceRun(ctx context.Context, service string) (controlv1.ServiceSelection, error) {
	r, err := c.Session()
	if err != nil {
		return controlv1.ServiceSelection{}, err
	}
	return c.control.SelectWorkloadServiceRun(ctx, r.Credential, service)
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
	if issued.ServiceId != service {
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

func cloneSession(r authorityv1.EnvironmentVisitorSession) authorityv1.EnvironmentVisitorSession {
	if r.ExpiresAt != nil {
		r.ExpiresAt = new(*r.ExpiresAt)
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

// sessionDeadline is the current finite proof horizon, bounded by an optional
// absolute limit. permission leases remain independently bounded and renewed.
func SessionDeadline(r authorityv1.EnvironmentVisitorSession) time.Time {
	until := r.IdentityExpiresAt
	if r.ExpiresAt != nil && r.ExpiresAt.Before(until) {
		until = *r.ExpiresAt
	}
	return until
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
