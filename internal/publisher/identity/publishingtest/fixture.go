// package publishingtest exercises service-only native clients against signed
// enrollment exchanges, exact service runs, and real publisher TLS/yamux streams.
package publishingtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/httpjson"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type enrollment struct {
	result authorityv1.PublisherEnrollmentResult
	public ed25519.PublicKey
}

type allocation struct {
	service string
	request controlv1.AllocateServiceRequest
	grant   string
}

type browserSession struct {
	service string
	subject visitortoken.Browser
}

type visitorGrant struct {
	service, id string
}

type Fixture struct {
	URL, Namespace, DomainID, OwnerToken      string
	HTTP                                      *http.Client
	Enrollments, Allocations, Runs, Deletions atomic.Int32
	mu                                        sync.Mutex
	backend                                   *testutil.PublishingFixture
	seed                                      *clientcontrol.Client
	enrollments                               map[string]*enrollment
	grants                                    map[string]*enrollment
	tokens                                    map[string]*enrollment
	replays                                   map[string]bool
	allocations                               map[string]allocation
	allocatedOwner                            map[string]string
	deleted                                   []string
	seenRuns                                  map[string]bool
	visitorKey                                ed25519.PrivateKey
	visitorGrants                             map[string]visitorGrant
	browsers                                  map[string]browserSession
	handoffs                                  map[string]string
	local                                     *localRuntime
	t                                         *testing.T
}

func id(t *testing.T, prefix string) string {
	t.Helper()
	value, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func secret(t *testing.T) string {
	t.Helper()
	var value [32]byte
	if _, err := rand.Read(value[:]); err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(value[:])
}

func New(t *testing.T, hooks testutil.PublishingHooks) *Fixture {
	t.Helper()
	backend := testutil.NewPublishingFixture(t, hooks)
	seed, err := clientcontrol.New(backend.URL, http.DefaultClient, credentials.AccessToken(backend.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	f := &Fixture{Namespace: backend.Namespace, DomainID: "dom_0000000000000000000001", OwnerToken: backend.AccessToken,
		backend: backend, seed: seed, enrollments: map[string]*enrollment{}, grants: map[string]*enrollment{}, tokens: map[string]*enrollment{},
		replays: map[string]bool{}, allocations: map[string]allocation{}, allocatedOwner: map[string]string{}, seenRuns: map[string]bool{},
		visitorKey: key, visitorGrants: map[string]visitorGrant{}, browsers: map[string]browserSession{}, handoffs: map[string]string{}, t: t}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	f.URL, f.HTTP = server.URL, server.Client()
	return f
}

func (f *Fixture) Owner() (*clientcontrol.Client, error) {
	return clientcontrol.New(f.URL, f.HTTP, credentials.AccessToken(f.OwnerToken))
}

func (f *Fixture) SavedService(ctx context.Context, name string, configuration controlv1.ProjectServiceConfiguration) (controlv1.Service, error) {
	if configuration.Protocol == nil {
		configuration.Protocol = new(controlv1.ServiceProtocolHTTP)
	}
	if configuration.Target == "" {
		configuration.Target = "app"
	}
	configuration.Name, configuration.DomainId = &name, &f.DomainID
	if configuration.Hostname == nil {
		configuration.Hostname = new(name + "." + f.Namespace)
	}
	return f.seed.CreateService(ctx, "tm_0000000000000000000001", name, id(f.t, opaqueid.IdempotencyPrefix), controlv1.ServiceMetadata{}, &configuration)
}

func (f *Fixture) NamespaceEnrollment(ctx context.Context) (string, error) {
	owner, err := f.Owner()
	if err != nil {
		return "", err
	}
	e, err := owner.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: "tm_0000000000000000000001", DomainId: &f.DomainID, Name: "go", Kind: "installed"})
	return e.EnrollmentKey, err
}

func (f *Fixture) OwnerVisitorToken(ctx context.Context, service string) (controlv1.VisitorTokenResponse, error) {
	owner, err := f.Owner()
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	return owner.IssueVisitorToken(ctx, controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: service}, Source: json.RawMessage(`{"kind":"control_session"}`)})
}

// browserhandoff seeds only the fake authority's authenticated browser session.
// redemption and permission installation still use the real service browser API.
func (f *Fixture) BrowserHandoff(service string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	cookie, ticket := secret(f.t), secret(f.t)
	f.browsers[cookie] = browserSession{service: service, subject: visitortoken.Browser{IdentityID: "ident_0000000000000000000001", SessionID: id(f.t, opaqueid.ControlSessionPrefix)}}
	f.handoffs[ticket] = cookie
	return ticket
}

func (f *Fixture) DeletedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.deleted...)
}

func write(w http.ResponseWriter, value any) { writeStatus(w, 200, value) }
func writeStatus(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func denied(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(401)
	_ = json.NewEncoder(w).Encode(controlv1.Problem{Type: "about:blank", Title: "publisher proof rejected", Code: controlv1.Unauthenticated, Status: 401})
}
func decode(r *http.Request, value any) bool {
	return httpjson.Decode(json.NewDecoder(r.Body), value) == nil
}

func (f *Fixture) canRead(e *enrollment, service controlv1.Service) bool {
	if e == nil || service.TeamId != e.result.TeamId {
		return false
	}
	if e.result.Kind == authorityv1.Service {
		return e.result.ServiceId != nil && *e.result.ServiceId == service.Id
	}
	return e.result.Kind == authorityv1.Namespace && f.allocatedOwner[service.Id] == e.result.GrantId
}

func (f *Fixture) serve(w http.ResponseWriter, r *http.Request) {
	if f.serveLocal(w, r) {
		return
	}
	if r.Method == http.MethodGet && r.URL.Path == "/v1/discovery" {
		f.forward(w, r, false)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/publisher-enrollments" {
		f.enroll(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/publisher-enrollments/redeem" {
		var body authorityv1.RedeemPublisherEnrollmentRequest
		if !decode(r, &body) {
			w.WriteHeader(400)
			return
		}
		public, err := base64.RawURLEncoding.Strict().DecodeString(body.PublicKey)
		f.mu.Lock()
		defer f.mu.Unlock()
		e := f.enrollments[body.EnrollmentKey]
		if err != nil || len(public) != ed25519.PublicKeySize || e == nil || e.public != nil && !bytes.Equal(e.public, public) {
			denied(w)
			return
		}
		e.public = append(ed25519.PublicKey(nil), public...)
		write(w, e.result)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/publisher-token" {
		var body authorityv1.PublisherTokenRequest
		if !decode(r, &body) {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		e := f.grants[body.GrantId]
		if e == nil || e.result.ClientId != body.ClientId || len(e.public) != ed25519.PublicKeySize {
			denied(w)
			return
		}
		proof, err := publisherproof.Verify(body.ClientAssertion, body.ClientId, e.result.KeyId, body.GrantId, f.URL+"/v1/publisher-token", e.public, time.Now())
		if err != nil || f.replays[proof.ID] {
			denied(w)
			return
		}
		f.replays[proof.ID] = true
		token := "pta_" + secret(f.t)
		f.tokens[token] = e
		write(w, authorityv1.PublisherTokenResponse{AccessToken: token, TokenType: "Bearer", GrantId: body.GrantId, ExpiresIn: 300})
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/visitor-policy" {
		f.policy(w, r)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/visitor-tokens" {
		f.visitorToken(w, r)
		return
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) >= 5 && parts[0] == "v1" && parts[1] == "services" && parts[3] == "runs" {
		f.run(w, r, parts)
		return
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if bearer == f.OwnerToken {
		if len(parts) == 4 && parts[0] == "v1" && parts[1] == "services" && parts[3] == "http-grants" && r.Method == http.MethodPost {
			f.createVisitorGrant(w, r, parts[2])
			return
		}
		f.forward(w, r, true)
		return
	}
	f.mu.Lock()
	e := f.tokens[bearer]
	f.mu.Unlock()
	if e == nil {
		denied(w)
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/publisher/services" {
		f.allocate(w, r, e)
		return
	}
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "publisher" && parts[2] == "services" {
		service, _, found := f.backend.Service(parts[3])
		f.mu.Lock()
		allowed := found && f.canRead(e, service)
		f.mu.Unlock()
		if !allowed {
			denied(w)
			return
		}
		if r.Method == http.MethodDelete {
			f.mu.Lock()
			if f.allocatedOwner[service.Id] != e.result.GrantId || !service.Ephemeral {
				f.mu.Unlock()
				denied(w)
				return
			}
			if service.Enabled {
				f.deleted = append(f.deleted, service.Id)
				f.Deletions.Add(1)
			}
			f.mu.Unlock()
			r.URL.Path = "/v1/services/" + service.Id
			f.forward(w, r, true)
		} else if r.Method == http.MethodGet && service.Enabled {
			write(w, service)
		} else {
			http.NotFound(w, r)
		}
		return
	}
	if len(parts) == 4 && parts[0] == "v1" && parts[1] == "services" && parts[3] == "runs" && r.Method == http.MethodPost {
		service, _, found := f.backend.Service(parts[2])
		f.mu.Lock()
		allowed := found && service.Enabled && f.canRead(e, service)
		f.mu.Unlock()
		if !allowed {
			denied(w)
			return
		}
		if !opaqueid.Valid(r.Header.Get("Idempotency-Key"), opaqueid.IdempotencyPrefix) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.backend.BindPublisher(r.Header.Get("Idempotency-Key"), e.result)
		f.forward(w, r, false)
		return
	}
	http.NotFound(w, r)
}

func (f *Fixture) enroll(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer "+f.OwnerToken {
		denied(w)
		return
	}
	var body controlv1.CreatePublisherEnrollmentRequest
	if !decode(r, &body) || body.TeamId != "tm_0000000000000000000001" {
		w.WriteHeader(400)
		return
	}
	result := authorityv1.PublisherEnrollmentResult{ClientId: id(f.t, opaqueid.PublisherIdentityPrefix), KeyId: id(f.t, opaqueid.PublisherIdentityKeyPrefix),
		GrantId: id(f.t, opaqueid.PublisherGrantPrefix), TeamId: body.TeamId}
	if body.ServiceId != nil && body.DomainId == nil {
		service, _, found := f.backend.Service(*body.ServiceId)
		if !found || !service.Enabled || service.TeamId != body.TeamId {
			denied(w)
			return
		}
		result.Kind, result.ServiceId = authorityv1.Service, body.ServiceId
	} else if body.DomainId != nil && *body.DomainId == f.DomainID && body.ServiceId == nil {
		result.Kind, result.DomainId, result.Namespace = authorityv1.Namespace, body.DomainId, &f.Namespace
	} else {
		w.WriteHeader(400)
		return
	}
	enrollmentID := id(f.t, opaqueid.PublisherEnrollmentPrefix)
	token := enrollmentID + "." + secret(f.t)
	f.mu.Lock()
	e := &enrollment{result: result}
	f.enrollments[token], f.grants[result.GrantId] = e, e
	f.mu.Unlock()
	f.Enrollments.Add(1)
	writeStatus(w, 201, controlv1.PublisherEnrollment{Id: enrollmentID, EnrollmentKey: token, ExpiresAt: time.Now().Add(time.Minute),
		TeamId: body.TeamId, Kind: controlv1.PublisherEnrollmentKind(result.Kind), ServiceId: result.ServiceId, DomainId: result.DomainId, Namespace: result.Namespace})
}

func (f *Fixture) allocate(w http.ResponseWriter, r *http.Request, e *enrollment) {
	var body controlv1.AllocateServiceRequest
	if e.result.Kind != authorityv1.Namespace || !decode(r, &body) || !opaqueid.Valid(body.InvocationId, opaqueid.InvocationPrefix) ||
		body.ExpiresAt != nil && !body.ExpiresAt.After(time.Now()) {
		w.WriteHeader(400)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	key := e.result.GrantId + "/" + body.InvocationId
	if previous, found := f.allocations[key]; found {
		if !reflect.DeepEqual(body, previous.request) {
			w.WriteHeader(409)
			return
		}
		service, _, _ := f.backend.Service(previous.service)
		if !service.Enabled {
			http.NotFound(w, r)
			return
		}
		writeStatus(w, 200, service)
		return
	}
	configuration := body.Configuration
	configuration.Name = new("temporary")
	configuration.DomainId = e.result.DomainId
	configuration.Hostname = new("eph-" + strings.ToLower(strings.TrimPrefix(body.InvocationId, opaqueid.InvocationPrefix)) + "." + *e.result.Namespace)
	configuration.Ephemeral = new(true)
	if configuration.Protocol == nil {
		configuration.Protocol = new(controlv1.ServiceProtocolHTTP)
	}
	if configuration.Public == nil {
		configuration.Public = new(true)
	}
	service, err := f.seed.CreateService(r.Context(), e.result.TeamId, "temporary", id(f.t, opaqueid.IdempotencyPrefix), controlv1.ServiceMetadata{}, &configuration)
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(502)
		return
	}
	service, err = f.backend.SetServiceExpiration(service.Id, body.ExpiresAt)
	if err != nil {
		f.t.Error(err)
		w.WriteHeader(502)
		return
	}
	f.allocations[key], f.allocatedOwner[service.Id] = allocation{service.Id, body, e.result.GrantId}, e.result.GrantId
	f.Allocations.Add(1)
	writeStatus(w, 201, service)
}

func (f *Fixture) run(w http.ResponseWriter, r *http.Request, parts []string) {
	run, found := f.backend.Run(parts[4])
	if !found && len(parts) == 5 && r.Method == http.MethodDelete {
		// the backend verifies the exact token for an idempotent close.
		f.forward(w, r, false)
		return
	}
	if !found || run.Service.Id != parts[2] {
		http.NotFound(w, r)
		return
	}
	if len(parts) == 6 && parts[5] == "start" {
		f.mu.Lock()
		e := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		allowed := f.canRead(e, run.Service) && e.result.ClientId == run.Preparation.PublisherIdentityId && e.result.GrantId == run.Preparation.PublisherGrantId && e.result.KeyId == run.Preparation.PublisherKeyId
		f.mu.Unlock()
		if !allowed {
			denied(w)
			return
		}
	} else if r.Header.Get("Authorization") != "Bearer "+run.Setup.RunToken {
		denied(w)
		return
	}
	if len(parts) >= 6 && parts[5] == "browser" {
		f.browser(w, r, run, parts)
		return
	}
	f.forward(w, r, false)
}

func (f *Fixture) forward(w http.ResponseWriter, r *http.Request, owner bool) {
	endpoint, _ := url.Parse(f.backend.URL)
	request := r.Clone(r.Context())
	request.URL.Scheme, request.URL.Host, request.Host, request.RequestURI = endpoint.Scheme, endpoint.Host, endpoint.Host, ""
	if owner {
		request.Header.Set("Authorization", "Bearer "+f.backend.AccessToken)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		w.WriteHeader(502)
		return
	}
	defer response.Body.Close()
	for name, values := range response.Header {
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/runs") && response.StatusCode < 300 {
		var preparation controlv1.ServiceRunPreparation
		if json.NewDecoder(response.Body).Decode(&preparation) != nil {
			w.WriteHeader(502)
			return
		}
		f.mu.Lock()
		if !f.seenRuns[preparation.ServiceRunId] {
			f.seenRuns[preparation.ServiceRunId] = true
			f.Runs.Add(1)
		}
		f.mu.Unlock()
		w.Header().Del("Content-Length")
		writeStatus(w, response.StatusCode, preparation)
		return
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}

func (f *Fixture) policy(w http.ResponseWriter, r *http.Request) {
	var body controlv1.PublisherVisitorPolicyRequest
	if !decode(r, &body) {
		w.WriteHeader(400)
		return
	}
	run, found := f.backend.Run(body.RunId)
	if !found || body.Resource.Kind != controlv1.VisitorResourceScopeKindService || body.Resource.Id != run.Service.Id ||
		body.RunNumber != run.Setup.RunNumber || r.Header.Get("Authorization") != "Bearer "+run.Setup.RunToken {
		denied(w)
		return
	}
	saved, configuration, _ := f.backend.Service(run.Service.Id)
	now := time.Now()
	anonymous := configuration.Http != nil && configuration.Http.Access != nil && configuration.Http.Access.Mode != nil && *configuration.Http.Access.Mode == controlv1.Anonymous
	policy := controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: saved.Endpoint.Hostname, Port: 443, Issuer: f.URL,
		VisitorPolicyRevision: 1, MetadataRevision: saved.TrustRevision, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second),
		Enabled: saved.Enabled, Anonymous: anonymous, VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "publishing-fixture", PublicKey: f.visitorKey.Public().(ed25519.PublicKey)}}}
	if saved.Endpoint.Public {
		policy.PublicEndpoint = &controlv1.VisitorPublicEndpoint{Hostname: saved.Endpoint.Hostname, Port: saved.Endpoint.Port, EndpointRevision: saved.EndpointRevision}
	}
	if saved.ExpiresAt != nil {
		policy.ConnectionDeadline = saved.ExpiresAt
		if saved.ExpiresAt.Before(policy.ValidUntil) {
			policy.ValidUntil = *saved.ExpiresAt
		}
		policy.Enabled = policy.Enabled && saved.ExpiresAt.After(now)
	}
	if configuration.Http != nil && configuration.Http.Access != nil && configuration.Http.Access.Ip != nil && len(*configuration.Http.Access.Ip) != 0 {
		key := sha256.Sum256([]byte("publishing-fixture-ip/" + saved.Id))
		policy.Ip = &controlv1.VisitorPolicyIP{Key: key[:], Prefixes: []controlv1.HashedIPPrefix{}}
		for _, text := range *configuration.Http.Access.Ip {
			prefix, err := netip.ParsePrefix(text)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			hashed, err := ippolicy.Hash(key, prefix)
			if err != nil {
				w.WriteHeader(400)
				return
			}
			policy.Ip.Prefixes = append(policy.Ip.Prefixes, controlv1.HashedIPPrefix{Family: controlv1.HashedIPPrefixFamily(hashed.Family), PrefixLength: hashed.Bits, Digest: hashed.Digest})
		}
	}
	write(w, controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: []int64{}, SnapshotRequired: body.AfterRevision == 0, Policy: policy})
}

func (f *Fixture) permission(service string, subject visitortoken.Subject) (controlv1.VisitorTokenResponse, error) {
	saved, _, found := f.backend.Service(service)
	if !found || !saved.Enabled {
		return controlv1.VisitorTokenResponse{}, fmt.Errorf("service unavailable")
	}
	now, expires := time.Now(), time.Now().Add(time.Minute).UTC().Truncate(time.Second)
	if saved.ExpiresAt != nil && saved.ExpiresAt.Before(expires) {
		expires = saved.ExpiresAt.UTC().Truncate(time.Second)
	}
	token, err := visitortoken.Sign(f.URL, "publishing-fixture", f.visitorKey, visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.Service, ID: service},
		Hostname: saved.Endpoint.Hostname, Port: 443, VisitorPolicyRevision: 1, Subject: subject, ExpiresAt: expires}, now)
	if err != nil {
		return controlv1.VisitorTokenResponse{}, err
	}
	return controlv1.VisitorTokenResponse{Resource: controlv1.VisitorResourceScope{Kind: controlv1.VisitorResourceScopeKindService, Id: service},
		Hostname: saved.Endpoint.Hostname, Port: 443, VisitorPolicyRevision: 1, ServiceTrustRevision: &saved.TrustRevision, ExpiresAt: expires, VisitorToken: token.Reveal()}, nil
}

func (f *Fixture) visitorToken(w http.ResponseWriter, r *http.Request) {
	var body controlv1.VisitorTokenRequest
	var source struct{ Kind, Credential, Secret string }
	if !decode(r, &body) || body.Resource.Kind != controlv1.VisitorResourceScopeKindService || json.Unmarshal(body.Source, &source) != nil {
		w.WriteHeader(400)
		return
	}
	var subject visitortoken.Subject
	f.mu.Lock()
	switch source.Kind {
	case "control_session":
		if r.Header.Get("Authorization") == "Bearer "+f.OwnerToken {
			subject = visitortoken.Browser{IdentityID: "ident_0000000000000000000001", SessionID: "cs_0000000000000000000001"}
		}
	case "grant":
		if grant, ok := f.visitorGrants[source.Credential]; ok && grant.service == body.Resource.Id {
			subject = visitortoken.Grant{GrantID: grant.id, Kind: "token"}
		}
	case "browser_session":
		if browser, ok := f.browsers[source.Secret]; ok && browser.service == body.Resource.Id {
			subject = browser.subject
		}
	}
	f.mu.Unlock()
	if subject == nil {
		denied(w)
		return
	}
	permission, err := f.permission(body.Resource.Id, subject)
	if err != nil {
		denied(w)
		return
	}
	write(w, permission)
}

func (f *Fixture) createVisitorGrant(w http.ResponseWriter, r *http.Request, service string) {
	var body controlv1.CreateVisitorCredentialRequest
	if !decode(r, &body) {
		w.WriteHeader(400)
		return
	}
	grant, credential := id(f.t, "shg_"), secret(f.t)
	permission, err := f.permission(service, visitortoken.Grant{GrantID: grant, Kind: "token"})
	if err != nil {
		denied(w)
		return
	}
	f.mu.Lock()
	f.visitorGrants[credential] = visitorGrant{service, grant}
	f.mu.Unlock()
	writeStatus(w, 201, controlv1.VisitorCredential{GrantId: grant, Kind: controlv1.VisitorCredentialKind("token"), RefreshCredential: credential, Permission: permission, ExpiresAt: permission.ExpiresAt})
}

func (f *Fixture) browser(w http.ResponseWriter, r *http.Request, run testutil.PublishingRun, parts []string) {
	var body controlv1.ServiceBrowserRequest
	if len(parts) != 7 || !decode(r, &body) || body.RunNumber != run.Setup.RunNumber {
		w.WriteHeader(400)
		return
	}
	f.mu.Lock()
	cookie := body.Secret
	if parts[6] == "handoff" {
		cookie = f.handoffs[body.Secret]
		delete(f.handoffs, body.Secret)
	}
	browser, found := f.browsers[cookie]
	if r.Method == http.MethodDelete {
		delete(f.browsers, cookie)
	}
	f.mu.Unlock()
	if !found || browser.service != run.Service.Id {
		denied(w)
		return
	}
	if r.Method == http.MethodDelete {
		w.WriteHeader(204)
		return
	}
	permission, err := f.permission(browser.service, browser.subject)
	if err != nil {
		denied(w)
		return
	}
	if parts[6] == "handoff" {
		write(w, controlv1.BrowserHandoffResponse{CookieSecret: cookie, ExpiresAt: permission.ExpiresAt, Permission: &permission, ReturnPath: "/"})
	} else {
		write(w, controlv1.BrowserAccessResponse{IdentityId: browser.subject.IdentityID, DisplayName: "fixture owner", TeamMember: true, VisitAllowed: true})
	}
}
