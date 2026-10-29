// package publishingtest exercises scoped native clients against signed
// enrollment HTTP exchanges and real publisher TLS/yamux lifecycle connections.
package publishingtest

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/testutil"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type enrollment struct {
	result authorityv1.PublisherEnrollmentResult
	public ed25519.PublicKey
}

type Fixture struct {
	URL, Namespace, DomainID, OwnerToken      string
	HTTP                                      *http.Client
	Enrollments, Allocations, Runs, Deletions atomic.Int32
	VisitorDecisions                          atomic.Int32
	visitorSequence                           atomic.Uint32
	mu                                        sync.Mutex
	backend                                   *testutil.PublishingFixture
	seed                                      *clientcontrol.Client
	routes                                    map[string]controlv1.PublicURL
	enrollments                               map[string]*enrollment
	grants                                    map[string]*enrollment
	tokens                                    map[string]*enrollment
	replays                                   map[string]bool
	runURLs                                   map[string]string
	deleted                                   []string
	setups                                    map[string]controlv1.PublishRunSetup
	hooks                                     testutil.PublishingHooks
	t                                         *testing.T
	relayOnce                                 sync.Once
	relayAddress                              string
	relayErr                                  error
	sessions                                  map[string]relaySession
}

func New(t *testing.T, hooks testutil.PublishingHooks) *Fixture {
	t.Helper()
	backend := testutil.NewPublishingFixture(t, testutil.PublishingHooks{Close: hooks.Close})
	seed, err := clientcontrol.New(backend.URL, http.DefaultClient, credentials.AccessToken(backend.AccessToken))
	if err != nil {
		t.Fatal(err)
	}
	f := &Fixture{Namespace: backend.Namespace, DomainID: "dom_0000000000000000000001", OwnerToken: backend.AccessToken, backend: backend, seed: seed, routes: map[string]controlv1.PublicURL{}, enrollments: map[string]*enrollment{}, grants: map[string]*enrollment{}, tokens: map[string]*enrollment{}, replays: map[string]bool{}, runURLs: map[string]string{}, setups: map[string]controlv1.PublishRunSetup{}, hooks: hooks, t: t, sessions: map[string]relaySession{}}
	server := httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	f.URL, f.HTTP = server.URL, server.Client()
	return f
}

func (f *Fixture) Owner() (*clientcontrol.Client, error) {
	return clientcontrol.New(f.URL, f.HTTP, credentials.AccessToken(f.OwnerToken))
}

func (f *Fixture) SavedPublicURL(ctx context.Context, purpose controlv1.PublicURLPurpose, target string) (controlv1.PublicURL, error) {
	protocol := controlv1.Http
	key, _ := opaqueid.New(opaqueid.IdempotencyPrefix)
	publicURL, err := f.seed.CreatePublicURL(ctx, controlv1.CreatePublicURLRequest{TeamId: "tm_0000000000000000000001", DomainId: f.DomainID, CanonicalHostname: string(purpose) + "." + f.Namespace, Target: target, Purpose: purpose, PublicUrlScope: controlv1.Member, ServiceProtocol: &protocol}, key)
	if err != nil {
		return publicURL, err
	}
	publicURL.ServiceProtocol = controlv1.Http
	f.mu.Lock()
	f.routes[publicURL.Id] = publicURL
	f.mu.Unlock()
	return publicURL, nil
}

func (f *Fixture) NamespaceEnrollment(ctx context.Context) (string, error) {
	owner, err := f.Owner()
	if err != nil {
		return "", err
	}
	e, err := owner.CreatePublisherEnrollment(ctx, controlv1.CreatePublisherEnrollmentRequest{TeamId: "tm_0000000000000000000001", DomainId: &f.DomainID, Name: "go", Kind: "installed"})
	return e.EnrollmentKey, err
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

func (f *Fixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" && r.URL.Path == "/v1/publisher-enrollments" {
		if r.Header.Get("Authorization") != "Bearer "+f.OwnerToken {
			denied(w)
			return
		}
		var b controlv1.CreatePublisherEnrollmentRequest
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			w.WriteHeader(400)
			return
		}
		id, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
		client, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
		key, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
		grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
		var secret [32]byte
		_, _ = rand.Read(secret[:])
		token := id + "." + base64.RawURLEncoding.EncodeToString(secret[:])
		result := authorityv1.PublisherEnrollmentResult{ClientId: client, KeyId: key, GrantId: grant, TeamId: b.TeamId}
		if b.PublicUrlId != nil {
			result.Kind, result.PublicUrlId = "saved_public_url", b.PublicUrlId
		} else if b.DomainId != nil {
			namespace := f.Namespace
			result.Kind, result.DomainId, result.Namespace = "namespace", b.DomainId, &namespace
		} else {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		e := &enrollment{result: result}
		f.enrollments[token], f.grants[grant] = e, e
		f.mu.Unlock()
		f.Enrollments.Add(1)
		writeStatus(w, 201, controlv1.PublisherEnrollment{Id: id, EnrollmentKey: token, ExpiresAt: time.Now().Add(time.Minute), TeamId: b.TeamId, Kind: controlv1.PublisherEnrollmentKind(result.Kind), PublicUrlId: b.PublicUrlId, DomainId: result.DomainId, Namespace: result.Namespace})
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/publisher-enrollments/redeem" {
		var b authorityv1.RedeemPublisherEnrollmentRequest
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			w.WriteHeader(400)
			return
		}
		public, err := base64.RawURLEncoding.Strict().DecodeString(b.PublicKey)
		f.mu.Lock()
		defer f.mu.Unlock()
		e := f.enrollments[b.EnrollmentKey]
		if err != nil || len(public) != 32 || e == nil || e.public != nil && !bytes.Equal(e.public, public) {
			denied(w)
			return
		}
		e.public = append(ed25519.PublicKey(nil), public...)
		write(w, e.result)
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/publisher-token" {
		var b authorityv1.PublisherTokenRequest
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			w.WriteHeader(400)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		e := f.grants[b.GrantId]
		if e == nil || e.result.ClientId != b.ClientId || len(e.public) != 32 {
			denied(w)
			return
		}
		proof, err := publisherproof.Verify(b.ClientAssertion, b.ClientId, e.result.KeyId, b.GrantId, f.URL+"/v1/publisher-token", e.public, time.Now())
		if err != nil || f.replays[proof.ID] {
			denied(w)
			return
		}
		f.replays[proof.ID] = true
		var secret [32]byte
		_, _ = rand.Read(secret[:])
		token := "pta_" + base64.RawURLEncoding.EncodeToString(secret[:])
		f.tokens[token] = e
		write(w, authorityv1.PublisherTokenResponse{AccessToken: token, TokenType: "Bearer", GrantId: b.GrantId, ExpiresIn: 300})
		return
	}
	if r.Method == http.MethodPost && r.URL.Path == "/v1/visitor-policy" {
		var body controlv1.PublisherVisitorPolicyRequest
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		setup, found := f.setups[body.RunId]
		f.mu.Unlock()
		if !found || body.Resource.Kind != "public_url" || body.Resource.Id != setup.PublicUrl.Id || body.RunNumber != setup.PublishRun.PublishRunNumber || r.Header.Get("Authorization") != "Bearer "+setup.PublishRunToken {
			denied(w)
			return
		}
		now := time.Now()
		key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{17}, 32))
		write(w, controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: []int64{}, SnapshotRequired: body.AfterRevision == 0,
			Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: setup.PublicUrl.CanonicalHostname, Port: 443, Issuer: f.URL,
				VisitorPolicyRevision: 1, KeyRevision: 1, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Anonymous: true,
				VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "publishing-fixture", PublicKey: key.Public().(ed25519.PublicKey)}},
				WorkloadLeases:   []controlv1.VisitorWorkloadLease{}, StreamAllocations: []controlv1.StreamCapacityAllocation{{Id: "salloc_" + strings.TrimPrefix(body.Resource.Id, "url_"), Resource: body.Resource, RunId: body.RunId, RunNumber: body.RunNumber,
					IngressId: "fixture-ingress", IngressRunId: "fixture-process", IngressLeaseRevision: 1, Capacity: 1024, ObservedAt: now, ValidUntil: now.Add(10 * time.Second), PublisherObserved: true, PublisherObservedUntil: new(now.Add(10 * time.Second)), ReservationKey: bytes.Repeat([]byte{0x42}, 32)}}}})
		return
	}
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/publish-runs/") && strings.HasSuffix(r.URL.Path, "/visitor-access") {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/publish-runs/"), "/visitor-access")
		f.mu.Lock()
		setup, found := f.setups[id]
		f.mu.Unlock()
		var body controlv1.HTTPVisitorRequest
		if !found || json.NewDecoder(r.Body).Decode(&body) != nil || body.PublishRunNumber != setup.PublishRun.PublishRunNumber || r.Header.Get("Authorization") != "Bearer "+setup.PublishRunToken {
			denied(w)
			return
		}
		f.VisitorDecisions.Add(1)
		write(w, controlv1.HTTPVisitorResponse{VisitAllowed: true, ValidUntil: new(time.Now().Add(time.Minute))})
		return
	}
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/publish-runs/") && (strings.HasSuffix(r.URL.Path, "/share-access") || strings.HasSuffix(r.URL.Path, "/share-state")) {
		path := strings.TrimPrefix(r.URL.Path, "/v1/publish-runs/")
		id, _, _ := strings.Cut(path, "/")
		f.mu.Lock()
		setup, found := f.setups[id]
		f.mu.Unlock()
		var body struct {
			PublishRunNumber int64 `json:"publish_run_number"`
		}
		if !found || json.NewDecoder(r.Body).Decode(&body) != nil || body.PublishRunNumber != setup.PublishRun.PublishRunNumber || r.Header.Get("Authorization") != "Bearer "+setup.PublishRunToken {
			denied(w)
			return
		}
		if strings.HasSuffix(path, "/share-access") {
			w.WriteHeader(http.StatusNoContent)
		} else {
			write(w, controlv1.PublishRunShareState{SchemaVersion: 1, Shares: []controlv1.PublisherShare{}})
		}
		return
	}
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/publish-runs/") && strings.HasSuffix(r.URL.Path, "/ready") {
		// consume the version body before a hook waits for HTTP/1 cancellation.
		_, _ = io.Copy(io.Discard, r.Body)
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/publish-runs/"), "/ready")
		f.mu.Lock()
		setup := f.setups[id]
		f.mu.Unlock()
		if f.hooks.Ready != nil {
			if err := f.hooks.Ready(r.Context(), setup); err != nil {
				w.WriteHeader(503)
				return
			}
		}
		write(w, setup.PublishRun)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/v1/publish-runs/") || strings.HasPrefix(r.URL.Path, "/v1/certificate-issuances/") {
		f.forward(w, r)
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	f.mu.Lock()
	e := f.tokens[token]
	f.mu.Unlock()
	if e == nil {
		denied(w)
		return
	}
	if r.Method == "GET" && r.URL.Path == "/v1/publisher/public-url" {
		if e.result.Kind != "saved_public_url" {
			denied(w)
			return
		}
		f.mu.Lock()
		publicURL := f.routes[*e.result.PublicUrlId]
		f.mu.Unlock()
		write(w, publicURL)
		return
	}
	if r.Method == "POST" && r.URL.Path == "/v1/publisher/public-urls" {
		if e.result.Kind != "namespace" {
			denied(w)
			return
		}
		var b controlv1.AllocateEphemeralPublicURLRequest
		if json.NewDecoder(r.Body).Decode(&b) != nil || !opaqueid.Valid(b.InvocationId, opaqueid.InvocationPrefix) {
			w.WriteHeader(400)
			return
		}
		protocol, ephemeral := controlv1.Http, true
		publicURL, err := f.seed.CreatePublicURL(r.Context(), controlv1.CreatePublicURLRequest{TeamId: e.result.TeamId, DomainId: *e.result.DomainId, CanonicalHostname: "eph-" + strings.ToLower(strings.TrimPrefix(b.InvocationId, opaqueid.InvocationPrefix)) + "." + *e.result.Namespace, Target: b.Target, Purpose: controlv1.App, PublicUrlScope: controlv1.Member, Ephemeral: &ephemeral, ServiceProtocol: &protocol}, b.InvocationId)
		if err != nil {
			w.WriteHeader(502)
			return
		}
		publicURL.Ephemeral, publicURL.ServiceProtocol = true, controlv1.Http
		f.mu.Lock()
		f.routes[publicURL.Id] = publicURL
		f.mu.Unlock()
		f.Allocations.Add(1)
		writeStatus(w, 201, publicURL)
		return
	}
	if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/v1/publisher/public-urls/") {
		id := strings.TrimPrefix(r.URL.Path, "/v1/publisher/public-urls/")
		f.mu.Lock()
		publicURL, found := f.routes[id]
		if !found || e.result.Kind != "namespace" || !publicURL.Ephemeral || !strings.HasSuffix(publicURL.CanonicalHostname, "."+*e.result.Namespace) {
			f.mu.Unlock()
			denied(w)
			return
		}
		f.deleted = append(f.deleted, id)
		f.mu.Unlock()
		f.Deletions.Add(1)
		w.WriteHeader(204)
		return
	}
	if r.Method == "POST" && strings.HasPrefix(r.URL.Path, "/v1/public-urls/") && strings.HasSuffix(r.URL.Path, "/publish-runs") {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/public-urls/"), "/publish-runs")
		f.mu.Lock()
		publicURL, found := f.routes[id]
		f.mu.Unlock()
		if !found || e.result.Kind == "saved_public_url" && id != *e.result.PublicUrlId || e.result.Kind == "namespace" && (!publicURL.Ephemeral || !strings.HasSuffix(publicURL.CanonicalHostname, "."+*e.result.Namespace)) {
			denied(w)
			return
		}
		if _, err := publisherproof.VerifyRun(e.public, r.Header.Get("Publisher-Run-Proof"), id, r.Header.Get("Idempotency-Key")); err != nil {
			denied(w)
			return
		}
		f.Runs.Add(1)
		f.forward(w, r)
		return
	}
	http.NotFound(w, r)
}

func (f *Fixture) forward(w http.ResponseWriter, r *http.Request) {
	endpoint, _ := url.Parse(f.backend.URL)
	request := r.Clone(r.Context())
	request.URL.Scheme, request.URL.Host, request.Host, request.RequestURI = endpoint.Scheme, endpoint.Host, endpoint.Host, ""
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
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/publish-runs") && response.StatusCode < 300 {
		var setup controlv1.PublishRunSetup
		if json.NewDecoder(response.Body).Decode(&setup) != nil {
			w.WriteHeader(502)
			return
		}
		f.mu.Lock()
		setup.PublicUrl = f.routes[setup.PublicUrl.Id]
		f.runURLs[setup.PublishRun.Id] = setup.PublicUrl.Id
		f.mu.Unlock()
		f.relayOnce.Do(func() { f.relayAddress, f.relayErr = f.startRelay(r.Context(), setup) })
		if f.relayErr != nil {
			w.WriteHeader(502)
			return
		}
		for i := range setup.PublisherConnections {
			setup.PublisherConnections[i].RelayAddress = f.relayAddress
		}
		f.mu.Lock()
		f.setups[setup.PublishRun.Id] = setup
		f.mu.Unlock()
		w.Header().Del("Content-Length")
		writeStatus(w, response.StatusCode, setup)
		return
	}
	if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/heartbeat") && response.StatusCode < 300 {
		var heartbeat controlv1.PublishRunHeartbeat
		if json.NewDecoder(response.Body).Decode(&heartbeat) != nil {
			w.WriteHeader(502)
			return
		}
		for i := range heartbeat.PublisherConnections {
			heartbeat.PublisherConnections[i].RelayAddress = f.relayAddress
		}
		w.Header().Del("Content-Length")
		writeStatus(w, response.StatusCode, heartbeat)
		return
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, response.Body)
}
