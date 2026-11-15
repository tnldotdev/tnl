package invocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type serviceSetupTransport func(*http.Request) (*http.Response, error)

func (f serviceSetupTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type serviceSetupFixture struct {
	t                                               *testing.T
	state                                           *clientstate.Database
	services                                        publisherServices
	saved, parent                                   controlv1.Service
	declaration                                     controlv1.ProjectServiceConfiguration
	identity                                        authorityv1.PublisherEnrollmentResult
	enrollment                                      string
	public                                          ed25519.PublicKey
	requests, creates, updates, changes, gets, runs int
	enrollments, redemptions                        int
	created                                         bool
	before                                          func(*http.Request) (*http.Response, bool)
	afterUpdate                                     func() error
}

func serviceTestID(t *testing.T, prefix string) string {
	t.Helper()
	id, err := opaqueid.New(prefix)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func serviceTestResponse(r *http.Request, status int, value any) *http.Response {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(bytes.NewReader(data)), Request: r}
}

func newServiceSetupFixture(t *testing.T, hostname string) *serviceSetupFixture {
	t.Helper()
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	const server = "https://control.example"
	store, err := state.Server(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	domain := serviceTestID(t, opaqueid.DomainPrefix)
	f := &serviceSetupFixture{t: t, state: state, saved: controlv1.Service{Id: serviceTestID(t, opaqueid.ServicePrefix),
		TeamId: serviceTestID(t, opaqueid.TeamPrefix), DomainId: &domain, Protocol: controlv1.ServiceProtocolHTTP,
		Enabled: true, TrustRevision: 1, CreatedAt: time.Now().UTC(),
		Endpoint: &controlv1.ServiceEndpoint{Hostname: hostname, Port: 443, Public: true}}}
	f.identity = authorityv1.PublisherEnrollmentResult{ClientId: serviceTestID(t, opaqueid.PublisherIdentityPrefix),
		GrantId: serviceTestID(t, opaqueid.PublisherGrantPrefix), KeyId: serviceTestID(t, opaqueid.PublisherIdentityKeyPrefix),
		TeamId: f.saved.TeamId, Kind: authorityv1.Service, ServiceId: &f.saved.Id}
	f.enrollment = serviceTestID(t, opaqueid.PublisherEnrollmentPrefix)
	client := &http.Client{Transport: serviceSetupTransport(f.serve)}
	control, err := clientcontrol.New(server, client, "session")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server, client, "session")
	if err != nil {
		t.Fatal(err)
	}
	f.services = publisherServices{state: store, routes: control, hostname: hostname, teamID: f.saved.TeamId, domainID: domain,
		authenticated: &auth.Client{ServerEndpoint: server, Control: control, Authority: authority}}
	return f
}

func (f *serviceSetupFixture) serve(r *http.Request) (*http.Response, error) {
	f.requests++
	if f.before != nil {
		if response, handled := f.before(r); handled {
			return response, nil
		}
	}
	token := r.Header.Get("Authorization")
	management := func() {
		if token != "Bearer session" {
			f.t.Error("service setup did not use the selected management session", r.Method, r.URL.Path)
		}
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /v1/services":
		management()
		page := controlv1.ServicePage{Services: []controlv1.ServiceSummary{}}
		if f.created {
			page.Services = append(page.Services, controlv1.ServiceSummary{Id: f.saved.Id, TeamId: f.saved.TeamId,
				Name: f.saved.Name, DomainId: f.saved.DomainId, Endpoint: f.saved.Endpoint, Enabled: true,
				Protocol: f.saved.Protocol, TrustRevision: f.saved.TrustRevision})
		}
		return serviceTestResponse(r, 200, page), nil
	case "POST /v1/services":
		management()
		var body controlv1.CreateServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		if f.created || body.Placement == nil || body.Placement.Hostname == nil || *body.Placement.Hostname != f.saved.Endpoint.Hostname ||
			body.Placement.DomainId == nil || *body.Placement.DomainId != *f.saved.DomainId || body.Configuration == nil ||
			body.Configuration.Target != "app" || body.TeamId != f.saved.TeamId {
			f.t.Error("creation changed an existing service or its exact placement/declaration", body)
		}
		f.created, f.saved.Name = true, body.Name
		f.declaration = *body.Configuration
		f.saved.TargetTls = body.TargetTls
		f.applyDeclaration()
		f.creates++
		return serviceTestResponse(r, 201, f.saved), nil
	case "GET /v1/services/" + f.saved.Id:
		management()
		f.gets++
		return serviceTestResponse(r, 200, f.saved), nil
	case "PUT /v1/services/" + f.saved.Id:
		management()
		var body controlv1.UpdateServiceRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		if body.Configuration == nil || body.ExpectedTrustRevision != f.saved.TrustRevision || body.Protocol != controlv1.ServiceProtocolHTTP ||
			body.ExpectedPublisherPool == nil || *body.ExpectedPublisherPool != f.saved.PublisherPool {
			f.t.Error("service update omitted its declaration or current trust revision", body)
		}
		f.updates++
		if !reflect.DeepEqual(f.declaration, *body.Configuration) {
			f.changes++
		}
		f.declaration = *body.Configuration
		f.saved.TargetTls, f.saved.PublisherPool = body.TargetTls, body.PublisherPool
		f.applyDeclaration()
		if f.afterUpdate != nil {
			if err := f.afterUpdate(); err != nil {
				return nil, err
			}
		}
		return serviceTestResponse(r, 200, f.saved), nil
	case "POST /v1/publisher-enrollments":
		management()
		var body controlv1.CreatePublisherEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		if body.ServiceId == nil || *body.ServiceId != f.saved.Id || body.DomainId != nil || body.TeamId != f.saved.TeamId {
			f.t.Error("service enrollment widened the actual grant", body)
		}
		f.enrollments++
		return serviceTestResponse(r, 201, controlv1.PublisherEnrollment{Id: f.enrollment,
			EnrollmentKey: f.enrollment + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			ExpiresAt:     time.Now().Add(time.Minute), TeamId: f.saved.TeamId, Kind: "service", ServiceId: &f.saved.Id}), nil
	case "POST /v1/publisher-enrollments/redeem":
		var body authorityv1.RedeemPublisherEnrollmentRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		if token != "" {
			f.t.Error("redemption used management authority")
		}
		var err error
		f.public, err = base64.RawURLEncoding.DecodeString(body.PublicKey)
		f.redemptions++
		return serviceTestResponse(r, 200, f.identity), err
	case "POST /v1/publisher-token":
		var body authorityv1.PublisherTokenRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			return nil, err
		}
		if token != "" {
			f.t.Error("assertion exchange used management authority")
		}
		if _, err := publisherproof.Verify(body.ClientAssertion, f.identity.ClientId, f.identity.KeyId, f.identity.GrantId,
			f.services.authenticated.ServerEndpoint+"/v1/publisher-token", f.public, time.Now()); err != nil {
			return nil, err
		}
		return serviceTestResponse(r, 200, authorityv1.PublisherTokenResponse{AccessToken: "service-access", TokenType: "Bearer", ExpiresIn: 60, GrantId: f.identity.GrantId}), nil
	case "GET /v1/publisher/services/" + f.saved.Id:
		if token != "Bearer service-access" {
			f.t.Error("service read escaped its actual publisher grant")
		}
		return serviceTestResponse(r, 200, f.saved), nil
	case "GET /v1/publisher/services/" + f.parent.Id:
		if f.parent.Id == "" || token != "Bearer parent-access" {
			f.t.Error("parent read did not use its captured publisher access")
		}
		return serviceTestResponse(r, 200, f.parent), nil
	case "POST /v1/services/" + f.saved.Id + "/runs":
		if token != "Bearer service-access" {
			f.t.Error("service run used management or parent authority")
		}
		f.runs++
		return serviceTestResponse(r, 503, map[string]any{"code": "unavailable", "status": 503}), nil
	default:
		return nil, errors.New("unexpected service setup operation: " + r.Method + " " + r.URL.Path)
	}
}

func (f *serviceSetupFixture) applyDeclaration() {
	if f.declaration.RequirePostQuantum != nil {
		f.saved.RequirePostQuantum = *f.declaration.RequirePostQuantum
	}
	if f.declaration.Http != nil {
		f.saved.HttpLimits = f.declaration.Http.Limits
	}
}

func TestReserveConfiguredServiceCreatesBeforeEnrollingPublisher(t *testing.T) {
	f := newServiceSetupFixture(t, "web.member.example")
	prefixes := []string{"192.0.2.1/32"}
	declaration := controlv1.ProjectServiceConfiguration{Target: "app", RequirePostQuantum: new(true),
		Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Anonymous), Ip: &prefixes}}}
	for range 2 {
		saved, err := reserveConfiguredService(t.Context(), f.services, declaration)
		if err != nil || saved.Id != f.saved.Id || f.creates != 1 || f.enrollments != 0 {
			t.Fatal("reservation changed service identity or enrolled prematurely", saved, err, f.creates, f.enrollments)
		}
	}
	if !f.saved.RequirePostQuantum || f.declaration.Http.Access.Mode == nil || *f.declaration.Http.Access.Mode != controlv1.Anonymous {
		t.Fatal("canonical creation lost PQ or visitor policy")
	}
	lock, err := clientstate.LockHostnameContext(t.Context(), f.services.state, f.services.hostname)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	if saved, err := reserveConfiguredService(ctx, f.services, declaration); err != nil || saved.Id != f.saved.Id {
		t.Fatal("unchanged live service waited for its own hostname lock", saved, err)
	}
}

func TestReserveConfiguredServiceUpdatesPolicyOnSameService(t *testing.T) {
	f := newServiceSetupFixture(t, "review.member.example")
	declaration := controlv1.ProjectServiceConfiguration{Target: "app",
		Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Restricted)}}}
	first, err := reserveConfiguredService(t.Context(), f.services, declaration)
	if err != nil {
		t.Fatal(err)
	}
	declaration.Http.Access = &controlv1.ProjectHTTPAccess{Mode: new(controlv1.Anonymous), Ip: new([]string{})}
	for range 2 {
		saved, err := reserveConfiguredService(t.Context(), f.services, declaration)
		if err != nil || saved.Id != first.Id || f.creates != 1 || f.changes != 1 {
			t.Fatal("policy update replaced the service or bypassed declaration approval", saved, err, f.creates, f.changes)
		}
	}
}

func TestReserveConfiguredServiceRereadsConflictAndLostUpdateReply(t *testing.T) {
	for _, scenario := range []string{"conflict", "lost reply"} {
		t.Run(scenario, func(t *testing.T) {
			f := newServiceSetupFixture(t, "hooks.member.example")
			declaration := controlv1.ProjectServiceConfiguration{Target: "app"}
			first, err := reserveConfiguredService(t.Context(), f.services, declaration)
			if err != nil {
				t.Fatal(err)
			}
			declaration.Http = &controlv1.ProjectServiceHTTP{Limits: &controlv1.ProjectHTTPApplicationLimits{Concurrency: new(32)}}
			if scenario == "conflict" {
				f.before = func(r *http.Request) (*http.Response, bool) {
					if r.Method != http.MethodPut {
						return nil, false
					}
					f.before = nil
					f.saved.TrustRevision++
					return serviceTestResponse(r, 409, controlv1.Problem{Code: controlv1.Conflict, Status: 409}), true
				}
			} else {
				f.afterUpdate = func() error { f.afterUpdate = nil; return io.ErrUnexpectedEOF }
			}
			gets := f.gets
			saved, err := reserveConfiguredService(t.Context(), f.services, declaration)
			if err != nil || saved.Id != first.Id || f.creates != 1 || f.gets < gets+2 || f.changes != 1 {
				t.Fatal("uncertain update did not reread and confirm the same service", saved, err, f.creates, f.gets, f.changes)
			}
		})
	}
}
