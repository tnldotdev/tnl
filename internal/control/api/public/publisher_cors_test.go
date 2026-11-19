package public

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	publisherCORSService = "svc_1234567890123456789012"
	publisherCORSRun     = "srun_1234567890123456789012"
	publisherCORSPair    = "cpp_1234567890123456789012"
	publisherCORSRunPath = "/v1/services/" + publisherCORSService + "/runs/" + publisherCORSRun
)

func TestPublisherCORSExactOperationAllowlist(t *testing.T) {
	h := testHandler(t, Config{}, nil, nil, nil)
	for _, operation := range []struct {
		method, path, headers string
	}{
		{"GET", "/v1/projects/shop/deployments/staging/services/web/publication", "authorization"},
		{"POST", "/v1/projects/shop/deployments/staging/services", "authorization, content-type"},
		{"GET", "/v1/publisher/services/" + publisherCORSService, "authorization"},
		{"DELETE", "/v1/publisher/services/" + publisherCORSService, "authorization"},
		{"POST", "/v1/services/" + publisherCORSService + "/runs", "authorization, content-type, idempotency-key"},
		{"POST", publisherCORSRunPath + "/start", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/renew", "authorization, content-type"},
		{"DELETE", publisherCORSRunPath, "authorization"},
		{"POST", publisherCORSRunPath + "/certificate-issuances", "authorization, content-type, idempotency-key"},
		{"GET", publisherCORSRunPath + "/certificate-issuances/issuance", "authorization"},
		{"POST", publisherCORSRunPath + "/certificate-installed", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/supplied-certificate-installed", "authorization, content-type"},
		{"POST", "/v1/visitor-policy", "authorization, content-type"},
		{"GET", publisherCORSRunPath + "/connector-peer-pairs", "authorization"},
		{"POST", publisherCORSRunPath + "/connector-peer-pairs/" + publisherCORSPair + "/delivery", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/connector-peer-pairs/" + publisherCORSPair + "/prepared", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/browser/handoff", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/browser/session", "authorization, content-type"},
		{"DELETE", publisherCORSRunPath + "/browser/session", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/share-redemptions", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/service-observations", "authorization, content-type"},
		{"GET", "/v1/discovery", ""},
	} {
		t.Run(operation.method+" "+operation.path, func(t *testing.T) {
			// preflight has no team query, body, or authentication. it must
			// succeed without parameter decoding, state reads, or mutations.
			r := httptest.NewRequest(http.MethodOptions, operation.path, nil)
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Access-Control-Request-Method", operation.method)
			if operation.headers != "" {
				r.Header.Set("Access-Control-Request-Headers", operation.headers)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != 204 || w.Body.Len() != 0 || w.Header().Get("Access-Control-Allow-Origin") != "*" ||
				w.Header().Get("Access-Control-Allow-Methods") != operation.method || w.Header().Get("Access-Control-Allow-Credentials") != "" ||
				w.Header().Get("Access-Control-Expose-Headers") != "" || w.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("publication preflight entered the handler or widened its grant", w.Code, w.Header())
			}
			if got := strings.ToLower(w.Header().Get("Access-Control-Allow-Headers")); got != operation.headers {
				t.Fatal("publication preflight granted unnecessary headers", got)
			}
		})
	}
	for _, operation := range []struct {
		method, path, headers string
	}{
		{"POST", "/v1/publisher/services", "authorization, content-type"},
		{"POST", "/v1/projects/shop/deployment-credentials", "authorization, content-type"},
		{"POST", "/v1/publisher/deployments/enroll", "content-type"},
		{"POST", "/v1/publisher/deployments/lease", "content-type"},
		{"POST", "/v1/publisher/runtimes/pub_1234567890123456789012/start", "content-type"},
		{"POST", publisherCORSRunPath + "/preview", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/feedback/authorization", "authorization, content-type"},
		{"POST", "/v1/services/" + publisherCORSService + "/client-certificates", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/authorize-client-certificate", "authorization, content-type"},
		{"GET", "/v1/browser/service-login", ""},
		{"POST", "/v1/shares", "authorization, content-type"},
		{"POST", publisherCORSRunPath + "/browser/session", "cookie, content-type"},
		{"POST", publisherCORSRunPath + "/browser/session", "authorization, content-type, x-tnl-actor-token"},
		{"POST", publisherCORSRunPath + "/renew", "authorization, content-type, idempotency-key"},
		{"GET", publisherCORSRunPath + "/certificate-issuances/issuance", "authorization, if-match"},
		{"POST", "/v1/discovery", ""},
		{"HEAD", "/v1/discovery", ""},
	} {
		t.Run("reject "+operation.method+" "+operation.path+" "+operation.headers, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodOptions, operation.path, nil)
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Access-Control-Request-Method", operation.method)
			if operation.headers != "" {
				r.Header.Set("Access-Control-Request-Headers", operation.headers)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code < 400 || w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("unselected publication operation acquired CORS", w.Code, w.Header())
			}
		})
	}
}

type publisherCORSPreparationStore struct {
	PublisherIdentityStore
	DeploymentPublicationStore
	ServiceStore
	ServiceRunStore
	t                *testing.T
	authCalls, calls int
	principal        controlstate.PublisherIdentity
	err              error
}

func (s *publisherCORSPreparationStore) AuthenticatePublisherAccess(_ context.Context, token, source string, _ time.Time) (controlstate.PublisherIdentity, error) {
	s.authCalls++
	if source != "192.0.2.1/32" {
		s.t.Fatal("publisher authentication lost its trusted socket source")
	}
	if token != "pta_explicit-publisher" {
		return controlstate.PublisherIdentity{}, controlstate.ErrPublisherIdentity
	}
	return s.principal, nil
}

func (s *publisherCORSPreparationStore) checkScope(scope controlstate.DeploymentScope, deployment string) {
	s.t.Helper()
	if scope.TeamID != "team_1" || scope.ProjectKey != "shop" || scope.ActorID != "" ||
		scope.AccessToken != "pta_explicit-publisher" || deployment != "staging" {
		s.t.Fatal("publication changed its explicit credential scope")
	}
	s.calls++
}

func (s *publisherCORSPreparationStore) GetDeploymentPublication(_ context.Context, scope controlstate.DeploymentScope, deployment, service string, _ time.Time) (controlstate.ServiceRecord, error) {
	s.checkScope(scope, deployment)
	if service != "web" {
		s.t.Fatal("named publication changed its selected service")
	}
	return controlstate.ServiceRecord{ID: publisherCORSService}, s.err
}

func (s *publisherCORSPreparationStore) AllocateDeploymentPublication(_ context.Context, request controlstate.AllocateDeploymentPublicationRequest) (controlstate.ServiceRecord, error) {
	s.checkScope(request.DeploymentScope, request.Deployment)
	if request.Invocation != "ivk_1234567890123456789012" || request.Configuration.Target != "app" {
		s.t.Fatal("temporary publication changed its captured allocation")
	}
	return controlstate.ServiceRecord{ID: publisherCORSService}, s.err
}

func (s *publisherCORSPreparationStore) GetServiceForPublisher(_ context.Context, service string, principal controlstate.PublisherIdentity, _ time.Time) (controlstate.ServiceRecord, error) {
	if service != publisherCORSService || principal != s.principal {
		s.t.Fatal("publisher read lost its exact service or credential grant")
	}
	s.calls++
	return controlstate.ServiceRecord{ID: service}, s.err
}

func (s *publisherCORSPreparationStore) DeletePublisherService(_ context.Context, principal controlstate.PublisherIdentity, service string, _ time.Time) error {
	if service != publisherCORSService || principal != s.principal {
		s.t.Fatal("temporary cleanup lost its original service or credential grant")
	}
	s.calls++
	return s.err
}

func (s *publisherCORSPreparationStore) PrepareServiceRun(_ context.Context, service string, principal controlstate.PublisherIdentity, key string, now time.Time, request controlstate.ServiceRunRequest) (controlstate.ServiceRunPreparation, error) {
	if principal != s.principal || service != publisherCORSService || key != "exact-run" ||
		request.Metadata.Protocol != "http" || request.Metadata.TrustRevision != 7 {
		s.t.Fatal("run preparation changed its publisher grant or declaration")
	}
	s.calls++
	return controlstate.ServiceRunPreparation{ServiceID: service, RunID: publisherCORSRun, RunNumber: 7,
		Token: "new-private-run-token", Traffic: request.TrafficDefaults, ExpiresAt: now.Add(time.Minute)}, s.err
}

func TestPublisherCORSPreparationKeepsPublisherGrantAndScope(t *testing.T) {
	for _, operation := range []struct {
		method, path, body string
		status, denied     int
		deniedErr          error
	}{
		{"GET", "/v1/projects/shop/deployments/staging/services/web/publication?team_id=team_1", "", 200, 403, controlstate.ErrDeploymentAccess},
		{"POST", "/v1/projects/shop/deployments/staging/services?team_id=team_1", `{"invocation_id":"ivk_1234567890123456789012","configuration":{"protocol":"http","target":"app"}}`, 201, 403, controlstate.ErrDeploymentAccess},
		{"GET", "/v1/publisher/services/" + publisherCORSService, "", 200, 404, controlstate.ErrServiceAccess},
		{"DELETE", "/v1/publisher/services/" + publisherCORSService, "", 204, 401, controlstate.ErrPublisherIdentity},
		{"POST", "/v1/services/" + publisherCORSService + "/runs", `{"protocol":"http","trust_revision":"7"}`, 201, 404, controlstate.ErrServiceAccess},
	} {
		t.Run(operation.method+" "+operation.path, func(t *testing.T) {
			for _, authentication := range []struct {
				name, header        string
				scope               controlstate.PublisherScope
				err                 error
				status, auth, calls int
			}{
				{name: "cookie only", status: 401},
				{name: "wrong scheme", header: "Basic pta_explicit-publisher", status: 401},
				{name: "human token is not publisher proof", header: "Bearer human-control-token", status: 401, auth: 1},
				{name: "publisher", header: "Bearer pta_explicit-publisher", scope: controlstate.PublisherScope{TeamID: "team_1", Kind: controlstate.DeploymentCredentialGrant}, status: operation.status, auth: 1, calls: 1},
				{name: "state denial", header: "Bearer pta_explicit-publisher", scope: controlstate.PublisherScope{TeamID: "team_1", Kind: controlstate.DeploymentCredentialGrant}, err: operation.deniedErr, status: operation.denied, auth: 1, calls: 1},
			} {
				t.Run(authentication.name, func(t *testing.T) {
					store := &publisherCORSPreparationStore{t: t, principal: controlstate.PublisherIdentity{
						ID: "pub_1234567890123456789012", GrantID: "pgr_1234567890123456789012", KeyID: "pky_1234567890123456789012", Scope: authentication.scope,
					}, err: authentication.err}
					h := testHandler(t, Config{DNSAutomation: true}, nil, nil, nil, Stores{PublisherIdentities: store, DeploymentPublication: store, Services: store, ServiceRuns: store})
					r := httptest.NewRequest(operation.method, operation.path, strings.NewReader(operation.body))
					r.Header.Set("Origin", "https://arbitrary.example")
					r.Header.Set("Content-Type", "application/json")
					if strings.HasSuffix(operation.path, "/runs") {
						r.Header.Set("Idempotency-Key", "exact-run")
					}
					r.AddCookie(&http.Cookie{Name: "__Host-tnl-browser", Value: "ambient-browser-secret"})
					if authentication.header != "" {
						r.Header.Set("Authorization", authentication.header)
					}
					w := httptest.NewRecorder()
					h.ServeHTTP(w, r)
					if w.Code != authentication.status || store.authCalls != authentication.auth || store.calls != authentication.calls {
						t.Fatal("CORS changed publisher authorization", w.Code, store.authCalls, store.calls, w.Body.String())
					}
					assertPublisherCORSResponse(t, w)
					for _, secret := range []string{"ambient-browser-secret", "human-control-token", "pta_explicit-publisher"} {
						if strings.Contains(w.Body.String(), secret) {
							t.Fatal("publication reflected authentication material")
						}
					}
					if authentication.status >= 400 && strings.Contains(w.Body.String(), "new-private-run-token") {
						t.Fatal("denied publication disclosed a run credential")
					}
				})
			}
		})
	}
}

func TestPublisherCORSDeploymentSelectionDoesNotBroadenGrantKindOrTeam(t *testing.T) {
	for _, scope := range []controlstate.PublisherScope{
		{TeamID: "other-team", Kind: controlstate.DeploymentCredentialGrant},
		{TeamID: "team_1", Kind: "namespace"},
		{TeamID: "team_1", Kind: "service", ServiceID: publisherCORSService},
	} {
		store := &publisherCORSPreparationStore{t: t, principal: controlstate.PublisherIdentity{Scope: scope}}
		h := testHandler(t, Config{}, nil, nil, nil, Stores{PublisherIdentities: store, DeploymentPublication: store})
		r := httptest.NewRequest(http.MethodGet, "/v1/projects/shop/deployments/staging/services/web/publication?team_id=team_1", nil)
		r.Header.Set("Origin", "https://arbitrary.example")
		r.Header.Set("Authorization", "Bearer pta_explicit-publisher")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != http.StatusForbidden || store.authCalls != 1 || store.calls != 0 {
			t.Fatal("CORS admitted a different team or publisher grant kind", w.Code, store.authCalls, store.calls)
		}
		assertPublisherCORSResponse(t, w)
	}
}

func TestPublisherCORSDiscoveryExposesManagedDomain(t *testing.T) {
	h := testHandler(t, Config{ManagedDomain: "apps.example.test", ControlURL: "https://control.example.test"}, nil, nil, nil)
	r := httptest.NewRequest(http.MethodGet, "/v1/discovery", nil)
	r.Header.Set("Origin", "https://arbitrary.example")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var facts controlv1.ControlDiscovery
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &facts) != nil || facts.ManagedDomain != "apps.example.test" {
		t.Fatal("discovery lost the managed domain", w.Code, w.Body.String())
	}
	assertPublisherCORSResponse(t, w)
}

func assertPublisherCORSResponse(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	if w.Header().Get("Access-Control-Allow-Origin") != "*" || w.Header().Get("Access-Control-Allow-Credentials") != "" ||
		w.Header().Get("Set-Cookie") != "" || w.Header().Get("Access-Control-Expose-Headers") != "" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("publication response changed its cookie or cache boundary", w.Header())
	}
}

func TestPublisherCORSRunOperationsNeverUseAmbientCookies(t *testing.T) {
	// any call through the embedded nil capabilities panics. absent bearer
	// authentication must fail before any run, certificate, or browser state call.
	stores := Stores{
		ServiceRuns:         struct{ ServiceRunStore }{},
		ServiceCertificates: struct{ managedCertificateStore }{},
		ServiceHTTP:         struct{ ServiceHTTPStore }{},
		ConnectorPeerPairs:  struct{ ConnectorPeerPairStore }{},
		ShareAccess:         struct{ ShareAccessStore }{},
		VisitorPolicy:       struct{ publisherVisitorPolicyStore }{},
		ServiceAudit:        struct{ ServiceAuditStore }{},
	}
	h := testHandler(t, Config{ControlURL: "https://control.example.test"}, nil, nil, nil, stores)
	for _, operation := range []struct{ method, path, body string }{
		{"POST", publisherCORSRunPath + "/renew", `{"healthy":true,"stream_capacity":2,"active_streams":0}`},
		{"DELETE", publisherCORSRunPath, ""},
		{"POST", publisherCORSRunPath + "/certificate-issuances", `{}`},
		{"GET", publisherCORSRunPath + "/certificate-issuances/issuance", ""},
		{"POST", publisherCORSRunPath + "/certificate-installed", `{}`},
		{"POST", "/v1/visitor-policy", `{}`},
		{"GET", publisherCORSRunPath + "/connector-peer-pairs", ""},
		{"POST", publisherCORSRunPath + "/connector-peer-pairs/" + publisherCORSPair + "/delivery", `{"delivery_generation":"1"}`},
		{"POST", publisherCORSRunPath + "/connector-peer-pairs/" + publisherCORSPair + "/prepared", `{"phase":"installed","delivery_id":"AQEBAQEBAQEBAQEBAQEBAQ","delivery_generation":"1","binding_expires_at":"2026-11-17T12:00:00Z"}`},
		{"POST", publisherCORSRunPath + "/browser/handoff", `{}`},
		{"POST", publisherCORSRunPath + "/browser/session", `{}`},
		{"DELETE", publisherCORSRunPath + "/browser/session", `{}`},
		{"POST", publisherCORSRunPath + "/share-redemptions", `{"run_number":"7","share_id":"shr_1234567890123456789012","secret":"body-secret"}`},
		{"POST", publisherCORSRunPath + "/service-observations", `{"run_number":"7","events":[]}`},
	} {
		t.Run(operation.method+" "+operation.path, func(t *testing.T) {
			r := httptest.NewRequest(operation.method, operation.path, strings.NewReader(operation.body))
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Content-Type", "application/json")
			if strings.HasSuffix(operation.path, "/certificate-issuances") {
				r.Header.Set("Idempotency-Key", "exact-csr")
			}
			for _, name := range []string{"__Host-tnl-browser", "__Host-tnl-share"} {
				r.AddCookie(&http.Cookie{Name: name, Value: strings.Repeat("A", 43)})
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized {
				t.Fatal("ambient cookie reached a protected operation", w.Code, w.Body.String())
			}
			assertPublisherCORSResponse(t, w)
		})
	}
}

type publisherCORSCertificateStore struct {
	managedCertificateStore
	t     *testing.T
	calls int
}

func (s *publisherCORSCertificateStore) CreateServiceCertificateIssuance(_ context.Context, service, run, token, directory, key string, number int64, csr []byte, _ time.Time) (controlstate.CertificateIssuance, error) {
	s.calls++
	if service != publisherCORSService || run != publisherCORSRun || number != 7 ||
		directory != "https://acme.example.test/directory" || key != "exact-csr" || !bytes.Equal(csr, []byte("captured-csr")) {
		s.t.Fatal("CORS changed certificate issuance's exact run, CSR, or idempotency")
	}
	if token != "exact-run-token" {
		return controlstate.CertificateIssuance{}, fmt.Errorf("private-authorization-details: %w", controlstate.ErrServiceAccess)
	}
	return controlstate.CertificateIssuance{ID: "issuance", ServiceID: service, ServiceRunID: run, ServiceRunNumber: uint64(number), State: controlstate.ACMEOrderPending}, nil
}

func TestPublisherCORSCertificateIssuanceRetainsRunAuthority(t *testing.T) {
	for _, test := range []struct {
		token         string
		status, calls int
	}{{"", 401, 0}, {"revoked-run-token", 404, 1}, {"exact-run-token", 201, 1}} {
		t.Run(test.token, func(t *testing.T) {
			store := &publisherCORSCertificateStore{t: t}
			h := testHandler(t, Config{CertificateIssuance: true, DNSAutomation: true, ACMEDirectoryURL: "https://acme.example.test/directory"}, nil, nil, nil, Stores{ServiceCertificates: store})
			body, err := json.Marshal(controlv1.CreateServiceCertificateIssuanceRequest{RunNumber: 7, Csr: []byte("captured-csr")})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, publisherCORSRunPath+"/certificate-issuances", bytes.NewReader(body))
			r.Header.Set("Origin", "https://arbitrary.example")
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Idempotency-Key", "exact-csr")
			if test.token != "" {
				r.Header.Set("Authorization", "Bearer "+test.token)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || store.calls != test.calls || strings.Contains(w.Body.String(), "private-authorization-details") ||
				strings.Contains(w.Body.String(), "captured-csr") || strings.Contains(w.Body.String(), "run-token") {
				t.Fatal("CORS changed certificate authorization or disclosed request details", w.Code, store.calls, w.Body.String())
			}
			assertPublisherCORSResponse(t, w)
		})
	}
}

type publisherCORSBrowserStore struct {
	ServiceHTTPStore
	t              *testing.T
	calls, refresh int
}

func (s *publisherCORSBrowserStore) RefreshServiceBrowserSession(_ context.Context, service, secret string, _ time.Time, _ func(context.Context, string) (controlstate.BrowserTokenRotation, error), _ ...string) (controlstate.BrowserAccessSession, error) {
	if service != publisherCORSService || secret != "explicit-body-secret" {
		s.t.Fatal("browser session refresh used ambient cookies or changed scope")
	}
	s.refresh++
	return controlstate.BrowserAccessSession{}, nil
}

func (s *publisherCORSBrowserStore) ServiceBrowserSession(_ context.Context, auth controlstate.ServiceHTTPRun, secret string, revoke bool, _ time.Time) (controlstate.VisitorPermission, error) {
	s.calls++
	if auth.Subject != (visitorscope.Scope{Kind: visitorscope.Service, ID: publisherCORSService}) ||
		auth.RunID != publisherCORSRun || auth.Number != 7 || secret != "explicit-body-secret" {
		s.t.Fatal("browser operation lost its explicit body secret or exact run")
	}
	if auth.Token != "exact-run-token" {
		return controlstate.VisitorPermission{}, controlstate.ErrServiceAccess
	}
	return controlstate.VisitorPermission{IdentityID: "verified-person", DisplayName: "Reviewer", VisitAllowed: true}, nil
}

func TestPublisherCORSBrowserSessionStillRequiresRunTokenAndBodySecret(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete} {
		for _, test := range []struct {
			token         string
			status, calls int
		}{{"", 401, 0}, {"revoked-run-token", 404, 1}, {"exact-run-token", 200, 1}} {
			t.Run(method+"/"+test.token, func(t *testing.T) {
				store := &publisherCORSBrowserStore{t: t}
				h := testHandler(t, Config{}, nil, nil, nil, Stores{ServiceHTTP: store})
				r := httptest.NewRequest(method, publisherCORSRunPath+"/browser/session", strings.NewReader(`{"run_number":"7","secret":"explicit-body-secret"}`))
				r.Header.Set("Origin", "https://arbitrary.example")
				r.Header.Set("Content-Type", "application/json")
				r.AddCookie(&http.Cookie{Name: "__Host-tnl-browser", Value: "different-ambient-secret"})
				if test.token != "" {
					r.Header.Set("Authorization", "Bearer "+test.token)
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				status := test.status
				if method == http.MethodDelete && status == 200 {
					status = 204
				}
				refresh := 0
				if method == http.MethodPost && test.calls != 0 {
					refresh = 1
				}
				if w.Code != status || store.calls != test.calls || store.refresh != refresh ||
					strings.Contains(w.Body.String(), "different-ambient-secret") || strings.Contains(w.Body.String(), "explicit-body-secret") {
					t.Fatal("CORS changed browser session authority", w.Code, store.calls, store.refresh, w.Body.String())
				}
				assertPublisherCORSResponse(t, w)
			})
		}
	}
}
