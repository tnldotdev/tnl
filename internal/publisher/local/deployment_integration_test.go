package local

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/observability/inspection"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherprotocol "github.com/tnldotdev/tnl/internal/publisher/localapi/protocol"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationDeploymentApplicationUsesSharedRegistrationAndCleanup(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "deployment_app")
	if err := controlstate.Migrate(ctx, databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeSimple)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	team, actor := session.Identity.Memberships[0].TeamID, session.Identity.Identity.ID
	for i := range 2 {
		name := fmt.Sprintf("invocation-relay-%d", i)
		if _, err := d.RegisterRelay(ctx, controlstate.RelayRegistration{RelayServiceID: name, RelayID: name + "-1", RelayRunID: name + "-run",
			ProtocolVersion: 1, RelayAddress: name + ".example.test:443", TLSServerName: name + ".example.test",
			InternalRelayAddress: name + ".internal:9445", ConnectionCapacity: 10, StreamCapacity: 10}, now, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := d.ApplyProjectConfiguration(ctx, controlstate.ApplyProjectConfigurationRequest{
		TeamID: team, ActorID: actor, ProjectKey: "shop", SourceFingerprint: strings.Repeat("a", 64),
		Deployment: "production", ServiceDeclarations: map[string]string{"web": "http"},
		Configuration: controlstate.ProjectConfiguration{Settings: &controlstate.DeploymentSettings{}, Services: map[string]controlstate.ProjectServiceConfiguration{
			"web": {Target: "app", Public: new(true), HTTP: &config.HTTPService{
				Access: &config.Access{Mode: "anonymous"},
				Limits: &config.WorkLimits{Total: new(10)},
			}},
		}}, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	h, err := controlpublic.NewHandler(controlpublic.Config{ManagedURLMode: naming.ManagedURLModeSimple, DNSAutomation: true}, controlpublic.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	remote := httptest.NewTLSServer(h)
	t.Cleanup(remote.Close)
	if _, err = controlauthority.Register(h, controlauthority.Config{ControlURL: remote.URL}, d); err != nil {
		t.Fatal(err)
	}
	if err := d.PrepareVisitorSigningKeys(ctx, remote.URL, now); err != nil {
		t.Fatal(err)
	}
	original := http.DefaultTransport
	http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme+"://"+r.URL.Host == remote.URL {
			return remote.Client().Transport.RoundTrip(r)
		}
		return original.RoundTrip(r)
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	api, err := controlv1.NewClientWithResponses(remote.URL, controlv1.WithHTTPClient(remote.Client()))
	if err != nil {
		t.Fatal(err)
	}
	registration := controlv1.RegisterDeploymentCredentialRequest{
		Name: "application", PublicKey: base64.RawURLEncoding.EncodeToString(public),
		DeploymentIds: new([]string{applied.Deployments[0].ID}), ExpiresIn: 600,
	}
	registration.Permissions.Publish = &controlv1.DeploymentPublishSelection{
		Services: new(controlv1.DeploymentCredentialServiceSelection{"web"}), Temporary: new(controlv1.TemporaryPublicationRestricted),
	}
	response, err := api.RegisterDeploymentCredentialWithResponse(ctx, "shop", &controlv1.RegisterDeploymentCredentialParams{TeamId: team, IdempotencyKey: "registration"}, registration, func(_ context.Context, r *http.Request) error {
		r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
		return nil
	})
	if err != nil || response.JSON201 == nil {
		t.Fatal("register app publication", response, err)
	}
	credential := auth.DeploymentCredential{Version: 1, ControlURL: remote.URL, Team: "acme", Approval: *response.JSON201, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
	token, err := credential.Encode()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := testAppRuntimeWorkers(t, true)
	type publication struct {
		config      publisherservice.RunConfig
		saved       controlv1.Service
		policy      controlv1.VisitorPolicySnapshot
		preparation controlv1.ServiceRunPreparation
	}
	configured := make(chan publisherservice.RunConfig, 1)
	ready := make(chan publication, 2)
	a.AttachPublication = func(_ context.Context, _ publisherapp.Service, cfg *publisherservice.RunConfig) error {
		configured <- *cfg
		return nil
	}
	// use actual signed service preparation, start, policy and close operations.
	// only relay sockets/certificate readiness are simulated in this registration
	// boundary; the fixture-backed routine test exercises the real HTTP publisher.
	configure := a.workers.Configure
	a.workers.Configure = func(ctx context.Context, service publisherapp.Service) (publisherapp.Configuration, error) {
		configuration, err := configure(ctx, service)
		if err != nil {
			return configuration, err
		}
		cfg := <-configured
		configuration.Service.Run = func(ctx context.Context, _ *clientstate.Tunnel, observe func(uint64, bool) error, _ inspection.Observer) (result error) {
			access, err := cfg.Access(ctx)
			if err != nil {
				return err
			}
			saved, err := cfg.Control.GetPublisherService(ctx, cfg.ServiceID, access)
			if err != nil {
				return err
			}
			key, err := opaqueid.New(opaqueid.IdempotencyPrefix)
			if err != nil {
				return err
			}
			prepared, err := cfg.Control.PrepareServiceRun(ctx, cfg.ServiceID, key, access, publisheridentity.ServiceDeclaration(saved))
			if err != nil {
				return err
			}
			setup, err := cfg.Control.StartServiceRun(ctx, cfg.ServiceID, prepared.ServiceRunId, access, prepared.RunNumber)
			if err != nil {
				return err
			}
			defer func() {
				finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
				defer cancel()
				result = errors.Join(result, cfg.Control.CloseServiceRun(finish, cfg.ServiceID, setup.ServiceRunId, credentials.ServiceRunToken(setup.RunToken)))
			}()
			policy, err := d.ReadPublisherVisitorPolicy(ctx, visitorscope.Scope{Kind: visitorscope.Service, ID: saved.Id}, setup.ServiceRunId, setup.RunNumber, setup.RunToken, 0, time.Now())
			if err != nil {
				return err
			}
			for _, routable := range []bool{false, true} {
				if err := observe(uint64(prepared.RunNumber), routable); err != nil {
					return err
				}
			}
			ready <- publication{cfg, saved, policy.Policy, prepared}
			<-ctx.Done()
			return nil
		}
		return configuration, nil
	}
	listener := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "app still running") }))
	t.Cleanup(listener.Close)
	for _, named := range []bool{true, false} {
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
		if err != nil {
			t.Fatal(err)
		}
		selection := map[string]any{"project": "acme/shop", "name": "production", "credential": token}
		if named {
			selection["service"] = "web"
		}
		body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef", "pid": os.Getpid(), "target": listener.URL, "deployment": selection}
		var registered publisherprotocol.Registration
		if err = publisherprotocol.Call(ctx, endpoint, "POST", "/v1/publications/register", body, &registered); err != nil {
			t.Fatal(err)
		}
		var published publication
		select {
		case published = <-ready:
		case <-time.After(5 * time.Second):
			t.Fatal("worker did not become routable")
		}
		cfg, saved := published.config, published.saved
		if saved.Ephemeral == named || cfg.Target != strings.TrimPrefix(listener.URL, "http://") || cfg.ServiceID != saved.Id ||
			published.policy.Anonymous != named || named && (saved.HttpLimits == nil || saved.HttpLimits.Total == nil || *saved.HttpLimits.Total != 10) ||
			cfg.PublisherIdentityID != credential.Approval.ClientId || cfg.PublisherGrantID != credential.Approval.GrantId || cfg.PublisherKeyID != credential.Approval.KeyId ||
			published.preparation.PublisherIdentityId != credential.Approval.ClientId || published.preparation.PublisherGrantId != credential.Approval.GrantId || published.preparation.PublisherKeyId != credential.Approval.KeyId {
			t.Fatal("publication changed saved policy or invented a target")
		}
		if !named && (saved.ExpiresAt == nil || saved.ExpiresAt.After(credential.Approval.ExpiresAt)) {
			t.Fatal("temporary service extended its captured credential deadline")
		}
		encoded, err := json.Marshal(a.manager.Snapshot())
		if err != nil || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), credential.PrivateKey) {
			t.Fatal("credential entered snapshot", err)
		}
		if err = publisherprotocol.Call(ctx, endpoint, "POST", "/v1/unregister", registered, nil); err != nil {
			t.Fatal(err)
		}
		surviving, err := d.GetService(ctx, saved.Id, actor)
		if named && (err != nil || !surviving.Enabled) || !named && !errors.Is(err, controlstate.ErrServiceAccess) {
			t.Fatal("cleanup changed wrong service lifetime", err)
		}
		stillRunning, err := http.Get(listener.URL)
		if err != nil {
			t.Fatal("cleanup stopped app listener", err)
		}
		_ = stillRunning.Body.Close()
		if stillRunning.StatusCode != 200 {
			t.Fatal("app stopped serving")
		}
	}
	for _, discovery := range []struct {
		name      string
		available *bool
		failure   error
	}{
		{name: "available", available: new(true)},
		{name: "disabled", available: new(false)},
		{name: "omitted"},
		{name: "failed", failure: errors.New("discovery unavailable")},
	} {
		t.Run("discovery/"+discovery.name, func(t *testing.T) {
			transport := http.DefaultTransport
			otherRequests := 0
			http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
				if r.URL.Scheme+"://"+r.URL.Host == remote.URL {
					if r.URL.Path == "/v1/discovery" {
						if discovery.failure != nil {
							return nil, discovery.failure
						}
						body, err := json.Marshal(controlv1.ControlDiscovery{BrowserLoginAvailable: discovery.available})
						if err != nil {
							return nil, err
						}
						return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(body))), Request: r}, nil
					}
					otherRequests++
				}
				return transport.RoundTrip(r)
			})
			defer func() { http.DefaultTransport = transport }()
			for _, service := range []string{"web", ""} {
				invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
				if err != nil {
					t.Fatal(err)
				}
				body, err := json.Marshal(map[string]any{
					"invocation_id": invocation, "target": listener.URL,
					"deployment": map[string]string{"project": "acme/shop", "name": "production", "credential": token, "service": service},
				})
				if err != nil {
					t.Fatal(err)
				}
				var request publisherprotocol.Invocation
				if err := json.Unmarshal(body, &request); err != nil {
					t.Fatal(err)
				}
				prepared, err := a.prepareDeploymentInvocation(t.Context(), request)
				if discovery.failure != nil {
					if !errors.Is(err, discovery.failure) || otherRequests != 0 {
						t.Fatal("discovery failure reached publication authority or lost its cause", err, otherRequests)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if prepared.browserLoginAvailable != (discovery.available != nil && *discovery.available) {
					t.Fatal("publication ignored the advertised browser sign-in capability")
				}
				if err := prepared.cleanup(); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
	t.Run("failed exchange does not allocate during cleanup", func(t *testing.T) {
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef",
			"pid": os.Getpid(), "target": listener.URL,
			"deployment": map[string]string{"project": "acme/shop", "name": "production", "credential": token}}
		encoded, _ := json.Marshal(body)
		var request publisherprotocol.Invocation
		if err := json.Unmarshal(encoded, &request); err != nil {
			t.Fatal(err)
		}
		transport := http.DefaultTransport
		defer func() { http.DefaultTransport = transport }()
		exchanges, allocations := 0, 0
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Host == strings.TrimPrefix(remote.URL, "https://") && r.URL.Path == "/v1/publisher-token" {
				exchanges++
				if exchanges == 1 {
					cancel()
					return &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{"Content-Type": {"application/problem+json"}},
						Body: io.NopCloser(strings.NewReader(`{"code":"unavailable","status":503,"title":"retry"}`)), Request: r}, nil
				}
			}
			if r.Method == http.MethodPost && r.URL.Path == "/v1/projects/shop/deployments/production/services" {
				allocations++
			}
			return transport.RoundTrip(r)
		})
		if _, err := a.invocation(ctx, request); err == nil || exchanges != 1 || allocations != 0 {
			t.Fatal("pre-attempt failure caused cleanup to create an allocation", err, exchanges, allocations)
		}
	})
	t.Run("lost allocation reply", func(t *testing.T) {
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef",
			"pid": os.Getpid(), "target": listener.URL, "limits": map[string]any{"total": 7},
			"deployment": map[string]string{"project": "acme/shop", "name": "production", "credential": token}}
		encoded, _ := json.Marshal(body)
		var request publisherprotocol.Invocation
		if err := json.Unmarshal(encoded, &request); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		transport := http.DefaultTransport
		defer func() { http.DefaultTransport = transport }()
		var declarations []string
		var allocated controlv1.Service
		selections := 0
		http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/publisher/services/") {
				selections++
				return nil, errors.New("publication selection is unavailable during cleanup")
			}
			if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/shop/deployments/production/services" {
				return transport.RoundTrip(r)
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			declarations = append(declarations, string(data))
			r.Body = io.NopCloser(bytes.NewReader(data))
			response, err := transport.RoundTrip(r)
			if err == nil && len(declarations) == 1 {
				if err := json.NewDecoder(response.Body).Decode(&allocated); err != nil {
					return nil, err
				}
				_ = response.Body.Close()
				*request.Limits.Total = 99
				cancel()
				return nil, io.ErrUnexpectedEOF
			}
			return response, err
		})
		if _, err := a.invocation(ctx, request); !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatal("registered allocation lost its response error", err)
		}
		if allocated.Id == "" || len(declarations) != 2 || declarations[0] != declarations[1] || selections != 0 {
			t.Fatal("registered recovery changed its invocation, declaration, or fixed expiry", declarations)
		}
		if _, err := d.GetService(t.Context(), allocated.Id, actor); !errors.Is(err, controlstate.ErrServiceAccess) {
			t.Fatal("uncertain registered allocation was not deleted with its original approval", err)
		}
	})
	t.Run("lost allocation reply and cleanup retry without publication selection", func(t *testing.T) {
		invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		body := map[string]any{"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef",
			"pid": os.Getpid(), "target": listener.URL, "limits": map[string]any{"total": 7},
			"deployment": map[string]string{"project": "acme/shop", "name": "production", "credential": token}}
		encoded, _ := json.Marshal(body)
		var request publisherprotocol.Invocation
		if err := json.Unmarshal(encoded, &request); err != nil {
			t.Fatal(err)
		}
		options, err := invocationOptions(request)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		transport := http.DefaultTransport
		defer func() { http.DefaultTransport = transport }()
		var allocated controlv1.Service
		var declarations, deletions []string
		independent := errors.New("cleanup transport failed")
		selections, exchanges := 0, 0
		http.DefaultTransport = invocationTransport(func(r *http.Request) (*http.Response, error) {
			if r.URL.Path == "/v1/publisher-token" {
				exchanges++
			}
			if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/publisher/services/") {
				selections++
				return nil, errors.New("publication selection is unavailable")
			}
			if r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/v1/publisher/services/") {
				deletions = append(deletions, r.URL.Path)
				if len(deletions) == 1 {
					return nil, errors.Join(context.Canceled, independent)
				}
			}
			if r.Method != http.MethodPost || r.URL.Path != "/v1/projects/shop/deployments/production/services" {
				return transport.RoundTrip(r)
			}
			data, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			declarations = append(declarations, string(data))
			r.Body = io.NopCloser(bytes.NewReader(data))
			response, err := transport.RoundTrip(r)
			if err == nil && len(declarations) == 1 {
				if err := json.NewDecoder(response.Body).Decode(&allocated); err != nil {
					return nil, err
				}
				_ = response.Body.Close()
				cancel()
				return nil, io.ErrUnexpectedEOF
			}
			return response, err
		})
		prepared, operationErr := a.prepareDeploymentInvocation(ctx, request, options)
		if prepared.cleanup == nil || !errors.Is(operationErr, io.ErrUnexpectedEOF) {
			t.Fatal("uncertain allocation lost its cleanup owner", operationErr)
		}
		*request.Limits.Total = 99
		cleanupErr := prepared.cleanup()
		if combined := errors.Join(operationErr, cleanupErr); !errors.Is(combined, io.ErrUnexpectedEOF) ||
			!errors.Is(combined, independent) || errors.Is(cleanupErr, publisherapp.ErrCleanupPermanent) {
			t.Fatal("cleanup discarded a failure or retired transient ownership", combined)
		}
		if err := prepared.cleanup(); err != nil {
			t.Fatal("cleanup could not retry its exact observed allocation", err)
		}
		completedExchanges := exchanges
		for range 3 {
			if err := prepared.cleanup(); err != nil {
				t.Fatal("successful cleanup did not remain terminal", err)
			}
		}
		if allocated.Id == "" || len(declarations) != 2 || declarations[0] != declarations[1] || selections != 0 ||
			len(deletions) != 2 || deletions[0] != "/v1/publisher/services/"+allocated.Id || deletions[0] != deletions[1] || exchanges != completedExchanges {
			t.Fatal("cleanup reselected publication, changed authority, or replayed a completed invocation", declarations, deletions, selections)
		}
		if _, err := d.GetService(t.Context(), allocated.Id, actor); !errors.Is(err, controlstate.ErrServiceAccess) {
			t.Fatal("successful cleanup did not retire the original allocation", err)
		}
	})
	inspect, err := pgx.Connect(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(context.Background())
	for _, lost := range []string{"expired", "revoked"} {
		t.Run(lost, func(t *testing.T) {
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			request := registration
			request.Name = lost
			request.PublicKey = base64.RawURLEncoding.EncodeToString(public)
			approved, err := api.RegisterDeploymentCredentialWithResponse(ctx, "shop", &controlv1.RegisterDeploymentCredentialParams{
				TeamId: team, IdempotencyKey: lost,
			}, request, func(_ context.Context, r *http.Request) error {
				r.Header.Set("Authorization", "Bearer "+session.AccessToken.String())
				return nil
			})
			if err != nil || approved.JSON201 == nil {
				t.Fatal("register short-lived cleanup identity", err)
			}
			credential := auth.DeploymentCredential{Version: 1, ControlURL: remote.URL, Team: "acme", Approval: *approved.JSON201, PrivateKey: base64.RawURLEncoding.EncodeToString(private)}
			token, err := credential.Encode()
			if err != nil {
				t.Fatal(err)
			}
			invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
			if err != nil {
				t.Fatal(err)
			}
			endpoint, err := a.capabilities.Issue(publisherprotocol.CapabilityRequest{Scope: "invocation", InvocationId: &invocation})
			if err != nil {
				t.Fatal(err)
			}
			body := map[string]any{
				"version": 1, "invocation_id": invocation, "owner": "0123456789abcdef0123456789abcdef", "pid": os.Getpid(), "target": listener.URL,
				"deployment": map[string]string{"project": "acme/shop", "name": "production", "credential": token},
			}
			var registered publisherprotocol.Registration
			if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/publications/register", body, &registered); err != nil {
				t.Fatal(err)
			}
			var published publication
			select {
			case published = <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("temporary publication worker did not become routable")
			}
			if lost == "expired" {
				if _, err := inspect.Exec(ctx, `UPDATE control.publisher_grants SET created_at=$2::timestamptz - interval '1 second', expires_at=$2 WHERE id=$1`, credential.Approval.GrantId, now.Add(-time.Second)); err != nil {
					t.Fatal(err)
				}
			} else if err := d.RevokePublisherIdentity(ctx, team, credential.Approval.ClientId, actor, time.Now()); err != nil {
				t.Fatal(err)
			}
			var response *publisherprotocol.ResponseError
			if err := publisherprotocol.Call(ctx, endpoint, "POST", "/v1/unregister", registered, nil); !errors.As(err, &response) || response.Code != "runtime.publication_cleanup_failed" {
				t.Fatal("permanent deletion denial was not reported", err)
			}
			if _, found := a.manager.ServiceForRegistration(registered.RegistrationID); found {
				t.Fatal("captured expired or revoked authority retained local ownership")
			}
			if err := a.manager.RetirementError(); !errors.Is(err, publisherapp.ErrCleanupPermanent) || !errors.Is(err, clientauthority.ErrUnauthenticated) {
				t.Fatal("owner retirement lost its authorization failure", err)
			}
			if _, err := d.GetService(ctx, published.saved.Id, actor); err != nil {
				t.Fatal("local retirement silently bypassed failed remote deletion", err)
			}
		})
	}
}
