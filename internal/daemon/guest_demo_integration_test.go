package daemon

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	quicgo "github.com/quic-go/quic-go"
	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type integrationGuestPublisherControl struct {
	*publisheridentity.Native
	shareRedeems   chan error
	heartbeats     *atomic.Int64
	policyRevision *atomic.Int64
	beforeInstall  func(context.Context) error
}

func (c integrationGuestPublisherControl) MarkServiceCertificateInstalled(ctx context.Context, service, run string, number int64, issuance string, expires time.Time, token credentials.ServiceRunToken) error {
	if c.beforeInstall != nil {
		if err := c.beforeInstall(ctx); err != nil {
			return err
		}
	}
	return c.Native.MarkServiceCertificateInstalled(ctx, service, run, number, issuance, expires, token)
}

func (c integrationGuestPublisherControl) HeartbeatServiceRun(ctx context.Context, service, run string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	response, err := c.Native.HeartbeatServiceRun(ctx, service, run, token, health)
	if err == nil && c.heartbeats != nil {
		c.heartbeats.Add(1)
	}
	return response, err
}

func (c integrationGuestPublisherControl) ReadPublisherVisitorPolicy(ctx context.Context, body controlv1.PublisherVisitorPolicyRequest, token string) (controlv1.VisitorPolicyUpdate, error) {
	if c.policyRevision != nil {
		// after_revision reports the policy already installed before this fetch,
		// rather than a response the publisher has not applied yet.
		c.policyRevision.Store(body.AfterRevision)
	}
	return c.Native.ReadPublisherVisitorPolicy(ctx, body, token)
}

func (c integrationGuestPublisherControl) RedeemServiceShare(ctx context.Context, service, run string, body controlv1.RedeemServiceShareRequest, token credentials.ServiceRunToken) (controlv1.ShareRedemption, error) {
	redemption, err := c.Native.RedeemServiceShare(ctx, service, run, body, token)
	select {
	case c.shareRedeems <- err:
	default:
	}
	return redemption, err
}

func redeemIntegrationGuestShare(t *testing.T, client *http.Client, address string) *http.Response {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
		if err != nil {
			t.Fatal("construct guest share request")
		}
		response, err := client.Do(request)
		if err == nil {
			return response
		}
		var requestError *url.Error
		if errors.As(err, &requestError) {
			// the request URL contains the share secret; report only the cause.
			err = requestError.Err
		}
		if response != nil {
			response.Body.Close()
			t.Fatalf("guest share redemption after response: %v", err)
		}
		if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("guest share redemption: %v", err)
		}
		// a newly created share can reach ingress before publisher policy refresh.
		// retry only this reusable GET's pre-response EOF, never an HTTP result or
		// a one-use handoff. a permanent failure still fails within five seconds.
		timer := time.NewTimer(100 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			t.Fatalf("guest share redemption never reached a response: %v", err)
		case <-timer.C:
		}
	}
}

func TestIntegrationGuestDemoIssuesAndAuthorizesOneRestrictedService(t *testing.T) {
	databaseURL, _ := standaloneTestDatabase(t)
	state, err := controlstate.Open(t.Context(), databaseURL, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.EnsurePrimaryIngressPool(t.Context(), "192.0.2.10", "", time.Now()); err != nil {
		t.Fatal(err)
	}
	h, err := controlpublic.NewHandler(controlpublic.Config{
		ManagedDomain:    "tnl.wtf",
		GuestDemoEnabled: true, DNSAutomation: true,
	}, controlpublic.DatabaseStores(state), state, state.Readiness)
	if err != nil {
		t.Fatal(err)
	}
	createGuest := httptest.NewRequest(http.MethodPost, "/v1/guest-demo", nil)
	createGuest.RemoteAddr = "192.0.2.7:49152"
	guestResponse := httptest.NewRecorder()
	h.ServeHTTP(guestResponse, createGuest)
	if guestResponse.Code != http.StatusCreated {
		t.Fatalf("guest creation = %d, %s", guestResponse.Code, guestResponse.Body.String())
	}
	var guest controlv1.GuestDemoSession
	if err := json.Unmarshal(guestResponse.Body.Bytes(), &guest); err != nil {
		t.Fatal(err)
	}
	if guest.GuestId == "" || guest.AccessToken == "" || !guest.ExpiresAt.After(time.Now()) {
		t.Fatal("guest response is missing its trial, credential, or fixed expiry")
	}
	create := func(key, ip string, overrides map[string]any) *httptest.ResponseRecorder {
		t.Helper()
		body := map[string]any{"target": "http://127.0.0.1:3000"}
		for field, value := range overrides {
			body[field] = value
		}
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/guest-demo/services", bytes.NewReader(payload))
		request.RemoteAddr = net.JoinHostPort(ip, "49153")
		request.Header.Set("Authorization", "Bearer "+guest.AccessToken)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		return response
	}
	if changed := create("guest-demo", "192.0.2.8", nil); changed.Code != http.StatusForbidden || !strings.Contains(changed.Body.String(), `"guest_ip_changed"`) {
		t.Fatalf("changed guest visitor IP = %d, %s", changed.Code, changed.Body.String())
	}
	allowed := create("guest-demo", "192.0.2.7", nil)
	if allowed.Code != http.StatusCreated {
		t.Fatalf("guest demo URL = %d, %s", allowed.Code, allowed.Body.String())
	}
	var service controlv1.Service
	if err := json.Unmarshal(allowed.Body.Bytes(), &service); err != nil {
		t.Fatal(err)
	}
	if service.GuestId != guest.GuestId || service.TeamId != "" || !service.Ephemeral || service.Endpoint == nil || !service.Endpoint.Public || !strings.HasPrefix(service.Endpoint.Hostname, "demo-1.guest-") {
		t.Fatalf("guest allocation did not retain its real trial and assigned endpoint: %+v", service)
	}
	for _, name := range []string{"guest-relay-a", "guest-relay-b"} {
		if _, err := state.RegisterRelay(t.Context(), controlstate.RelayRegistration{
			RelayServiceID: name, RelayID: name + "-process", RelayRunID: name + "-run",
			ProtocolVersion: 1, RelayAddress: name + ".example.test:443",
			TLSServerName: name + ".example.test", InternalRelayAddress: name + ".internal:9445",
			ConnectionCapacity: 4, StreamCapacity: 4,
		}, time.Now(), time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enrollmentBody, err := json.Marshal(controlv1.EnrollGuestPublisherRequest{ServiceId: service.Id, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
	if err != nil {
		t.Fatal(err)
	}
	enrollRequest := httptest.NewRequest(http.MethodPost, "/v1/guest-demo/publisher", strings.NewReader(string(enrollmentBody)))
	enrollRequest.RemoteAddr = "192.0.2.7:49154"
	enrollRequest.Header.Set("Authorization", "Bearer "+guest.AccessToken)
	enrollRequest.Header.Set("Content-Type", "application/json")
	enrolled := httptest.NewRecorder()
	h.ServeHTTP(enrolled, enrollRequest)
	if enrolled.Code != http.StatusOK {
		t.Fatalf("guest identity enrollment = %d, %s", enrolled.Code, enrolled.Body.String())
	}
	var identity authorityv1.PublisherEnrollmentResult
	if err := json.Unmarshal(enrolled.Body.Bytes(), &identity); err != nil || identity.ServiceId == nil || *identity.ServiceId != service.Id || identity.GuestId != guest.GuestId || identity.TeamId != "" || identity.Kind != "service" {
		t.Fatalf("guest identity = %+v: %v", identity, err)
	}
	const audience = "https://control.example.test/v1/publisher-token"
	assertion, err := publisherproof.Sign(identity.ClientId, identity.KeyId, identity.GrantId, audience, private, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	access, err := state.ExchangePublisherAssertion(t.Context(), identity.ClientId, identity.GrantId, audience, assertion, "192.0.2.7/32", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	startRun := func(key string) *httptest.ResponseRecorder {
		t.Helper()
		body, err := json.Marshal(publisheridentity.ServiceDeclaration(service))
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/services/"+service.Id+"/runs", bytes.NewReader(body))
		request.RemoteAddr = "192.0.2.7:49155"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+access.Token)
		request.Header.Set("Idempotency-Key", key)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		return response
	}
	started := startRun("guest-first-run")
	if started.Code != http.StatusCreated {
		t.Fatalf("guest publish run = %d, %s", started.Code, started.Body.String())
	}
	var setup controlv1.ServiceRunPreparation
	if err := json.Unmarshal(started.Body.Bytes(), &setup); err != nil ||
		setup.ServiceId != service.Id || setup.GuestId != guest.GuestId || setup.TeamId != "" || setup.CertificatePlan == nil ||
		setup.CertificatePlan.Scope != service.Endpoint.Hostname || len(setup.CertificatePlan.Identifiers) != 1 ||
		setup.CertificatePlan.Identifiers[0] != service.Endpoint.Hostname {
		t.Fatalf("guest certificate plan = %+v, error = %v", setup.CertificatePlan, err)
	}
	if repeated := startRun("guest-second-run"); repeated.Code != http.StatusConflict {
		t.Fatalf("second active guest publish run = %d, %s", repeated.Code, repeated.Body.String())
	}
	for _, overrides := range []map[string]any{
		{"hostname": "app.example"}, {"allowed_ip_prefixes": []string{"0.0.0.0/0"}}, {"team_id": "fabricated-team"},
	} {
		denied := create("guest-override", "192.0.2.7", overrides)
		var problem controlv1.Problem
		if err := json.Unmarshal(denied.Body.Bytes(), &problem); err != nil || denied.Code != http.StatusBadRequest || problem.Code != controlv1.InvalidRequest {
			t.Fatalf("guest override = %d, %+v, %v", denied.Code, problem, err)
		}
	}
	if attempted := create("guest-second-service", "192.0.2.7", nil); attempted.Code != http.StatusConflict {
		t.Fatalf("second active demo service accepted: %d, %s", attempted.Code, attempted.Body.String())
	}
}

func TestIntegrationGuestDemoPublishesWithoutSignIn(t *testing.T) {
	testIntegrationGuestDemo(t, false)
}

func TestIntegrationGuestDemoDeadlineClosesConnectionsWithoutControl(t *testing.T) {
	testIntegrationGuestDemo(t, true)
}

func testIntegrationGuestDemo(t *testing.T, deadlineProof bool) {
	t.Helper()
	databaseURL, inspect := standaloneTestDatabase(t)
	owner := newRuntimeTopology(t)
	publicListener := serviceRuntimeListener(t, owner)
	publicFront := serviceRuntimeListener(t, owner)
	relayUDP := integrationPacketListener(t, owner)
	publicAddress, relayUDPAddress := publicFront.Addr().String(), relayUDP.LocalAddr().String()
	dns := newPrivateFixtureDNS(t, owner)
	pebble := startIntegrationPebble(t, integrationPort(t, publicAddress), dns.address, owner)
	cfg, listeners := standalonePublishConfig(t, databaseURL, publicListener, relayUDP, pebble.directoryURL, owner)
	// preserve the public https destination through the fixture's ephemeral
	// backend port, using the same trusted proxy boundary as split ingress.
	cfg.RequireProxyHeader, cfg.IngressTrustedProxies = true, []string{"127.0.0.1/32"}
	startSplitIngressProxy(t, owner, publicFront, publicListener.Addr().String())
	cfg.GuestDemoEnabled = true
	if deadlineProof {
		// keep process leases longer than guest authority, so their expiry cannot
		// conceal a missing guest connection fence.
		cfg.IngressLeaseDuration, cfg.RelayLeaseDuration = time.Minute, time.Minute
	}
	ca := newIntegrationTestCA(t)
	controlCertificate := ca.issueServer(t, cfg.ServerHostname(), owner)
	// this boundary tests guest issuance and visitor access, not infrastructure
	// DNS-01 polling. automatic relay issuance has its own real DNS/Pebble suite.
	relayCertificate := ca.issueServer(t, cfg.StandaloneRelayHostname(), owner)
	cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile = relayCertificate.certificateFile, relayCertificate.privateKeyFile
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	controlTLS, err := staticServerTLS(controlCertificate.certificateFile, controlCertificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	controlProxy := serviceRuntimeListener(t, owner)
	publicControl := controlProxy.Addr().String()
	serveIntegrationControlProxy(t, owner, controlProxy, cfg.ControlListen, controlTLS)
	var offline atomic.Bool
	var rejected atomic.Int64
	closing := make(chan struct{})
	noteClosing := sync.OnceFunc(func() { close(closing) })
	withOutage := func(client *http.Client) *http.Client {
		base := client.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if offline.Load() {
				rejected.Add(1)
				if request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/services/") && strings.Contains(request.URL.Path, "/runs/") {
					noteClosing()
				}
				return nil, clientcontrol.ErrUnavailable
			}
			return base.RoundTrip(request)
		})
		return client
	}
	process := startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		dns: dns, listeners: listeners,
		acmeHTTPClient:    pebble.httpClient,
		serviceHTTPClient: withOutage(&http.Client{Timeout: 2 * time.Second}),
		relayClientTLS:    &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}, owner: owner,
	})
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(integrationPublisherDiagnostics(inspect, pebble.logPath))
			var authority string
			err := inspect.QueryRow(`SELECT json_build_object('ready_at',active_ready_at,'ready_deadline',ready_deadline,
				'serving_until',serving_until,'used_ready_ns',used_ready_ns,'ended_at',ended_at,'end_reason',end_reason,
				'publisher_expires_at',(SELECT publisher_expires_at FROM control.service_runs ORDER BY created_at DESC LIMIT 1),
				'closed_at',(SELECT closed_at FROM control.service_runs ORDER BY created_at DESC LIMIT 1),
				'publisher_connections',(SELECT json_agg(json_build_object('slot',connection_slot,'state',state,
					'relay_id',relay_id,'relay_run_id',relay_run_id,'relay_lease_revision',relay_lease_revision))
					FROM control.service_connection_slots),
				'ingress_leases',(SELECT json_agg(json_build_object('id',ingress_id,'run_id',ingress_run_id,
					'expires_at',lease_expires_at,'lease_revision',ingress_lease_revision)) FROM control.ingress_leases),
				'relay_leases',(SELECT json_agg(json_build_object('id',relay_id,'run_id',relay_run_id,
					'expires_at',lease_expires_at,'lease_revision',relay_lease_revision)) FROM control.relay_leases))::text
				FROM control.guest_trials LIMIT 1`).Scan(&authority)
			t.Logf("guest authority at failure: %s; read error %v", authority, err)
			var visitors, decisions string
			err = inspect.QueryRow(`SELECT COALESCE(json_agg(json_build_object('run',service_run_id,
				'authenticated',identity_id IS NOT NULL OR workload_session_id IS NOT NULL,'promoted',promoted_at IS NOT NULL,
				'closed',closed_at IS NOT NULL,'valid_until',valid_until))::text,'[]')
				FROM control.public_service_visitors`).Scan(&visitors)
			t.Logf("guest ingress admissions: %s; read error %v", visitors, err)
			err = inspect.QueryRow(`SELECT COALESCE(json_agg(json_build_object('event',event_type,
				'outcome',outcome,'reason',reason))::text,'[]') FROM control.service_audit_events
				WHERE event_type IN ('connection.open','connection.close','http.decision')`).Scan(&decisions)
			t.Logf("guest visitor decisions: %s; read error %v", decisions, err)
		}
	})
	waitForProcessReady(t, process)
	controlHTTP, _ := newIntegrationHTTPSClient(t, ca.roots, publicControl, false, owner)
	withOutage(controlHTTP)
	serverURL := "https://" + cfg.ServerHostname()
	control, err := clientcontrol.New(serverURL, controlHTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := control.CreateGuestDemo(t.Context())
	if err != nil {
		t.Fatalf("guest credential without sign-in: %v", err)
	}
	if deadlineProof {
		if _, err := inspect.Exec(`UPDATE control.guest_trials SET used_ready_ns=$2 WHERE id=$1`, issued.GuestId, int64(controlstate.GuestReadyAllowance-8*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	clientState, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(owner.directory, "guest-state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	owner.cleanupResource(t, func() { _ = clientState.Close() })
	authenticated, err := auth.Authenticate(t.Context(), auth.Config{
		ServerEndpoint: serverURL, State: clientState, AccessToken: issued.AccessToken,
		HTTPClient: controlHTTP, Diagnostics: io.Discard,
	})
	if err != nil {
		t.Fatalf("guest client could not reach control without login: %v", err)
	}
	store, err := clientState.Server(t.Context(), serverURL)
	if err != nil {
		t.Fatal(err)
	}
	localDemo, err := demo.Start(nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := localDemo.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	localDemo.SetGuest()
	// exercise both directions beyond the former cumulative guest transfer cap.
	var targetRequests atomic.Int64
	transferTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		if r.URL.Path != "/transfer" {
			localDemo.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("guest transfer upload: %v", err)
			http.Error(w, "upload failed", http.StatusBadRequest)
			return
		}
		if _, err := w.Write(body); err != nil {
			t.Errorf("guest transfer target: %v", err)
		}
	}))
	t.Cleanup(transferTarget.Close)
	clientIP, err := authenticated.Control.ClientIP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddr(clientIP.Ip)
	if err != nil {
		t.Fatal(err)
	}
	relayTLS := &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}
	quic := redirectIntegrationConnector(relayUDPAddress, muxsession.QUICConnector{TLSConfig: relayTLS, Config: muxsession.QUICConfig{Config: &quicgo.Config{EnableDatagrams: true}}, Dialer: owner.quicTransport(t)})
	tcp := redirectIntegrationConnector(publicAddress, muxsession.WebSocketConnector{TLSConfig: relayTLS})
	if !address.IsLoopback() {
		t.Fatalf("guest fixture control transport source is not loopback: %s", address)
	}
	service, err := authenticated.Control.AllocateGuestDemoService(t.Context(), "guest-demo-service", controlv1.AllocateGuestDemoServiceRequest{Target: transferTarget.URL})
	if err != nil {
		t.Fatal(err)
	}
	if service.GuestId != issued.GuestId || service.TeamId != "" || service.Endpoint == nil || !service.Endpoint.Public || !strings.HasPrefix(service.Endpoint.Hostname, "demo-1.guest-") {
		t.Fatalf("guest allocation did not retain trial ownership: %+v", service)
	}
	hostname := service.Endpoint.Hostname
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuedPublisher, err := authenticated.Control.EnrollGuestPublisher(t.Context(), service.Id, public)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(serverURL, controlHTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := clientcontrol.New(serverURL, controlHTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	if issuedPublisher.ServiceId == nil || *issuedPublisher.ServiceId != service.Id || issuedPublisher.GuestId != issued.GuestId || issuedPublisher.TeamId != "" || issuedPublisher.Kind != "service" {
		t.Fatalf("guest publisher has different service or trial authority: %+v", issuedPublisher)
	}
	native, err := publisheridentity.NewNative(publisheridentity.NativeControl{Services: scoped}, authority, issuedPublisher, private)
	if err != nil {
		t.Fatal(err)
	}
	createShare := func() controlv1.ShareCreation {
		t.Helper()
		share, err := authenticated.Control.CreateServiceShare(t.Context(), "guest-reviewer-share", controlv1.CreateShareRequest{
			ServiceIds: []string{service.Id}, EntryServiceId: service.Id, ExpiresAt: issued.ExpiresAt,
		})
		if err != nil || share.Share.Scope != controlv1.ShareScopeGuest {
			t.Fatalf("guest trial share = %+v, %v", share, err)
		}
		return share
	}
	var share controlv1.ShareCreation
	shareRedeems := make(chan error, 1)
	var heartbeats, policyRevision atomic.Int64
	controlAdapter := integrationGuestPublisherControl{Native: native, shareRedeems: shareRedeems, heartbeats: &heartbeats, policyRevision: &policyRevision}
	preparing := make(chan controlv1.ServiceRunPreparation, 1)
	certificateWaiting, allowCertificate := make(chan struct{}, 1), make(chan struct{})
	allowSecondConnection := make(chan struct{})
	releaseCertificate := sync.OnceFunc(func() { close(allowCertificate) })
	releaseSecondConnection := sync.OnceFunc(func() { close(allowSecondConnection) })
	defer releaseCertificate()
	defer releaseSecondConnection()
	var targetHealthy atomic.Bool
	targetHealthy.Store(true)
	if deadlineProof {
		// hold the real certificate acknowledgment, not its result. two claimed
		// relay connections must not admit visitors without that certificate.
		share = createShare()
		controlAdapter.beforeInstall = func(ctx context.Context) error {
			select {
			case certificateWaiting <- struct{}{}:
			default:
			}
			select {
			case <-allowCertificate:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	visitor := newIntegrationVisitor(t, pebble.roots, publicAddress, owner)
	visitor.transport.ExpectContinueTimeout = 5 * time.Second
	ingressLease := readSplitIngressLease(t, inspect, standaloneIngressID)
	assertCurrentIngress := func() {
		t.Helper()
		current := readSplitIngressLease(t, inspect, standaloneIngressID)
		if current.runID != ingressLease.runID || current.revision != ingressLease.revision || !current.expiresAt.After(time.Now()) {
			t.Fatalf("guest visitor did not use a current ingress process: before=%+v current=%+v", ingressLease, current)
		}
	}
	assertUncharged := func() {
		t.Helper()
		var used int64
		if deadlineProof {
			used = int64(controlstate.GuestReadyAllowance - 8*time.Second)
		}
		var uncharged bool
		if err := inspect.QueryRow(`SELECT used_ready_ns=$2 AND first_ready_at IS NULL
			AND active_ready_at IS NULL AND ready_deadline IS NULL AND serving_until IS NULL
			FROM control.guest_trials WHERE id=$1`, issued.GuestId, used).Scan(&uncharged); err != nil || !uncharged {
			t.Fatalf("preparation spent ready authority: %t, %v", uncharged, err)
		}
	}
	assertUnavailable := func(stage string) {
		t.Helper()
		assertCurrentIngress()
		paths := []string{"/state"}
		if share.Link != "" {
			entry, err := url.Parse(share.Link)
			if err != nil || entry.Scheme != "https" || entry.Host != hostname {
				t.Fatal("guest share does not use its actual service endpoint")
			}
			paths = append(paths, entry.Path)
		}
		for _, path := range paths {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			var connected atomic.Bool
			ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{ConnectDone: func(_, _ string, err error) { connected.Store(err == nil) }})
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+path, nil)
			if err != nil {
				cancel()
				t.Fatal("construct preparation visitor request")
			}
			response, err := visitor.client.Do(request)
			cancel()
			if response != nil {
				response.Body.Close()
				t.Fatalf("%s carried an HTTP response: %d", stage, response.StatusCode)
			}
			if !connected.Load() || err == nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("%s did not promptly reject HTTPS on the live ingress listener", stage)
			}
		}
		if targetRequests.Load() != 0 {
			t.Fatalf("%s forwarded HTTP to the local service", stage)
		}
		select {
		case err := <-shareRedeems:
			t.Fatalf("%s reached publisher share redemption: %v", stage, err)
		default:
		}
		assertUncharged()
	}
	runConfig := publisherservice.RunConfig{
		Control: controlAdapter, Access: native.Access, ServiceID: service.Id, State: store,
		PublisherIdentityID: issuedPublisher.ClientId, PublisherGrantID: issuedPublisher.GrantId, PublisherKeyID: issuedPublisher.KeyId,
		Metadata: publisheridentity.ServiceMetadata(service), Target: strings.TrimPrefix(transferTarget.URL, "http://"),
		Demo: true, Feedback: true, ProjectService: "demo",
		RelayQUIC: quic, RelayWebSocket: tcp, HeartbeatInterval: 100 * time.Millisecond, DrainTime: time.Second,
		Prepared: func(run controlv1.ServiceRunPreparation) error { preparing <- run; return nil },
	}
	if deadlineProof {
		runConfig.Healthy = func(context.Context) bool { return targetHealthy.Load() }
	} else {
		// install the real certificate while only one connection can become ready.
		// initial public admission requires both assigned relay connections.
		runConfig.Connect = func(ctx context.Context, bound *publisherservice.Bound, slot uint8, options publisherservice.ConnectOptions) (publisherservice.SlotSession, error) {
			if slot == 1 {
				select {
				case <-allowSecondConnection:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			connection, err := bound.ConnectSlot(ctx, slot, options)
			if err != nil {
				return nil, err
			}
			return connection, nil
		}
	}
	handle := startOwnedIntegrationPublisher(t, owner, runConfig, func() string { return integrationPublisherDiagnostics(inspect, pebble.logPath) })
	var prepared controlv1.ServiceRunPreparation
	select {
	case prepared = <-preparing:
	case <-handle.done:
		t.Fatalf("publisher stopped before preparation: %v", handle.result())
	case <-time.After(30 * time.Second):
		t.Fatal("publisher did not reach preparation")
	}
	if deadlineProof {
		waitForReadyPublisherConnections(t, inspect, prepared.ServiceId, prepared.RunNumber, 2)
		select {
		case <-certificateWaiting:
		case <-handle.done:
			t.Fatalf("publisher stopped before certificate installation: %v", handle.result())
		case <-time.After(30 * time.Second):
			t.Fatal("publisher did not reach certificate installation")
		}
		var missingCertificate bool
		if err := inspect.QueryRow(`SELECT certificate_expires_at IS NULL AND healthy
			AND state='starting' AND ready_at IS NULL FROM control.service_runs WHERE id=$1`,
			prepared.ServiceRunId).Scan(&missingCertificate); err != nil || !missingCertificate {
			t.Fatalf("certificate gate did not retain the starting run: %t, %v", missingCertificate, err)
		}
		assertUnavailable("guest without an installed certificate")
		// retain the setup-budget proof after installing the certificate too.
		// commit unhealthy target status before allowing the real acknowledgment.
		targetHealthy.Store(false)
		waitForIntegrationCondition(t, 5*time.Second, func(ctx context.Context) (bool, error) {
			var unhealthy bool
			err := inspect.QueryRowContext(ctx, `SELECT NOT healthy FROM control.service_runs WHERE id=$1`, prepared.ServiceRunId).Scan(&unhealthy)
			return unhealthy, err
		})
		releaseCertificate()
		waitForIntegrationCondition(t, 10*time.Second, func(ctx context.Context) (bool, error) {
			var installed bool
			err := inspect.QueryRowContext(ctx, `SELECT run.certificate_expires_at>now() AND NOT run.healthy
				AND run.state='starting' AND guest.active_ready_at IS NULL
				FROM control.service_runs run JOIN control.guest_trials guest ON guest.active_service_run_id=run.id
				WHERE guest.id=$1 AND run.id=$2`, issued.GuestId, prepared.ServiceRunId).Scan(&installed)
			return installed, err
		})
		before := heartbeats.Load()
		for renewal := range 3 {
			waitForIntegrationCondition(t, 10*time.Second, func(context.Context) (bool, error) {
				return heartbeats.Load() >= before+int64(renewal)+1, nil
			})
			assertUnavailable("guest with an unhealthy target")
		}
		t.Logf("guest preparation rejected regular and share visitors across %d successful heartbeats", heartbeats.Load()-before)
		targetHealthy.Store(true)
	} else {
		waitForReadyPublisherConnections(t, inspect, prepared.ServiceId, prepared.RunNumber, 1)
		waitForIntegrationCondition(t, 30*time.Second, func(ctx context.Context) (bool, error) {
			var installed bool
			err := inspect.QueryRowContext(ctx, `SELECT certificate_expires_at>now() AND healthy
				AND state='starting' AND ready_at IS NULL FROM control.service_runs WHERE id=$1`,
				prepared.ServiceRunId).Scan(&installed)
			return installed, err
		})
		assertUnavailable("guest with only one ready relay connection")
		releaseSecondConnection()
	}
	ready := waitForPublisherReady(t, handle)
	if ready.ServiceId != service.Id || ready.ServiceRunId != prepared.ServiceRunId || ready.RunNumber != prepared.RunNumber || ready.Hostname != hostname || ready.GuestId != issued.GuestId {
		t.Fatalf("ready guest changed its allocated service or prepared run: %+v", ready)
	}
	if !deadlineProof {
		// retain the normal guest workflow: a newly ready demo creates its share.
		share = createShare()
	}
	var firstReadyAt time.Time
	if err := inspect.QueryRow(`SELECT first_ready_at FROM control.guest_trials WHERE id = $1`, issued.GuestId).Scan(&firstReadyAt); err != nil || firstReadyAt.IsZero() {
		t.Fatalf("guest trial did not record its first ready run: %v", err)
	}
	waitForReadyPublisherConnections(t, inspect, ready.ServiceId, ready.RunNumber, 2)
	assertCurrentIngress()
	localDemo.SetPublicURL(serviceHTTPAddress(ready))
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor.client.Jar = jar
	shareClient := *visitor.client
	shareClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	entry := redeemIntegrationGuestShare(t, &shareClient, share.Link)
	if entry.StatusCode != http.StatusSeeOther || strings.TrimSuffix(entry.Header.Get("Location"), "/") != serviceHTTPAddress(ready) {
		entry.Body.Close()
		select {
		case controlErr := <-shareRedeems:
			t.Fatalf("guest share redemption = %d, control error = %v", entry.StatusCode, controlErr)
		default:
			t.Fatalf("guest share redemption = %d, control not contacted", entry.StatusCode)
		}
	}
	_ = entry.Body.Close()
	redirected, err := visitor.client.Get(serviceHTTPAddress(ready) + "/")
	if err != nil {
		t.Fatalf("guest share redirect: %v", err)
	}
	redirected.Body.Close()
	if redirected.StatusCode != http.StatusOK {
		t.Fatalf("guest share redirect = %d", redirected.StatusCode)
	}
	if !deadlineProof {
		payload := bytes.Repeat([]byte("guest transfer\n"), (6<<20)/len("guest transfer\n")+1)
		transferRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serviceHTTPAddress(ready)+"/transfer", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		// wait for authorization before sending a body larger than ingress's pending
		// visitor budget; that budget remains independent of cumulative transfer.
		transferRequest.Header.Set("Expect", "100-continue")
		transferRequest.Header.Set("Content-Type", "application/octet-stream")
		transferred, err := visitor.client.Do(transferRequest)
		if err != nil {
			t.Fatal(err)
		}
		echo, readErr := io.ReadAll(transferred.Body)
		transferred.Body.Close()
		if readErr != nil || transferred.StatusCode != http.StatusOK || !bytes.Equal(echo, payload) {
			t.Fatalf("guest transfer = %d, %d bytes, %v", transferred.StatusCode, len(echo), readErr)
		}
		t.Logf("guest uploaded and downloaded %d bytes with no cumulative transfer cap", len(payload))
		transferredAt := time.Now()
		beforeRenewal := heartbeats.Load()
		waitForIntegrationCondition(t, 20*time.Second, func(ctx context.Context) (bool, error) {
			var renewed bool
			var revision int64
			err := inspect.QueryRowContext(ctx, `SELECT run.publisher_expires_at > $3 AND run.closed_at IS NULL, policy.revision
				FROM control.service_runs AS run JOIN control.visitor_policies AS policy
				ON policy.resource_id=run.service_id
				WHERE run.service_id=$1 AND run.run_number=$2`, ready.ServiceId, ready.RunNumber, transferredAt).Scan(&renewed, &revision)
			// observe a successful renewal after the transfer and the policy already
			// installed by this exact service run, not a newly fetched response.
			return heartbeats.Load() > beforeRenewal && renewed && policyRevision.Load() >= revision, err
		})
	}
	response, err := visitor.client.Get(serviceHTTPAddress(ready) + "/state")
	if err != nil {
		t.Fatalf("guest visitor: %v%s", err, integrationPublisherDiagnostics(inspect, pebble.logPath))
	}
	var state demo.State
	decodeErr := json.NewDecoder(response.Body).Decode(&state)
	response.Body.Close()
	if decodeErr != nil || response.StatusCode != http.StatusOK || state.PublicURL != serviceHTTPAddress(ready) || !state.Guest {
		t.Fatalf("guest demo through visitor TLS = %d, %+v, %v", response.StatusCode, state, decodeErr)
	}
	assertIntegrationPublicURLCertificate(t, response, hostname)
	assertCurrentIngress()
	if targetRequests.Load() == 0 {
		t.Fatal("ready guest share did not carry HTTP bytes to the local service")
	}
	ping, err := visitor.client.Post(serviceHTTPAddress(ready)+"/ping", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	var pong demo.State
	decodeErr = json.NewDecoder(ping.Body).Decode(&pong)
	ping.Body.Close()
	if decodeErr != nil || pong.RequestCount != 1 || pong.GeneratedAt == "" {
		t.Fatalf("guest pong = %d, %+v, %v", ping.StatusCode, pong, decodeErr)
	}
	if deadlineProof {
		var deadline, servingUntil time.Time
		if err := inspect.QueryRow(`SELECT ready_deadline,serving_until FROM control.guest_trials WHERE id=$1`, issued.GuestId).Scan(&deadline, &servingUntil); err != nil {
			t.Fatal(err)
		}
		held, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", publicAddress, &tls.Config{RootCAs: pebble.roots, ServerName: hostname, MinVersion: tls.VersionTLS13})
		if err != nil {
			t.Fatal(err)
		}
		defer held.Close()
		if err := held.SetDeadline(deadline.Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		origin, err := url.Parse(serviceHTTPAddress(ready))
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodGet, serviceHTTPAddress(ready)+"/state", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, cookie := range jar.Cookies(origin) {
			request.AddCookie(cookie)
		}
		if err := request.Write(held); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(held)
		response, err := http.ReadResponse(reader, request)
		if err != nil {
			t.Fatal(err)
		}
		_, readErr := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if readErr != nil || response.StatusCode != http.StatusOK || !time.Now().Before(servingUntil) {
			t.Fatalf("held connection before outage: status=%d error=%v", response.StatusCode, readErr)
		}
		offline.Store(true)
		defer offline.Store(false)
		if _, err := reader.ReadByte(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("idle guest connection survived its offline deadline: %v", err)
		}
		closedAt := time.Now()
		// include any heartbeat committed while the held connection was being
		// established. settlement retains this horizon even if cleanup has run.
		if err := inspect.QueryRow(`SELECT serving_until FROM control.guest_trials WHERE id=$1`, issued.GuestId).Scan(&servingUntil); err != nil {
			t.Fatal(err)
		}
		if closedAt.After(servingUntil.Add(time.Second)) || closedAt.After(deadline.Add(time.Second)) || rejected.Load() == 0 {
			t.Fatal("connection did not close locally during control outage")
		}
		t.Logf("guest connection closed at %s; issued horizon %s; ready deadline %s; rejected control requests %d", closedAt, servingUntil, deadline, rejected.Load())
		if err := waitForDoneWithin(closing, max(0, time.Until(deadline))+10*time.Second); err != nil {
			t.Fatal("publisher did not attempt to close its expired service run", err)
		}
		// a service owner publishes one run, not an automatic replacement. a stop
		// racing cleanup must still preserve the confirmed local lease failure.
		handle.cancel()
		offline.Store(false)
		if err := waitForDoneWithin(handle.done, 10*time.Second); err != nil {
			t.Fatal("publisher cleanup did not join", err)
		}
		if err := handle.result(); !errors.Is(err, publisherservice.ErrPrivateStream) {
			t.Fatalf("publisher expiry result = %v", err)
		}
		select {
		case run := <-preparing:
			t.Fatalf("expired service owner prepared a replacement run: %s", run.ServiceRunId)
		default:
		}
		var runs int
		var lastRun string
		if err := inspect.QueryRow(`SELECT count(*), max(id) FROM control.service_runs WHERE service_id=$1`, ready.ServiceId).Scan(&runs, &lastRun); err != nil || runs != 1 || lastRun != ready.ServiceRunId {
			t.Fatalf("expiry replaced the exact guest run: count=%d last=%s error=%v", runs, lastRun, err)
		}
		// acknowledge only the asserted terminal cutoff; the topology still joins
		// the owner and treats unrelated cleanup failures as failures.
		handle.mu.Lock()
		handle.err = nil
		handle.mu.Unlock()
		return
	}
	page, err := visitor.client.Get(serviceHTTPAddress(ready) + "/")
	if err != nil {
		t.Fatal(err)
	}
	html, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil || !strings.Contains(string(html), "/__tnl/feedback/toolbar.") || !strings.Contains(page.Header.Get("Content-Security-Policy"), "style-src 'unsafe-inline'") {
		t.Fatalf("demo toolbar or original styles missing: %v", err)
	}
	var previewID string
	if err = inspect.QueryRow(`SELECT id FROM control.previews WHERE demo_service_run_id=$1`, ready.ServiceRunId).Scan(&previewID); err != nil {
		t.Fatal(err)
	}
	report := func() *http.Response {
		t.Helper()
		request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, serviceHTTPAddress(ready)+"/__tnl/feedback", strings.NewReader(`{"schema_version":1,"text":"Demo suggestion","page_path":"/","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Idempotency-Key", "demo-report")
		response, err := visitor.client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}
	// guest publication and share visits need no sign-in; feedback authors do.
	unsigned := report()
	unsignedBody, readErr := io.ReadAll(unsigned.Body)
	unsigned.Body.Close()
	if readErr != nil || unsigned.StatusCode != http.StatusUnauthorized || string(unsignedBody) != "feedback requires sign-in; sign in and retry\n" {
		t.Fatalf("unsigned guest feedback = %d, %q, %v", unsigned.StatusCode, unsignedBody, readErr)
	}
	localFeedback, err := store.DemoFeedback(t.Context(), previewID, func(context.Context, string, string) (controlv1.FeedbackAuthorization, error) {
		t.Error("absent demo content requested authorization")
		return controlv1.FeedbackAuthorization{}, errors.New("unexpected authorization")
	})
	if err != nil {
		t.Fatal(err)
	}
	unsignedReports, err := localFeedback.List(t.Context(), "", "", "", "")
	if err != nil || len(unsignedReports.Threads) != 0 || unsignedReports.EventCursor != 0 {
		t.Fatalf("unsigned guest created local feedback: %+v, %v", unsignedReports, err)
	}
	privateState, err := controlstate.Open(t.Context(), databaseURL, testStorageKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer privateState.Close()
	// session issuance is fixture setup, not a login proof. the separate
	// reviewer's one-use handoff and report still cross the real publisher.
	now := time.Now()
	reviewer, err := privateState.CreateOIDCControlSession(t.Context(), cfg.ManagedDomain, controlstate.OIDCIdentity{
		Issuer: cfg.OIDCIssuer, Subject: "guest-feedback-reviewer", DisplayName: "Sam",
		AssertionDigest: sha256.Sum256([]byte("guest-feedback-reviewer")), AssertionExpiry: now.Add(time.Hour),
	}, cfg.AccessTokenLifetime, cfg.RefreshTokenLifetime, now)
	if err != nil || reviewer.Identity.Identity.Administrator {
		t.Fatalf("independent guest reviewer session: %v", err)
	}
	handoff, err := privateState.IssueBrowserHandoff(t.Context(), controlstate.BrowserLoginAttempt{
		Subject:       visitorscope.Scope{Kind: visitorscope.Service, ID: ready.ServiceId},
		ServiceRunIDs: []string{ready.ServiceRunId}, ReturnPath: "/",
	}, controlstate.BrowserAccessSession{
		IdentityID: reviewer.Identity.Identity.ID, AccessToken: reviewer.AccessToken.String(), RefreshToken: reviewer.RefreshToken.String(),
		AccessExpiresAt: reviewer.AccessExpiresAt, ExpiresAt: reviewer.RefreshExpiresAt,
	}, time.Now())
	if err != nil {
		t.Fatal("issue guest reviewer handoff", err)
	}
	signedIn, err := shareClient.Get(handoff.Origin + "/__tnl/team/handoff/" + handoff.Token)
	if err != nil {
		// the request URL contains a one-use secret.
		t.Fatal("redeem guest reviewer handoff")
	}
	signedIn.Body.Close()
	if signedIn.StatusCode != http.StatusSeeOther || strings.TrimSuffix(signedIn.Header.Get("Location"), "/") != serviceHTTPAddress(ready) {
		t.Fatalf("guest reviewer handoff = %d", signedIn.StatusCode)
	}
	reported := report()
	var thread controlv1.FeedbackThread
	decodeErr = json.NewDecoder(reported.Body).Decode(&thread)
	reported.Body.Close()
	if decodeErr != nil || reported.StatusCode != http.StatusOK || thread.SchemaVersion != 1 || thread.SourceAtReport.Complete || thread.SourceAtReport.HeadCommit != "" || len(thread.SourceAtReport.ChangedFiles) != 0 {
		t.Fatalf("guest feedback = %d, %+v, %v", reported.StatusCode, thread, decodeErr)
	}
	if thread.Report.Author == nil || !thread.Report.Author.Verified || thread.Report.Author.IdentityId == nil ||
		*thread.Report.Author.IdentityId != reviewer.Identity.Identity.ID || thread.Report.Author.DisplayName != "Sam" {
		t.Fatalf("guest feedback lost its independent verified author: %+v", thread.Report.Author)
	}
	stopIntegrationPublisher(t, handle)
	if err := authenticated.Control.DeleteGuestService(t.Context(), service.Id); err != nil && !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("remove guest demo URL after publication drains: %v", err)
	}
	localFeedback, err = store.DemoFeedback(t.Context(), previewID, func(context.Context, string, string) (controlv1.FeedbackAuthorization, error) {
		t.Error("deleted demo content requested authorization")
		return controlv1.FeedbackAuthorization{}, errors.New("unexpected authorization")
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localFeedback.GetFeedbackThread(t.Context(), thread.Id); !errors.Is(err, clientstate.ErrFeedbackNotFound) {
		t.Fatal("demo comments retained after stop", err)
	}
	var deleted bool
	if err := inspect.QueryRow(`SELECT deleted_at IS NOT NULL AND NOT enabled
		AND NOT EXISTS(SELECT 1 FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL)
		FROM control.services WHERE id = $1`, ready.ServiceId).Scan(&deleted); err != nil || !deleted {
		t.Fatalf("stopped demo retained a live service or run: %t, %v", deleted, err)
	}
	if _, err := privateState.ForgetGuestPrivateState(t.Context(), time.Now().Add(73*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var scrubbed bool
	if err := inspect.QueryRow(`SELECT source_ip_digest IS NULL AND credential_hash IS NULL
		FROM control.guest_trials WHERE id = $1`, issued.GuestId).Scan(&scrubbed); err != nil || !scrubbed {
		t.Fatalf("expired guest retained source binding: %t, %v", scrubbed, err)
	}
	var forgotten bool
	if err := inspect.QueryRow(`SELECT configuration_ciphertext IS NULL AND storage_key_id IS NULL
		FROM control.services WHERE id=$1`, service.Id).Scan(&forgotten); err != nil || !forgotten {
		t.Fatalf("expired guest retained its encrypted target declaration: %t, %v", forgotten, err)
	}
	var retiredProjection bool
	if err := inspect.QueryRow(`SELECT to_regclass('control.ingress_routing_table_events') IS NULL`).Scan(&retiredProjection); err != nil || !retiredProjection {
		t.Fatalf("guest source hashes can still be retained in the retired routing projection: %v", err)
	}
}
