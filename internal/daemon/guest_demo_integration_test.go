package daemon

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlpublic "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type integrationGuestPublisherControl struct {
	*clientcontrol.Client
	native       *publisheridentity.Native
	assigned     controlv1.PublicURL
	shareRedeems chan error
	markReady    func(context.Context, string, uint64, credentials.PublishRunToken) error
	heartbeats   *atomic.Int64
}

func (c integrationGuestPublisherControl) PublisherIdentityID() string {
	return c.native.PublisherIdentityID()
}

func (c integrationGuestPublisherControl) CreatePublicURL(_ context.Context, body controlv1.CreatePublicURLRequest, _ string) (controlv1.PublicURL, error) {
	if body.Purpose != controlv1.Demo || body.CanonicalHostname != c.assigned.CanonicalHostname || body.Target != c.assigned.Target || body.Ephemeral == nil || !*body.Ephemeral {
		return controlv1.PublicURL{}, publisheridentity.ErrScope
	}
	return c.assigned, nil
}

func (c integrationGuestPublisherControl) CreatePublishRun(ctx context.Context, id, retry string) (controlv1.PublishRunSetup, error) {
	return c.native.CreatePublishRun(ctx, id, retry)
}

func (c integrationGuestPublisherControl) MarkPublishRunReady(ctx context.Context, run string, number uint64, token credentials.PublishRunToken) error {
	if c.markReady != nil {
		return c.markReady(ctx, run, number, token)
	}
	return c.Client.MarkPublishRunReady(ctx, run, number, token)
}

func (c integrationGuestPublisherControl) HeartbeatPublishRun(ctx context.Context, run string, number uint64, token credentials.PublishRunToken) (controlv1.PublishRunHeartbeat, error) {
	response, err := c.Client.HeartbeatPublishRun(ctx, run, number, token)
	if err == nil && c.heartbeats != nil {
		c.heartbeats.Add(1)
	}
	return response, err
}

func (c integrationGuestPublisherControl) RedeemPublishRunShare(ctx context.Context, runID string, body controlv1.RedeemShareRequest, token credentials.PublishRunToken) (controlv1.ShareRedemption, error) {
	redemption, err := c.Client.RedeemPublishRunShare(ctx, runID, body, token)
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

func TestIntegrationGuestDemoIssuesAndAuthorizesOneRestrictedPublicURL(t *testing.T) {
	databaseURL, _ := standaloneTestDatabase(t)
	state, err := controlstate.Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
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
	if !strings.HasPrefix(guest.Namespace, "guest-") {
		t.Fatalf("guest metadata = %+v", guest)
	}
	create := func(hostname string, ip string) *httptest.ResponseRecorder {
		t.Helper()
		body := controlv1.CreatePublicURLRequest{
			TeamId: guest.TeamId, DomainId: guest.DomainId, MembershipId: &guest.MembershipId,
			CanonicalHostname: hostname, Target: "http://127.0.0.1:3000",
			PublicUrlScope: controlv1.Member, Purpose: controlv1.Demo, Ephemeral: new(bool),
		}
		*body.Ephemeral = true
		body.AllowedIpPrefixes = &[]string{ip}
		payload, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/public-urls", strings.NewReader(string(payload)))
		request.Header.Set("Authorization", "Bearer "+guest.AccessToken)
		request.Header.Set("Idempotency-Key", hostname)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		return response
	}
	allocate := httptest.NewRequest(http.MethodPost, "/v1/guest-demo/number", nil)
	allocate.RemoteAddr = "192.0.2.7:49153"
	allocate.Header.Set("Authorization", "Bearer "+guest.AccessToken)
	allocated := httptest.NewRecorder()
	h.ServeHTTP(allocated, allocate)
	if allocated.Code != http.StatusOK || !strings.Contains(allocated.Body.String(), `"number":1`) {
		t.Fatalf("first demo number = %d, %s", allocated.Code, allocated.Body.String())
	}
	hostname := "demo-1." + guest.Namespace
	if changed := create(hostname, "192.0.2.8/32"); changed.Code != http.StatusForbidden || !strings.Contains(changed.Body.String(), `"guest_ip_changed"`) {
		t.Fatalf("changed guest visitor IP = %d, %s", changed.Code, changed.Body.String())
	}
	allowed := create(hostname, "192.0.2.7/32")
	if allowed.Code != http.StatusCreated {
		t.Fatalf("guest demo URL = %d, %s", allowed.Code, allowed.Body.String())
	}
	var publicURL controlv1.PublicURL
	if err := json.Unmarshal(allowed.Body.Bytes(), &publicURL); err != nil {
		t.Fatal(err)
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
	enrollmentBody, err := json.Marshal(controlv1.EnrollGuestPublisherRequest{PublicUrlId: publicURL.Id, PublicKey: base64.RawURLEncoding.EncodeToString(public)})
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
	var identity controlv1.GuestPublisherIdentity
	if err := json.Unmarshal(enrolled.Body.Bytes(), &identity); err != nil || identity.PublicUrlId != publicURL.Id {
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
		request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/"+publicURL.Id+"/publish-runs", strings.NewReader("{}"))
		request.RemoteAddr = "192.0.2.7:49155"
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+access.Token)
		request.Header.Set("Idempotency-Key", key)
		proof, err := publisherproof.SignRun(private, publicURL.Id, key)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("Publisher-Run-Proof", proof)
		response := httptest.NewRecorder()
		h.ServeHTTP(response, request)
		return response
	}
	started := startRun("guest-first-run")
	if started.Code != http.StatusCreated {
		t.Fatalf("guest publish run = %d, %s", started.Code, started.Body.String())
	}
	var setup controlv1.PublishRunSetup
	if err := json.Unmarshal(started.Body.Bytes(), &setup); err != nil ||
		setup.CertificatePlan.Scope != publicURL.CanonicalHostname || len(setup.CertificatePlan.Identifiers) != 1 ||
		setup.CertificatePlan.Identifiers[0] != publicURL.CanonicalHostname {
		t.Fatalf("guest certificate plan = %+v, error = %v", setup.CertificatePlan, err)
	}
	if repeated := startRun("guest-second-run"); repeated.Code != http.StatusConflict {
		t.Fatalf("second active guest publish run = %d, %s", repeated.Code, repeated.Body.String())
	}
	for _, denied := range []*httptest.ResponseRecorder{
		create("app-1."+guest.Namespace, "192.0.2.7/32"),
		create("demo-2."+guest.Namespace, "0.0.0.0/0"),
	} {
		var problem controlv1.Problem
		if err := json.Unmarshal(denied.Body.Bytes(), &problem); err != nil || denied.Code != http.StatusForbidden || problem.Code != controlv1.GuestDemoOnly {
			t.Fatalf("guest override = %d, %+v, %v", denied.Code, problem, err)
		}
	}
	if attempted := create("demo-2."+guest.Namespace, "192.0.2.7/32"); attempted.Code != http.StatusForbidden {
		t.Fatalf("unallocated demo number accepted: %d, %s", attempted.Code, attempted.Body.String())
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
	publicListener := serviceRuntimeListener(t)
	relayUDP := integrationPacketListener(t)
	publicAddress, relayUDPAddress := publicListener.Addr().String(), relayUDP.LocalAddr().String()
	dns := newPrivateFixtureDNS(t)
	pebble := startIntegrationPebble(t, integrationPort(t, publicAddress), dns.address)
	cfg, listeners := standalonePublishConfig(t, databaseURL, publicListener, relayUDP, pebble.directoryURL)
	cfg.GuestDemoEnabled = true
	if deadlineProof {
		// keep process leases longer than guest authority, so their expiry cannot
		// conceal a missing guest connection fence.
		cfg.IngressLeaseDuration, cfg.RelayLeaseDuration = time.Minute, time.Minute
	}
	owner := newRuntimeTopology(t)
	ca := newIntegrationTestCA(t)
	controlCertificate := ca.issueServer(t, cfg.ServerHostname())
	// this boundary tests guest issuance and visitor access, not infrastructure
	// DNS-01 polling. automatic relay issuance has its own real DNS/Pebble suite.
	relayCertificate := ca.issueServer(t, cfg.StandaloneRelayHostname())
	cfg.RelayTLSCertificateFile, cfg.RelayTLSPrivateKeyFile = relayCertificate.certificateFile, relayCertificate.privateKeyFile
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	controlTLS, err := staticServerTLS(controlCertificate.certificateFile, controlCertificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	publicControl := unusedTCPAddress(t)
	startIntegrationControlProxy(t, owner, publicControl, cfg.ControlListen, controlTLS)
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
				if request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/publish-runs/") {
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
				'publisher_expires_at',(SELECT publisher_expires_at FROM control.publish_runs ORDER BY created_at DESC LIMIT 1),
				'closed_at',(SELECT closed_at FROM control.publish_runs ORDER BY created_at DESC LIMIT 1))::text FROM control.guest_trials LIMIT 1`).Scan(&authority)
			t.Logf("guest authority at failure: %s; read error %v", authority, err)
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
	clientstate, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer clientstate.Close()
	authenticated, err := auth.Authenticate(t.Context(), auth.Config{
		ServerEndpoint: serverURL, State: clientstate, AccessToken: issued.AccessToken,
		HTTPClient: controlHTTP, Diagnostics: io.Discard,
	})
	if err != nil {
		t.Fatalf("guest client could not reach control without login: %v", err)
	}
	allocated, err := authenticated.Control.AllocateGuestDemoNumber(t.Context())
	if err != nil || allocated.Number != 1 {
		t.Fatalf("guest demo number = %+v, %v", allocated, err)
	}
	store, err := clientstate.Server(t.Context(), serverURL)
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
	clientIP, err := authenticated.Control.ClientIP(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	address, err := netip.ParseAddr(clientIP.Ip)
	if err != nil {
		t.Fatal(err)
	}
	relayTLS := &tls.Config{RootCAs: ca.roots, MinVersion: tls.VersionTLS13}
	quic := redirectIntegrationConnector(relayUDPAddress, muxsession.QUICConnector{TLSConfig: relayTLS})
	tcp := redirectIntegrationConnector(publicAddress, muxsession.TLSYamuxConnector{TLSConfig: relayTLS})
	hostname := "demo-1." + issued.Namespace
	prefixes := []string{netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()).String()}
	ephemeral, protocol := true, controlv1.Http
	publicURL, err := authenticated.Control.CreatePublicURL(t.Context(), controlv1.CreatePublicURLRequest{
		TeamId: issued.TeamId, MembershipId: &issued.MembershipId, DomainId: issued.DomainId,
		CanonicalHostname: hostname, Purpose: controlv1.Demo, PublicUrlScope: controlv1.Member,
		ServiceProtocol: &protocol, Target: localDemo.Target(), AllowedIpPrefixes: &prefixes, Ephemeral: &ephemeral,
	}, "guest-demo-url")
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issuedPublisher, err := authenticated.Control.EnrollGuestPublisher(t.Context(), publicURL.Id, public)
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
	identity := authorityv1.PublisherEnrollmentResult{ClientId: issuedPublisher.ClientId, KeyId: issuedPublisher.KeyId, GrantId: issuedPublisher.GrantId, TeamId: issuedPublisher.TeamId, PublicUrlId: &publicURL.Id, Kind: authorityv1.SavedPublicUrl}
	native, err := publisheridentity.NewNative(scoped, authority, identity, private)
	if err != nil {
		t.Fatal(err)
	}
	if err := native.SelectPublicURL(publicURL); err != nil {
		t.Fatal(err)
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(secret)
	createShare := func() controlv1.Share {
		t.Helper()
		share, err := authenticated.Control.CreateURLShare(t.Context(), "guest-reviewer-share", controlv1.CreateShareRequest{
			PublicUrlIds: []string{publicURL.Id}, ExpiresAt: issued.ExpiresAt, SecretFingerprint: hex.EncodeToString(fingerprint[:]),
		})
		if err != nil || share.Scope != controlv1.ShareScopeGuest {
			t.Fatalf("guest trial share = %+v, %v", share, err)
		}
		return share
	}
	var share controlv1.Share
	shareRedeems := make(chan error, 1)
	var heartbeats atomic.Int64
	controlAdapter := integrationGuestPublisherControl{Client: authenticated.Control, native: native, assigned: publicURL, shareRedeems: shareRedeems, heartbeats: &heartbeats}
	preparing, allowReady := make(chan error, 1), make(chan struct{})
	if deadlineProof {
		// only the short-budget fixture pre-creates its share. withhold the final
		// ready mutation while the real publisher renews and ingress prepares.
		share = createShare()
		var first sync.Once
		controlAdapter.markReady = func(ctx context.Context, run string, number uint64, token credentials.PublishRunToken) error {
			select {
			case <-allowReady:
				return authenticated.Control.MarkPublishRunReady(ctx, run, number, token)
			default:
				first.Do(func() { preparing <- authenticated.Control.MarkPublishRunReady(ctx, run, number, token) })
				return clientcontrol.ErrUnavailable
			}
		}
	}
	visitor := newIntegrationVisitor(t, pebble.roots, publicAddress, owner)
	handle := startOwnedIntegrationPublisher(t, owner, publisher.Config{
		Control: controlAdapter, TeamID: issued.TeamId, MembershipID: issued.MembershipId,
		ControlURL: serverURL,
		DomainID:   issued.DomainId, Hostname: hostname, PublicURLScope: controlv1.Member, Purpose: controlv1.Demo,
		PolicyRevision: 1, Target: localDemo.Target(),
		AllowedIPPrefixes: prefixes,
		Ephemeral:         true, State: store,
		Demo: true, Feedback: true, Service: "demo",
		Logf:          t.Logf,
		QUICConnector: quic, TCPConnector: tcp,
	}, func() string { return integrationPublisherDiagnostics(inspect, pebble.logPath) })
	if deadlineProof {
		select {
		case err := <-preparing:
			if !errors.Is(err, clientcontrol.ErrUnavailable) && !errors.Is(err, clientcontrol.ErrStatusConflict) {
				t.Fatalf("first preparation mutation = %v", err)
			}
		case <-handle.done:
			t.Fatalf("publisher stopped before preparation: %v", handle.result())
		case <-time.After(30 * time.Second):
			t.Fatal("publisher did not reach preparation")
		}
		waitForIntegrationCondition(t, 5*time.Second, func(ctx context.Context) (bool, error) {
			var prepared bool
			err := inspect.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM control.ingress_public_run_observations AS installed
				JOIN control.guest_trials AS guest ON guest.active_publish_run_id=installed.publish_run_id
				WHERE guest.id=$1 AND installed.valid_until>now() AND guest.active_ready_at IS NULL)`, issued.GuestId).Scan(&prepared)
			return prepared, err
		})
		before := heartbeats.Load()
		for renewal := range 3 {
			waitForIntegrationCondition(t, 10*time.Second, func(context.Context) (bool, error) {
				return heartbeats.Load() >= before+int64(renewal), nil
			})
			for _, path := range []string{"/state", "/__tnl/share/" + share.Id + "." + base64.RawURLEncoding.EncodeToString(secret)} {
				ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+hostname+path, nil)
				if err != nil {
					cancel()
					t.Fatal("construct preparation visitor request")
				}
				response, err := visitor.client.Do(request)
				cancel()
				if response != nil {
					response.Body.Close()
					t.Fatalf("starting guest carried an HTTP response: %d", response.StatusCode)
				}
				if err == nil || errors.Is(err, context.DeadlineExceeded) {
					t.Fatal("starting guest did not reject the visitor connection promptly")
				}
			}
			var uncharged bool
			if err := inspect.QueryRow(`SELECT used_ready_ns=$2 AND active_ready_at IS NULL AND ready_deadline IS NULL AND serving_until IS NULL
				FROM control.guest_trials WHERE id=$1`, issued.GuestId, int64(controlstate.GuestReadyAllowance-8*time.Second)).Scan(&uncharged); err != nil || !uncharged {
				t.Fatalf("preparation spent ready authority: %t, %v", uncharged, err)
			}
		}
		select {
		case err := <-shareRedeems:
			t.Fatalf("starting guest reached publisher share redemption: %v", err)
		default:
		}
		t.Logf("guest preparation rejected regular and share visitors across %d successful heartbeats", heartbeats.Load()-before)
		close(allowReady)
	}
	ready := waitForPublisherReady(t, handle)
	if !deadlineProof {
		// retain the normal guest workflow: a newly ready demo creates its share.
		share = createShare()
	}
	var firstReadyAt time.Time
	if err := inspect.QueryRow(`SELECT first_ready_at FROM control.guest_trials WHERE id = $1`, issued.GuestId).Scan(&firstReadyAt); err != nil || firstReadyAt.IsZero() {
		t.Fatalf("guest trial did not record its first ready run: %v", err)
	}
	waitForReadyPublisherConnections(t, inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, inspect, 1)
	localDemo.SetPublicURL(ready.PublicURL)
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor.client.Jar = jar
	shareClient := *visitor.client
	shareClient.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	entry := redeemIntegrationGuestShare(t, &shareClient, ready.PublicURL+"/__tnl/share/"+share.Id+"."+base64.RawURLEncoding.EncodeToString(secret))
	if entry.StatusCode != http.StatusSeeOther || entry.Header.Get("Location") != ready.PublicURL+"/" {
		entry.Body.Close()
		select {
		case controlErr := <-shareRedeems:
			t.Fatalf("guest share redemption = %d, control error = %v", entry.StatusCode, controlErr)
		default:
			t.Fatalf("guest share redemption = %d, control not contacted", entry.StatusCode)
		}
	}
	_ = entry.Body.Close()
	redirected, err := visitor.client.Get(ready.PublicURL + "/")
	if err != nil {
		t.Fatalf("guest share redirect: %v", err)
	}
	redirected.Body.Close()
	if redirected.StatusCode != http.StatusOK {
		t.Fatalf("guest share redirect = %d", redirected.StatusCode)
	}
	response, err := visitor.client.Get(ready.PublicURL + "/state")
	if err != nil {
		t.Fatalf("guest visitor: %v%s", err, integrationPublisherDiagnostics(inspect, pebble.logPath))
	}
	var state demo.State
	decodeErr := json.NewDecoder(response.Body).Decode(&state)
	response.Body.Close()
	if decodeErr != nil || response.StatusCode != http.StatusOK || state.PublicURL != ready.PublicURL || !state.Guest {
		t.Fatalf("guest demo through visitor TLS = %d, %+v, %v", response.StatusCode, state, decodeErr)
	}
	ping, err := visitor.client.Post(ready.PublicURL+"/ping", "", nil)
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
		origin, err := url.Parse(ready.PublicURL)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest(http.MethodGet, ready.PublicURL+"/state", nil)
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
			t.Fatal("publisher did not stop at its own confirmed deadline", err)
		}
		// local expiry has already closed the transport and begun cleanup. stop
		// Run's replacement loop so its result remains the original lease failure.
		handle.cancel()
		offline.Store(false)
		if err := waitForDoneWithin(handle.done, 10*time.Second); err != nil {
			t.Fatal("publisher cleanup did not join", err)
		}
		if err := handle.result(); !errors.Is(err, clientcontrol.ErrStatusConflict) {
			t.Fatalf("publisher expiry result = %v", err)
		}
		// acknowledge only the asserted terminal cutoff; the topology still joins
		// the owner and treats unrelated cleanup failures as failures.
		handle.mu.Lock()
		handle.err = nil
		handle.mu.Unlock()
		return
	}
	page, err := visitor.client.Get(ready.PublicURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	html, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil || !strings.Contains(string(html), "/__tnl/feedback/toolbar.") || !strings.Contains(page.Header.Get("Content-Security-Policy"), "style-src 'unsafe-inline'") {
		t.Fatalf("demo toolbar or original styles missing: %v", err)
	}
	reportRequest, err := http.NewRequest(http.MethodPost, ready.PublicURL+"/__tnl/feedback", strings.NewReader(`{"schema_version":1,"text":"Demo suggestion","display_name":"Sam","page_path":"/","evidence":{"schema_version":1,"actions":[],"failed_requests":[]}}`))
	if err != nil {
		t.Fatal(err)
	}
	reportRequest.Header.Set("Content-Type", "application/json")
	reportRequest.Header.Set("Idempotency-Key", "demo-report")
	reported, err := visitor.client.Do(reportRequest)
	if err != nil {
		t.Fatal(err)
	}
	var thread controlv1.FeedbackThread
	decodeErr = json.NewDecoder(reported.Body).Decode(&thread)
	reported.Body.Close()
	if decodeErr != nil || reported.StatusCode != http.StatusOK || thread.SchemaVersion != 1 || thread.SourceAtReport.Complete || thread.SourceAtReport.HeadCommit != "" || len(thread.SourceAtReport.ChangedFiles) != 0 {
		t.Fatalf("guest feedback = %d, %+v, %v", reported.StatusCode, thread, decodeErr)
	}
	stopIntegrationPublisher(t, handle)
	if err := authenticated.Control.DeletePublicURL(t.Context(), publicURL.Id); err != nil && !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatalf("remove guest demo URL after publication drains: %v", err)
	}
	var demoComments int
	if err := inspect.QueryRow(`SELECT count(*) FROM control.feedback_threads WHERE public_url_id = $1`, ready.PublicURLID).Scan(&demoComments); err != nil || demoComments != 0 {
		t.Fatalf("demo comments retained after stop: %d, %v", demoComments, err)
	}
	var deleted bool
	if err := inspect.QueryRow(`SELECT lifecycle_state = 'deleted' AND request_digest_ciphertext IS NULL
		AND request_digest_storage_key_id IS NULL AND allowed_ip_hashes IS NULL
		FROM control.public_urls WHERE id = $1`, ready.PublicURLID).Scan(&deleted); err != nil || !deleted {
		t.Fatalf("stopped demo retained saved policy or digest: %t, %v", deleted, err)
	}
	privateState, err := controlstate.Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer privateState.Close()
	if _, err := privateState.ForgetGuestPrivateState(t.Context(), time.Now().Add(73*time.Hour)); err != nil {
		t.Fatal(err)
	}
	var scrubbed bool
	if err := inspect.QueryRow(`SELECT source_ip_digest IS NULL AND credential_hash IS NULL
		FROM control.guest_trials WHERE id = $1`, issued.GuestId).Scan(&scrubbed); err != nil || !scrubbed {
		t.Fatalf("expired guest retained source binding: %t, %v", scrubbed, err)
	}
	var retainedHashes int
	if err := inspect.QueryRow(`SELECT count(*) FROM control.ingress_routing_table_events
		WHERE public_url_id = $1 AND convert_from(projection, 'UTF8')::jsonb ? 'allowed_ip_hashes'`,
		ready.PublicURLID).Scan(&retainedHashes); err != nil || retainedHashes != 0 {
		t.Fatalf("expired guest routing events retained %d IP hashes: %v", retainedHashes, err)
	}
}
