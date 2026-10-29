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
	"github.com/tnldotdev/tnl/internal/policy/trafficlimits"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisher/demo"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type integrationGuestPublisherControl struct {
	*clientcontrol.Client
	native   *publisheridentity.Native
	assigned controlv1.PublicURL
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
	}, state, state, state.Readiness)
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
	publicAddress, relayUDPAddress := publicListener.Addr().String(), unusedUDPAddress(t)
	dns := newPrivateFixtureDNS(t)
	pebble := startIntegrationPebble(t, integrationPort(t, publicAddress), dns.address)
	cfg, listeners := standalonePublishConfig(t, databaseURL, publicListener, relayUDPAddress, pebble.directoryURL)
	cfg.GuestDemoEnabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	owner := newRuntimeTopology(t)
	ca := newIntegrationTestCA(t)
	controlCertificate := ca.issueServer(t, cfg.ServerHostname())
	controlTLS, err := staticServerTLS(controlCertificate.certificateFile, controlCertificate.privateKeyFile)
	if err != nil {
		t.Fatal(err)
	}
	publicControl := unusedTCPAddress(t)
	startIntegrationControlProxy(t, owner, publicControl, cfg.ControlListen, controlTLS)
	var controlOffline atomic.Bool
	var rejectedControlCalls atomic.Int64
	publisherClosing := make(chan struct{})
	notePublisherClosing := sync.OnceFunc(func() { close(publisherClosing) })
	withControlOutage := func(client *http.Client) *http.Client {
		base := client.Transport
		if base == nil {
			base = http.DefaultTransport
		}
		client.Transport = splitACMERoundTripFunc(func(request *http.Request) (*http.Response, error) {
			if controlOffline.Load() {
				rejectedControlCalls.Add(1)
				if request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/v1/publish-runs/") {
					notePublisherClosing()
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
		serviceHTTPClient: withControlOutage(&http.Client{Timeout: 2 * time.Second}),
		relayClientTLS:    &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13}, owner: owner,
	})
	waitForProcessReady(t, process)
	controlHTTP, _ := newIntegrationHTTPSClient(t, ca.roots, publicControl, false, owner)
	withControlOutage(controlHTTP)
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
	relayTLS := &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13}
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
	handle := startOwnedIntegrationPublisher(t, owner, publisher.Config{
		Control: integrationGuestPublisherControl{Client: authenticated.Control, native: native, assigned: publicURL}, TeamID: issued.TeamId, MembershipID: issued.MembershipId,
		ControlURL: serverURL,
		DomainID:   issued.DomainId, Hostname: hostname, PublicURLScope: controlv1.Member, Purpose: controlv1.Demo,
		PolicyRevision: 1, Target: localDemo.Target(),
		AllowedIPPrefixes: prefixes,
		Ephemeral:         true, State: store,
		Demo: true, Feedback: true, Service: "demo",
		QUICConnector: quic, TCPConnector: tcp,
	}, func() string { return integrationPublisherDiagnostics(inspect, pebble.logPath) })
	ready := waitForPublisherReady(t, handle)
	var trafficJSON []byte
	if err := inspect.QueryRow(`SELECT traffic_limits FROM control.publish_runs WHERE public_url_id=$1 AND publish_run_number=$2`, ready.PublicURLID, ready.PublishRunNumber).Scan(&trafficJSON); err != nil {
		t.Fatal(err)
	}
	var traffic trafficlimits.Limits
	if err := json.Unmarshal(trafficJSON, &traffic); err != nil || traffic != trafficlimits.Guest() {
		t.Fatalf("guest traffic limits = %+v, %v", traffic, err)
	}
	var firstReadyAt time.Time
	if err := inspect.QueryRow(`SELECT first_ready_at FROM control.guest_trials WHERE id = $1`, issued.GuestId).Scan(&firstReadyAt); err != nil || firstReadyAt.IsZero() {
		t.Fatalf("guest trial did not record its first ready run: %v", err)
	}
	waitForReadyPublisherConnections(t, inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, inspect, 2)
	localDemo.SetPublicURL(ready.PublicURL)
	visitor := newIntegrationVisitor(t, pebble.roots, publicAddress, owner)
	logIntegrationPublishRunAuthority(t, inspect, ready.PublicURLID, ready.PublishRunNumber, "guest-routing-acknowledged")
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(secret)
	share, err := authenticated.Control.CreateURLShare(t.Context(), "guest-reviewer-share", controlv1.CreateShareRequest{
		PublicUrlIds: []string{ready.PublicURLID}, ExpiresAt: issued.ExpiresAt, SecretFingerprint: hex.EncodeToString(fingerprint[:]),
	})
	if err != nil || share.Scope != controlv1.ShareScopeGuest {
		t.Fatalf("guest trial share = %+v, %v", share, err)
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	visitor.client.Jar = jar
	entry, err := visitor.client.Get(ready.PublicURL + "/__tnl/share/" + share.Id + "." + base64.RawURLEncoding.EncodeToString(secret))
	if err != nil || entry.StatusCode != http.StatusOK {
		t.Fatalf("guest share link = %+v, %v", entry, err)
	}
	_ = entry.Body.Close()
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
	page, err := visitor.client.Get(ready.PublicURL + "/")
	if err != nil {
		t.Fatal(err)
	}
	html, err := io.ReadAll(page.Body)
	page.Body.Close()
	if err != nil || !strings.Contains(string(html), "/__tnl/feedback/toolbar.") || !strings.Contains(page.Header.Get("Content-Security-Policy"), "style-src 'unsafe-inline'") {
		t.Fatalf("demo toolbar or original styles missing: %v", err)
	}
	for _, font := range []string{"fira-code-latin-wght-normal.woff2", "fira-code-symbols2-wght-normal.woff2"} {
		response, err := visitor.client.Get(ready.PublicURL + "/fonts/" + font)
		if err != nil {
			t.Fatal(err)
		}
		bytes, err := io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || bytes == 0 {
			t.Fatalf("demo font under guest limits = %d, %d bytes, %v", response.StatusCode, bytes, err)
		}
	}
	if deadlineProof {
		var deadline time.Time
		if err := inspect.QueryRow(`SELECT ready_deadline FROM control.guest_trials WHERE id=$1`, issued.GuestId).Scan(&deadline); err != nil {
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
		if readErr != nil || response.StatusCode != http.StatusOK || !time.Now().Before(deadline) {
			t.Fatalf("held guest connection before deadline = %d, %v", response.StatusCode, readErr)
		}
		controlOffline.Store(true)
		defer controlOffline.Store(false)
		if _, err := reader.ReadByte(); err == nil || errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("guest connection survived its offline ready deadline: %v", err)
		}
		if time.Now().After(deadline.Add(time.Second)) || rejectedControlCalls.Load() == 0 {
			t.Fatal("guest closure did not occur within the hard deadline during a control outage")
		}
		// serving has already stopped within the hard bound above. process
		// cleanup has its separate ordinary bounded drain, not serving authority.
		// do not cancel this owner before observing its own expiry: an earlier
		// policy/ingress cutoff can close the connection before the publisher's
		// last issued deadline, and parent cancellation would hide that cause.
		if err := waitForDoneWithin(publisherClosing, max(0, time.Until(deadline))+10*time.Second); err != nil {
			t.Fatal("guest publisher did not reach cleanup after its own deadline", err)
		}
		// only restore control after the owner has reached run-close itself.
		// offline serving must not depend on audit flush or remote close success.
		controlOffline.Store(false)
		if err := waitForDoneWithin(handle.done, 10*time.Second); err != nil {
			t.Fatal("guest publisher cleanup did not join", err)
		}
		if err := handle.result(); !errors.Is(err, clientcontrol.ErrStatusConflict) {
			t.Fatalf("guest publisher cutoff result = %v", err)
		} else {
			t.Logf("expected guest publisher cutoff: %v", err)
		}
		// acknowledge only the asserted terminal cutoff, as the ingress-restart
		// fixture does for its expected lease loss. cleanup still joins this run.
		handle.mu.Lock()
		handle.err = nil
		handle.mu.Unlock()
		return
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
