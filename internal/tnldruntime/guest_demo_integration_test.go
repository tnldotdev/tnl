package tnldruntime

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlapi"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/demo"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationGuestDemoIssuesAndAuthorizesOneRestrictedPublicURL(t *testing.T) {
	databaseURL, _ := standaloneTestDatabase(t)
	state, err := controlstate.Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	const hostedSecret = "test-hosted-guest-secret-012345678901"
	authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/service/guest-domain" && r.Header.Get("Authorization") == "Bearer "+hostedSecret &&
			strings.HasPrefix(r.URL.Query().Get("namespace_label"), "guest-"):
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(authorityv1.GuestDomain{
				DomainId: "dom_guest", ManagedDomain: "tnl.wtf", NamespaceAvailable: true, DnsAuthorityReference: "da_guest",
			})
		default:
			w.WriteHeader(http.StatusUnauthorized)
		}
	}))
	defer authority.Close()
	h, err := controlapi.NewHandler(controlapi.Config{
		ManagedDeploymentDomain: "tnl.wtf", AuthorityEndpoint: authority.URL,
		GuestDemoEnabled: true, DNSAutomation: true,
		HostedSecret: hostedSecret, HTTPClient: authority.Client(),
	}, state, nil, state.Readiness)
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
			PublicUrlScope: controlv1.Member, Ephemeral: new(bool),
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
	var route controlv1.PublicURL
	if err := json.Unmarshal(allowed.Body.Bytes(), &route); err != nil {
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
	startRun := func(key string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, "/v1/public-urls/"+route.Id+"/publish-runs", nil)
		request.Header.Set("Authorization", "Bearer "+guest.AccessToken)
		request.Header.Set("Idempotency-Key", key)
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
		setup.CertificatePlan.Scope != guest.Namespace || len(setup.CertificatePlan.Identifiers) != 2 {
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
	databaseURL, inspect := standaloneTestDatabase(t)
	publicAddress, relayUDPAddress := unusedTCPAddress(t), unusedUDPAddress(t)
	pebble := startIntegrationPebble(t, integrationPort(t, publicAddress), startIntegrationDNS(t))
	cfg := standalonePublishConfig(t, databaseURL, publicAddress, relayUDPAddress, pebble.directoryURL)
	cfg.GuestDemoEnabled = true
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	owner := newRuntimeTopology(t)
	process := startIntegrationProcessWithOptions(t, cfg, integrationProcessOptions{
		acmeHTTPClient: pebble.httpClient,
		relayClientTLS: &tls.Config{RootCAs: pebble.roots, MinVersion: tls.VersionTLS13}, owner: owner,
	})
	waitForProcessReady(t, process)
	controlHTTP, _ := newIntegrationHTTPSClient(t, pebble.roots, publicAddress, false, owner)
	serverURL := "https://" + cfg.ServerHostname()
	control, err := controlclient.New(serverURL, controlHTTP, "")
	if err != nil {
		t.Fatal(err)
	}
	issued, err := control.CreateGuestDemo(t.Context())
	if err != nil {
		t.Fatalf("guest credential without sign-in: %v", err)
	}
	clientState, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer clientState.Close()
	authenticated, err := clientauth.Authenticate(t.Context(), clientauth.Config{
		ServerEndpoint: serverURL, State: clientState, AccessToken: issued.AccessToken,
		HTTPClient: controlHTTP, Diagnostics: io.Discard,
	})
	if err != nil {
		t.Fatalf("guest client could not reach control without login: %v", err)
	}
	allocated, err := authenticated.Control.AllocateGuestDemoNumber(t.Context())
	if err != nil || allocated.Number != 1 {
		t.Fatalf("guest demo number = %+v, %v", allocated, err)
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
	handle := startOwnedIntegrationPublisher(t, owner, publisher.Config{
		Control: authenticated.Control, TeamID: issued.TeamId, MembershipID: issued.MembershipId,
		DomainID: issued.DomainId, Hostname: hostname, PublicURLScope: controlv1.Member,
		PolicyRevision: 1, Target: localDemo.Target(),
		AllowedIPPrefixes: []string{netip.PrefixFrom(address.Unmap(), address.Unmap().BitLen()).String()},
		Ephemeral:         true, State: store,
		Demo: true, Feedback: true, Service: "demo",
		QUICConnector: quic, TCPConnector: tcp,
	}, func() string { return integrationPublisherDiagnostics(inspect, pebble.logPath) })
	ready := waitForPublisherReady(t, handle)
	var firstReadyAt time.Time
	if err := inspect.QueryRow(`SELECT first_ready_at FROM control.guest_trials WHERE id = $1`, issued.GuestId).Scan(&firstReadyAt); err != nil || firstReadyAt.IsZero() {
		t.Fatalf("guest trial did not record its first ready run: %v", err)
	}
	waitForReadyPublisherConnections(t, inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, inspect, 1)
	localDemo.SetPublicURL(ready.PublicURL)
	visitor := newIntegrationVisitor(t, pebble.roots, publicAddress, owner)
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
