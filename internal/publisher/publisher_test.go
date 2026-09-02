package publisher

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/serverclient"
	"github.com/tnldotdev/tnl/pkg/protocol/serverv1"
	"github.com/tnldotdev/tnl/pkg/protocol/transportv1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRunPublishChecksTargetBeforeCreatingRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	server := new(publisherServerStub)
	err = Run(context.Background(), Config{
		Server: server, Hostname: "route.example", Target: target,
		Certificate: routeTestCertificate(t, "route.example"),
	})
	if err == nil {
		t.Fatal("Run accepted unavailable target")
	}
	if server.createCalls != 0 {
		t.Fatalf("CreateRoute calls = %d, want 0", server.createCalls)
	}
}

func TestRunPublishRejectsWeakManualCertificate(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), DNSNames: []string{"*.example", "other.invalid"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, privateKey.Public(), privateKey)
	if err != nil {
		t.Fatal(err)
	}
	err = Run(context.Background(), Config{
		Server: new(publisherServerStub), Hostname: "route.example", Target: "http://127.0.0.1:3000",
		Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey},
	})
	if err == nil {
		t.Fatal("Run accepted a wildcard RSA application certificate")
	}
}

func TestCreateOrRecoverUsesLocalRouteToken(t *testing.T) {
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	server := &publisherServerStub{
		createErr: serverclient.ErrStatusConflict,
		routes: []serverv1.Route{{
			Id: "route_id", Hostname: "route.example", LocalTarget: "http://127.0.0.1:3000",
		}},
		sessionSetup: serverv1.SessionSetup{Route: serverv1.Route{Id: "route_id"}},
	}
	policy := []string{"192.0.2.0/24"}
	setup, err := createOrRecover(
		context.Background(), server, "route.example", "http://127.0.0.1:3000", routeToken, policy,
	)
	if err != nil {
		t.Fatal(err)
	}
	if setup.Route.Id != "route_id" || server.sessionRouteToken != routeToken {
		t.Fatalf("setup = %#v, session route token = %q", setup, server.sessionRouteToken)
	}
	if server.created.AllowedIpPrefixes == nil || fmt.Sprint(*server.created.AllowedIpPrefixes) != "[192.0.2.0/24]" ||
		fmt.Sprint(server.sessionAllowedIPPrefixes) != "[192.0.2.0/24]" {
		t.Fatalf("create/session policies = %v, %v", server.created.AllowedIpPrefixes, server.sessionAllowedIPPrefixes)
	}
	if _, _, err := credentials.ParseRouteToken(credentials.RouteToken(server.created.RouteToken)); err != nil {
		t.Fatalf("create route token = %q: %v", server.created.RouteToken, err)
	}
}

func TestCreateOrRecoverRetriesBeforeCredentialRotationCommits(t *testing.T) {
	previous := activationRetry
	activationRetry = time.Millisecond
	t.Cleanup(func() { activationRetry = previous })
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	want := serverv1.SessionSetup{Route: serverv1.Route{Id: "route_id"}}
	server := &publisherServerStub{
		createErrors: []error{serverclient.ErrUnavailable, nil},
		createSetups: []serverv1.SessionSetup{{}, want},
		routes: []serverv1.Route{{
			Id: "route_id", Hostname: "route.example", LocalTarget: "http://127.0.0.1:3000",
		}},
		sessionErr: serverclient.ErrUnauthenticated,
	}
	setup, err := createOrRecover(
		context.Background(), server, "route.example", "http://127.0.0.1:3000", routeToken, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if setup.Route.Id != want.Route.Id || server.createCalls != 2 {
		t.Fatalf("setup = %#v, create calls = %d", setup, server.createCalls)
	}
}

func TestHeartbeatSessionSurvivesTransientFailure(t *testing.T) {
	previous := heartbeatInterval
	heartbeatInterval = time.Millisecond
	t.Cleanup(func() { heartbeatInterval = previous })
	server := &publisherServerStub{heartbeatErrors: []error{serverclient.ErrUnavailable, serverclient.ErrStatusConflict}}
	err := heartbeatSession(
		context.Background(), server, "route_id", 1, "tnl_session_test", time.Now().Add(time.Second),
	)
	if !errors.Is(err, serverclient.ErrStatusConflict) || server.heartbeatCalls != 2 {
		t.Fatalf("heartbeat error = %v, calls = %d", err, server.heartbeatCalls)
	}
}

func TestHeartbeatSessionStartsImmediately(t *testing.T) {
	previous := heartbeatInterval
	heartbeatInterval = time.Hour
	t.Cleanup(func() { heartbeatInterval = previous })
	server := &publisherServerStub{heartbeatErrors: []error{serverclient.ErrStatusConflict}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := heartbeatSession(ctx, server, "route_id", 1, "tnl_session_test", time.Now().Add(time.Second))
	if !errors.Is(err, serverclient.ErrStatusConflict) || server.heartbeatCalls != 1 {
		t.Fatalf("heartbeat error = %v, calls = %d", err, server.heartbeatCalls)
	}
}

func TestRunPublishCreatesSessionAfterHeartbeatFence(t *testing.T) {
	previousRelayCheck := relayCheckInterval
	relayCheckInterval = time.Millisecond
	t.Cleanup(func() { relayCheckInterval = previousRelayCheck })
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	firstSession, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	secondSession, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	routeID := "route_0123456789abcdef0123456789abcdef"
	setup := func(version int, token credentials.SessionToken) serverv1.SessionSetup {
		return serverv1.SessionSetup{
			Route: serverv1.Route{Id: routeID, Hostname: "route.example", Version: version},
			Session: serverv1.RouteSession{
				Id: "session_0123456789abcdef0123456789abcdef", RouteId: routeID,
				Version: version, ExpiresAt: time.Now().Add(time.Minute),
			},
			SessionToken: token.String(), WorkerPublicKey: key.NewNode().Public().String(),
		}
	}
	server := &publisherServerStub{
		createErrors:    []error{nil},
		createSetups:    []serverv1.SessionSetup{setup(1, firstSession)},
		sessionSetup:    setup(2, secondSession),
		heartbeatErrors: []error{nil, nil},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var versions []uint64
	regionLoads := 0
	err = Run(ctx, Config{
		Server: server, Hostname: "route.example", Target: "http://" + listener.Addr().String(),
		Certificate: routeTestCertificate(t, "route.example"),
		RelayRegion: "test", Regions: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
		LoadRegions: func(context.Context) (map[string]*tailcfg.DERPRegion, error) {
			regionLoads++
			hostname := "old-derp.example"
			if regionLoads > 1 {
				hostname = "new-derp.example"
			}
			return map[string]*tailcfg.DERPRegion{"test": {
				RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: hostname}},
			}}, nil
		},
		DrainTime: time.Millisecond,
		OnSessionReady: func(_ string, version uint64) error {
			versions = append(versions, version)
			if version == 2 {
				cancel()
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if server.sessionCalls != 1 || regionLoads < 3 || len(versions) != 2 ||
		versions[0] != 1 || versions[1] != 2 || server.deleteCalls != 1 {
		t.Fatalf("session calls = %d, delete calls = %d, region loads = %d, versions = %v",
			server.sessionCalls, server.deleteCalls, regionLoads, versions)
	}
}

func TestIssueCertificatePersistsAndRotatesApplicationKey(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.OpenRoute("route_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	route, err := NewRoute(RouteConfig{
		Hostname: "route.example", Target: "http://127.0.0.1:3000", AllowedClient: key.NewNode().Public(),
		RelayRegion: "test", Regions: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	server := &issuanceServer{publisherServerStub: new(publisherServerStub), t: t}
	material, err := issueCertificate(
		context.Background(), server, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"session", "route.example", "tlsserver", make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if server.readyCalls != 1 || server.removedCalls != 1 || server.installedCalls != 1 {
		t.Fatalf("certificate calls = ready %d, removed %d, installed %d", server.readyCalls, server.removedCalls, server.installedCalls)
	}
	loaded, found, err := state.Current("route.example")
	if err != nil || !found || loaded.Certificate.Leaf == nil {
		t.Fatalf("loaded certificate = %+v, %v, %v", loaded, found, err)
	}
	firstKey := material.Certificate.Leaf.RawSubjectPublicKeyInfo
	second, err := issueCertificate(
		context.Background(), server, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"session", "route.example", "tlsserver", make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstKey) == string(second.Certificate.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("renewal reused the application key")
	}
}

func TestUnacknowledgedCertificateRebindsAfterRestart(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.OpenRoute("route_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	route := testCertificateRoute(t, true)
	defer route.Close()
	server := &issuanceServer{publisherServerStub: new(publisherServerStub), t: t, installErrors: []error{serverclient.ErrCertificateStatus}}
	material, err := issueCertificate(
		context.Background(), server, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"session", "route.example", "tlsserver", make(chan error),
	)
	if !errors.Is(err, serverclient.ErrCertificateStatus) || material.Installed {
		t.Fatalf("issuance = %+v, %v", material, err)
	}
	loaded, found, err := state.Current("route.example")
	if err != nil || !found || loaded.Installed {
		t.Fatalf("unacknowledged current = %+v, %v, %v", loaded, found, err)
	}
	server.reuseCurrent = true
	material, err = reconcileCertificateInstallation(
		context.Background(), server, route, state, "route_0123456789abcdef0123456789abcdef", 2,
		"session", "route.example", "tlsserver", loaded, make(chan error),
	)
	if err != nil || !material.Installed || material.Version != 2 || server.issuances != 2 || server.installedCalls != 2 {
		t.Fatalf("reconciled material = %+v, issuances = %d, installs = %d, error = %v", material, server.issuances, server.installedCalls, err)
	}
}

func TestTerminalIssuanceRotatesPendingApplicationKey(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.OpenRoute("route_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	pending, err := state.Pending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	initialKey, err := x509.MarshalPKIXPublicKey(&pending.Key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	route := testCertificateRoute(t, true)
	defer route.Close()
	server := &issuanceServer{publisherServerStub: new(publisherServerStub), t: t, terminalFirst: true}
	material, err := issueCertificate(
		context.Background(), server, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"session", "route.example", "tlsserver", make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if server.issuances != 2 || string(initialKey) == string(material.Certificate.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatalf("issuances = %d; terminal issuance key was reused", server.issuances)
	}
}

func TestUnacknowledgedCertificatePastRenewalFallsBackToReplacement(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.OpenRoute("route_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	pending, err := state.Pending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	current, err := state.Commit(
		"route.example", pending, signCSR(t, mustParseCSR(t, pending.CSRDER), "route.example"),
		time.Now().Add(-time.Millisecond), "issuance_old", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	route := testCertificateRoute(t, true)
	defer route.Close()
	if err := route.InstallCertificate(current.Certificate); err != nil {
		t.Fatal(err)
	}
	server := &issuanceServer{publisherServerStub: new(publisherServerStub), t: t}
	replacement, err := refreshCertificate(
		context.Background(), server, route, state, "route_0123456789abcdef0123456789abcdef", 2,
		"session", "route.example", "tlsserver", current, make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Version != 2 || bytes.Equal(
		current.Certificate.Leaf.RawSubjectPublicKeyInfo, replacement.Certificate.Leaf.RawSubjectPublicKeyInfo,
	) {
		t.Fatalf("replacement = %+v", replacement)
	}
}

func TestUnacknowledgedCertificateCanCompleteFreshReboundIssuance(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.OpenRoute("route_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	pending, err := state.Pending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	current, err := state.Commit(
		"route.example", pending, signCSR(t, mustParseCSR(t, pending.CSRDER), "route.example"),
		time.Now().Add(30*24*time.Hour), "issuance_old", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	route := testCertificateRoute(t, true)
	defer route.Close()
	if err := route.InstallCertificate(current.Certificate); err != nil {
		t.Fatal(err)
	}
	server := &issuanceServer{publisherServerStub: new(publisherServerStub), t: t}
	replacement, err := refreshCertificate(
		context.Background(), server, route, state, "route_0123456789abcdef0123456789abcdef", 2,
		"session", "route.example", "tlsserver", current, make(chan error),
	)
	if err != nil || !replacement.Installed || replacement.Version != 2 || !bytes.Equal(
		current.Certificate.Leaf.RawSubjectPublicKeyInfo, replacement.Certificate.Leaf.RawSubjectPublicKeyInfo,
	) {
		t.Fatalf("rebound replacement = %+v, %v", replacement, err)
	}
}

func TestCertificateRetryPropagatesConsumedStaleSession(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.OpenRoute("route_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	route := testCertificateRoute(t, true)
	defer route.Close()
	heartbeatErrors := make(chan error, 1)
	heartbeatErrors <- serverclient.ErrStatusConflict
	_, err = issueCertificate(
		context.Background(), &unavailableCertificateServer{publisherServerStub: new(publisherServerStub)}, route, state,
		"route_0123456789abcdef0123456789abcdef", 1, "session", "route.example", "tlsserver", heartbeatErrors,
	)
	if !errors.Is(err, serverclient.ErrStatusConflict) {
		t.Fatalf("issuance error = %v", err)
	}
}

func TestCertificateIssuanceAcceptsChallengeBearingResumeStates(t *testing.T) {
	digest := sha256.Sum256([]byte("key authorization"))
	for _, state := range []serverv1.CertificateIssuanceStatus{
		serverv1.CertificateIssuanceStatusWaitingForChallenge, serverv1.CertificateIssuanceStatusValidating, serverv1.CertificateIssuanceStatusReadyToFinalize, serverv1.CertificateIssuanceStatusFinalizing, serverv1.CertificateIssuanceStatusDownloading,
	} {
		issuance := serverv1.CertificateIssuance{
			Id: "issuance_id", RouteId: "route_id", Version: 2, Hostname: "route.example", AcmeProfile: "tlsserver", Status: state,
			Challenge: &serverv1.CertificateChallenge{
				Id: "challenge", Hostname: "route.example", Digest: base64.RawURLEncoding.EncodeToString(digest[:]),
				ExpiresAt: time.Now().Add(time.Hour),
			},
		}
		if err := validateCertificateIssuance(issuance, "route_id", 2, "route.example", "tlsserver", "issuance_id"); err != nil {
			t.Fatalf("state %q: %v", state, err)
		}
	}
}

func TestRenewalFailureKeepsCurrentCertificateServing(t *testing.T) {
	previousRetry := renewalRetry
	renewalRetry = 5 * time.Millisecond
	t.Cleanup(func() { renewalRetry = previousRetry })
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	state, err := store.OpenRoute("route_0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	pending, err := state.Pending("route.example")
	if err != nil {
		t.Fatal(err)
	}
	material, err := state.Commit(
		"route.example", pending, signCSR(t, mustParseCSR(t, pending.CSRDER), "route.example"),
		time.Now().Add(-time.Millisecond), "issuance_current", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.MarkInstalled("route.example", material.IssuanceID, material.Version); err != nil {
		t.Fatal(err)
	}
	material, found, err := state.Current("route.example")
	if err != nil || !found || !material.Installed {
		t.Fatalf("installed current = %+v, %v, %v", material, found, err)
	}
	sessionToken, _, _, err := credentials.NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	server := &renewalFailureServer{publisherServerStub: new(publisherServerStub), called: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	var logs atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runSession(ctx, Config{
			Server: server, Target: "http://127.0.0.1:3000", State: store, ACMEProfile: "tlsserver",
			RelayRegion: "test", Regions: map[string]*tailcfg.DERPRegion{"test": {
				RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
			}}, DrainTime: 20 * time.Millisecond, Logf: func(string, ...any) { logs.Add(1) },
		}, serverv1.SessionSetup{
			Route:        serverv1.Route{Id: "route_0123456789abcdef0123456789abcdef", Hostname: "route.example"},
			Session:      serverv1.RouteSession{Version: 1, ExpiresAt: time.Now().Add(time.Minute)},
			SessionToken: sessionToken.String(), WorkerPublicKey: key.NewNode().Public().String(),
		}, state, func() error { return nil })
	}()
	select {
	case <-server.called:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("renewal was not attempted")
	}
	select {
	case err := <-result:
		cancel()
		t.Fatalf("renewal failure stopped the route: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	cancel()
	err = <-result
	if errors.Is(err, serverclient.ErrCertificateStatus) || server.issuanceCalls == 0 || logs.Load() == 0 {
		t.Fatalf("runSession error = %v, renewal calls = %d, logs = %d", err, server.issuanceCalls, logs.Load())
	}
}

func mustParseCSR(t *testing.T, der []byte) *x509.CertificateRequest {
	t.Helper()
	request, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func testCertificateRoute(t *testing.T, strict bool) *Route {
	t.Helper()
	route, err := NewRoute(RouteConfig{
		Hostname: "route.example", Target: "http://127.0.0.1:3000", StrictCertificate: strict,
		AllowedClient: key.NewNode().Public(), RelayRegion: "test", Regions: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return route
}

type publisherServerStub struct {
	createCalls              int
	createErr                error
	createErrors             []error
	createSetups             []serverv1.SessionSetup
	created                  serverv1.CreateRouteRequest
	routes                   []serverv1.Route
	sessionSetup             serverv1.SessionSetup
	sessionRouteToken        credentials.RouteToken
	sessionAllowedIPPrefixes []string
	sessionErr               error
	sessionCalls             int
	heartbeatCalls           int
	heartbeatErrors          []error
	deleteCalls              int
}

type issuanceServer struct {
	*publisherServerStub
	t                 *testing.T
	issuances         int
	readyCalls        int
	removedCalls      int
	installedCalls    int
	lastCSR           *x509.CertificateRequest
	currentIssuanceID string
	currentVersion    int
	certificate       string
	notBefore         time.Time
	notAfter          time.Time
	renewAt           time.Time
	reuseCurrent      bool
	installErrors     []error
	terminalFirst     bool
}

type renewalFailureServer struct {
	*publisherServerStub
	issuanceCalls int
	called        chan struct{}
}

type unavailableCertificateServer struct{ *publisherServerStub }

func (*unavailableCertificateServer) CreateCertificateIssuance(
	context.Context,
	string,
	uint64,
	credentials.SessionToken,
	string,
	[]byte,
) (serverv1.CertificateIssuance, error) {
	return serverv1.CertificateIssuance{}, serverclient.ErrUnavailable
}

func (c *renewalFailureServer) CreateCertificateIssuance(
	context.Context,
	string,
	uint64,
	credentials.SessionToken,
	string,
	[]byte,
) (serverv1.CertificateIssuance, error) {
	c.issuanceCalls++
	select {
	case c.called <- struct{}{}:
	default:
	}
	return serverv1.CertificateIssuance{}, serverclient.ErrCertificateStatus
}

func (c *issuanceServer) CreateCertificateIssuance(
	_ context.Context,
	_ string,
	version uint64,
	_ credentials.SessionToken,
	_ string,
	csrDER []byte,
) (serverv1.CertificateIssuance, error) {
	c.t.Helper()
	c.issuances++
	c.currentIssuanceID = fmt.Sprintf("issuance_%032x", c.issuances)
	c.currentVersion = int(version)
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || request.CheckSignature() != nil {
		c.t.Fatalf("CSR = %v, %v", request, err)
	}
	c.lastCSR = request
	if c.terminalFirst && c.issuances == 1 {
		return serverv1.CertificateIssuance{
			Id: c.currentIssuanceID, RouteId: "route_0123456789abcdef0123456789abcdef",
			Version: c.currentVersion, Hostname: "route.example", AcmeProfile: "tlsserver", Status: serverv1.CertificateIssuanceStatusBlocked,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}, nil
	}
	if c.reuseCurrent {
		return serverv1.CertificateIssuance{
			Id: c.currentIssuanceID, RouteId: "route_0123456789abcdef0123456789abcdef",
			Version: c.currentVersion, Hostname: "route.example", AcmeProfile: "tlsserver", Status: serverv1.CertificateIssuanceStatusWaitingForInstall,
			CertificatePem: &c.certificate, NotBefore: &c.notBefore, NotAfter: &c.notAfter,
			RenewAt: &c.renewAt, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}, nil
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("key authorization %d", c.issuances)))
	return serverv1.CertificateIssuance{
		Id: c.currentIssuanceID, RouteId: "route_0123456789abcdef0123456789abcdef",
		Version: c.currentVersion, Hostname: "route.example", AcmeProfile: "tlsserver", Status: serverv1.CertificateIssuanceStatusWaitingForChallenge,
		Challenge: &serverv1.CertificateChallenge{
			Id: fmt.Sprintf("challenge-%d", c.issuances), Hostname: "route.example", Digest: base64.RawURLEncoding.EncodeToString(digest[:]),
			ExpiresAt: time.Now().Add(time.Hour),
		},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}, nil
}

func (c *issuanceServer) CertificateChallengeReady(
	_ context.Context,
	_ string,
	_ credentials.SessionToken,
) (serverv1.CertificateIssuance, error) {
	c.t.Helper()
	c.readyCalls++
	c.certificate = string(signCSR(c.t, c.lastCSR, "route.example"))
	block, _ := pem.Decode([]byte(c.certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		c.t.Fatal(err)
	}
	c.notBefore, c.notAfter = leaf.NotBefore, leaf.NotAfter
	c.renewAt = time.Now().Add(30 * 24 * time.Hour).UTC()
	return serverv1.CertificateIssuance{
		Id: c.currentIssuanceID, RouteId: "route_0123456789abcdef0123456789abcdef",
		Version: c.currentVersion, Hostname: "route.example", AcmeProfile: "tlsserver", Status: serverv1.CertificateIssuanceStatusWaitingForInstall,
		CertificatePem: &c.certificate, NotBefore: &c.notBefore, NotAfter: &c.notAfter,
		RenewAt: &c.renewAt, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}, nil
}

func (c *issuanceServer) CertificateChallengeRemoved(context.Context, string, credentials.SessionToken) error {
	c.removedCalls++
	return nil
}

func (c *issuanceServer) CertificateInstalled(context.Context, string, uint64, string, credentials.SessionToken) error {
	c.installedCalls++
	if len(c.installErrors) != 0 {
		err := c.installErrors[0]
		c.installErrors = c.installErrors[1:]
		return err
	}
	return nil
}

func signCSR(t *testing.T, request *x509.CertificateRequest, hostname string) []byte {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(request.PublicKey.(*ecdsa.PublicKey).Curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issuer := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Issuer"}, IsCA: true, BasicConstraintsValid: true,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(365 * 24 * time.Hour), KeyUsage: x509.KeyUsageCertSign,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuer, issuer, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err = x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{hostname}, NotBefore: now.Add(-time.Minute),
		NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, issuer, request.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
}

func (c *publisherServerStub) CreateRoute(_ context.Context, request serverv1.CreateRouteRequest) (serverv1.SessionSetup, error) {
	index := c.createCalls
	c.createCalls++
	c.created = request
	if index < len(c.createErrors) {
		var setup serverv1.SessionSetup
		if index < len(c.createSetups) {
			setup = c.createSetups[index]
		}
		return setup, c.createErrors[index]
	}
	return serverv1.SessionSetup{}, c.createErr
}

func (c *publisherServerStub) ListRoutes(context.Context) ([]serverv1.Route, error) {
	return c.routes, nil
}

func (c *publisherServerStub) DeleteRoute(context.Context, string) error {
	c.deleteCalls++
	return nil
}

func (c *publisherServerStub) CreateRouteSession(
	_ context.Context,
	_ string,
	token credentials.RouteToken,
	allowedIPPrefixes []string,
) (serverv1.SessionSetup, error) {
	c.sessionCalls++
	c.sessionRouteToken = token
	c.sessionAllowedIPPrefixes = append([]string(nil), allowedIPPrefixes...)
	return c.sessionSetup, c.sessionErr
}

func (*publisherServerStub) RegisterTransport(
	context.Context,
	string,
	uint64,
	credentials.SessionToken,
	transportv1.TailcatDescriptor,
) error {
	return nil
}

func (*publisherServerStub) Ready(context.Context, string, uint64, credentials.SessionToken) error {
	return nil
}

func (c *publisherServerStub) Heartbeat(
	context.Context,
	string,
	uint64,
	credentials.SessionToken,
) (serverv1.HeartbeatResponse, error) {
	index := c.heartbeatCalls
	c.heartbeatCalls++
	if index < len(c.heartbeatErrors) && c.heartbeatErrors[index] != nil {
		return serverv1.HeartbeatResponse{}, c.heartbeatErrors[index]
	}
	return serverv1.HeartbeatResponse{ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (*publisherServerStub) CreateCertificateIssuance(
	context.Context,
	string,
	uint64,
	credentials.SessionToken,
	string,
	[]byte,
) (serverv1.CertificateIssuance, error) {
	return serverv1.CertificateIssuance{}, nil
}

func (*publisherServerStub) CertificateChallengeReady(
	context.Context,
	string,
	credentials.SessionToken,
) (serverv1.CertificateIssuance, error) {
	return serverv1.CertificateIssuance{}, nil
}

func (*publisherServerStub) CertificateChallengeRemoved(context.Context, string, credentials.SessionToken) error {
	return nil
}

func (*publisherServerStub) CertificateInstalled(
	context.Context,
	string,
	uint64,
	string,
	credentials.SessionToken,
) error {
	return nil
}
