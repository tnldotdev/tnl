package publication

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

	"github.com/0xcadams/tnl/internal/clientstate"
	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"github.com/0xcadams/tnl/pkg/protocol/transportv1"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestRunPublicChecksTargetBeforeCreatingRoute(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	core := new(publicCoreStub)
	err = RunPublic(context.Background(), PublicConfig{
		Core: core, Hostname: "route.example", Target: target,
		Certificate: routeTestCertificate(t, "route.example"),
	})
	if err == nil {
		t.Fatal("RunPublic accepted unavailable target")
	}
	if core.createCalls != 0 {
		t.Fatalf("CreateRoute calls = %d, want 0", core.createCalls)
	}
}

func TestRunPublicRejectsWeakManualCertificate(t *testing.T) {
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
	err = RunPublic(context.Background(), PublicConfig{
		Core: new(publicCoreStub), Hostname: "route.example", Target: "http://127.0.0.1:3000",
		Certificate: tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey},
	})
	if err == nil {
		t.Fatal("RunPublic accepted a wildcard RSA application certificate")
	}
}

func TestCreateOrRecoverUsesLocallyOwnedRouteToken(t *testing.T) {
	routeToken, _, _, err := credentials.NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	core := &publicCoreStub{
		createErr: coreclient.ErrStateConflict,
		routes: []corev1.Route{{
			Id: "route_id", Hostname: "route.example", DisplayTarget: "http://127.0.0.1:3000",
		}},
		acquired: corev1.LeaseSetup{Route: corev1.Route{Id: "route_id"}},
	}
	setup, err := createOrRecover(
		context.Background(), core, "route.example", "http://127.0.0.1:3000", routeToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if setup.Route.Id != "route_id" || core.acquiredToken != routeToken {
		t.Fatalf("setup = %#v, acquired token = %q", setup, core.acquiredToken)
	}
	if _, _, err := credentials.ParseRouteToken(credentials.RouteToken(core.created.RouteToken)); err != nil {
		t.Fatalf("create route token = %q: %v", core.created.RouteToken, err)
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
	want := corev1.LeaseSetup{Route: corev1.Route{Id: "route_id"}}
	core := &publicCoreStub{
		createErrors: []error{coreclient.ErrUnavailable, nil},
		createSetups: []corev1.LeaseSetup{{}, want},
		routes: []corev1.Route{{
			Id: "route_id", Hostname: "route.example", DisplayTarget: "http://127.0.0.1:3000",
		}},
		acquireErr: coreclient.ErrUnauthenticated,
	}
	setup, err := createOrRecover(
		context.Background(), core, "route.example", "http://127.0.0.1:3000", routeToken,
	)
	if err != nil {
		t.Fatal(err)
	}
	if setup.Route.Id != want.Route.Id || core.createCalls != 2 {
		t.Fatalf("setup = %#v, create calls = %d", setup, core.createCalls)
	}
}

func TestHeartbeatLeaseSurvivesTransientFailure(t *testing.T) {
	previous := heartbeatInterval
	heartbeatInterval = time.Millisecond
	t.Cleanup(func() { heartbeatInterval = previous })
	core := &publicCoreStub{heartbeatErrors: []error{coreclient.ErrUnavailable, coreclient.ErrStateConflict}}
	err := heartbeatLease(
		context.Background(), core, "route_id", 1, "tnl_lease_test", time.Now().Add(time.Second),
	)
	if !errors.Is(err, coreclient.ErrStateConflict) || core.heartbeatCalls != 2 {
		t.Fatalf("heartbeat error = %v, calls = %d", err, core.heartbeatCalls)
	}
}

func TestHeartbeatLeaseStartsImmediately(t *testing.T) {
	previous := heartbeatInterval
	heartbeatInterval = time.Hour
	t.Cleanup(func() { heartbeatInterval = previous })
	core := &publicCoreStub{heartbeatErrors: []error{coreclient.ErrStateConflict}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	err := heartbeatLease(ctx, core, "route_id", 1, "tnl_lease_test", time.Now().Add(time.Second))
	if !errors.Is(err, coreclient.ErrStateConflict) || core.heartbeatCalls != 1 {
		t.Fatalf("heartbeat error = %v, calls = %d", err, core.heartbeatCalls)
	}
}

func TestRunPublicReacquiresAfterHeartbeatFence(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	firstLease, _, _, err := credentials.NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	secondLease, _, _, err := credentials.NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	routeID := "route_0123456789abcdef0123456789abcdef"
	setup := func(generation int, token credentials.LeaseToken) corev1.LeaseSetup {
		return corev1.LeaseSetup{
			Route: corev1.Route{Id: routeID, Hostname: "route.example", Generation: generation},
			Lease: corev1.RouteLease{
				Id: "lease_0123456789abcdef0123456789abcdef", RouteId: routeID,
				Generation: generation, ExpiresAt: time.Now().Add(time.Minute),
			},
			LeaseToken: token.String(), IngressPublicKey: key.NewNode().Public().String(),
		}
	}
	core := &publicCoreStub{
		createErrors:    []error{nil},
		createSetups:    []corev1.LeaseSetup{setup(1, firstLease)},
		acquired:        setup(2, secondLease),
		heartbeatErrors: []error{coreclient.ErrStateConflict, nil},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var generations []uint64
	err = RunPublic(ctx, PublicConfig{
		Core: core, Hostname: "route.example", Target: "http://" + listener.Addr().String(),
		Certificate:  routeTestCertificate(t, "route.example"),
		RelayProfile: "test", Profiles: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
		DrainTime: time.Millisecond,
		OnLeaseReady: func(_ string, generation uint64) error {
			generations = append(generations, generation)
			if generation == 2 {
				cancel()
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if core.acquireCalls != 1 || len(generations) != 1 || generations[0] != 2 {
		t.Fatalf("acquire calls = %d, generations = %v", core.acquireCalls, generations)
	}
}

func TestIssueCertificatePersistsAndRotatesApplicationKey(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://core.example")
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
		RelayProfile: "test", Profiles: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	core := &issuanceCore{publicCoreStub: new(publicCoreStub), t: t}
	material, err := issueCertificate(
		context.Background(), core, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"lease", "route.example", "tlsserver", make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if core.readyCalls != 1 || core.removedCalls != 1 || core.installedCalls != 1 {
		t.Fatalf("certificate calls = ready %d, removed %d, installed %d", core.readyCalls, core.removedCalls, core.installedCalls)
	}
	loaded, found, err := state.Current("route.example")
	if err != nil || !found || loaded.Certificate.Leaf == nil {
		t.Fatalf("loaded certificate = %+v, %v, %v", loaded, found, err)
	}
	firstKey := material.Certificate.Leaf.RawSubjectPublicKeyInfo
	second, err := issueCertificate(
		context.Background(), core, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"lease", "route.example", "tlsserver", make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if string(firstKey) == string(second.Certificate.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatal("renewal reused the application key")
	}
}

func TestUnacknowledgedCertificateRebindsAfterRestart(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://core.example")
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
	core := &issuanceCore{publicCoreStub: new(publicCoreStub), t: t, installErrors: []error{coreclient.ErrCertificateState}}
	material, err := issueCertificate(
		context.Background(), core, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"lease", "route.example", "tlsserver", make(chan error),
	)
	if !errors.Is(err, coreclient.ErrCertificateState) || material.Installed {
		t.Fatalf("issuance = %+v, %v", material, err)
	}
	loaded, found, err := state.Current("route.example")
	if err != nil || !found || loaded.Installed {
		t.Fatalf("unacknowledged current = %+v, %v, %v", loaded, found, err)
	}
	core.reuseCurrent = true
	material, err = reconcileCertificateInstallation(
		context.Background(), core, route, state, "route_0123456789abcdef0123456789abcdef", 2,
		"lease", "route.example", "tlsserver", loaded, make(chan error),
	)
	if err != nil || !material.Installed || material.Generation != 2 || core.orders != 2 || core.installedCalls != 2 {
		t.Fatalf("reconciled material = %+v, orders = %d, installs = %d, error = %v", material, core.orders, core.installedCalls, err)
	}
}

func TestTerminalOrderRotatesPendingApplicationKey(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://core.example")
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
	core := &issuanceCore{publicCoreStub: new(publicCoreStub), t: t, terminalFirst: true}
	material, err := issueCertificate(
		context.Background(), core, route, state, "route_0123456789abcdef0123456789abcdef", 1,
		"lease", "route.example", "tlsserver", make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if core.orders != 2 || string(initialKey) == string(material.Certificate.Leaf.RawSubjectPublicKeyInfo) {
		t.Fatalf("orders = %d; terminal order key was reused", core.orders)
	}
}

func TestUnacknowledgedCertificatePastRenewalFallsBackToReplacement(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://core.example")
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
		time.Now().Add(-time.Millisecond), "cert_old", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	route := testCertificateRoute(t, true)
	defer route.Close()
	if err := route.InstallCertificate(current.Certificate); err != nil {
		t.Fatal(err)
	}
	core := &issuanceCore{publicCoreStub: new(publicCoreStub), t: t}
	replacement, err := refreshCertificate(
		context.Background(), core, route, state, "route_0123456789abcdef0123456789abcdef", 2,
		"lease", "route.example", "tlsserver", current, make(chan error),
	)
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Generation != 2 || bytes.Equal(
		current.Certificate.Leaf.RawSubjectPublicKeyInfo, replacement.Certificate.Leaf.RawSubjectPublicKeyInfo,
	) {
		t.Fatalf("replacement = %+v", replacement)
	}
}

func TestUnacknowledgedCertificateCanCompleteFreshReboundOrder(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://core.example")
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
		time.Now().Add(30*24*time.Hour), "cert_old", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	route := testCertificateRoute(t, true)
	defer route.Close()
	if err := route.InstallCertificate(current.Certificate); err != nil {
		t.Fatal(err)
	}
	core := &issuanceCore{publicCoreStub: new(publicCoreStub), t: t}
	replacement, err := refreshCertificate(
		context.Background(), core, route, state, "route_0123456789abcdef0123456789abcdef", 2,
		"lease", "route.example", "tlsserver", current, make(chan error),
	)
	if err != nil || !replacement.Installed || replacement.Generation != 2 || !bytes.Equal(
		current.Certificate.Leaf.RawSubjectPublicKeyInfo, replacement.Certificate.Leaf.RawSubjectPublicKeyInfo,
	) {
		t.Fatalf("rebound replacement = %+v, %v", replacement, err)
	}
}

func TestCertificateRetryPropagatesConsumedStaleLease(t *testing.T) {
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://core.example")
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
	heartbeatErrors <- coreclient.ErrStateConflict
	_, err = issueCertificate(
		context.Background(), &unavailableCertificateCore{publicCoreStub: new(publicCoreStub)}, route, state,
		"route_0123456789abcdef0123456789abcdef", 1, "lease", "route.example", "tlsserver", heartbeatErrors,
	)
	if !errors.Is(err, coreclient.ErrStateConflict) {
		t.Fatalf("issuance error = %v", err)
	}
}

func TestCertificateOrderAcceptsChallengeBearingResumeStates(t *testing.T) {
	digest := sha256.Sum256([]byte("key authorization"))
	for _, state := range []corev1.CertificateOrderState{
		corev1.WaitingForChallenge, corev1.Validating, corev1.ReadyToFinalize, corev1.Finalizing, corev1.Downloading,
	} {
		order := corev1.CertificateOrder{
			Id: "cert_id", RouteId: "route_id", Generation: 2, Hostname: "route.example", Profile: "tlsserver", State: state,
			Challenge: &corev1.CertificateChallenge{
				Id: "challenge", Hostname: "route.example", Digest: base64.RawURLEncoding.EncodeToString(digest[:]),
				ExpiresAt: time.Now().Add(time.Hour),
			},
		}
		if err := validateCertificateOrder(order, "route_id", 2, "route.example", "tlsserver", "cert_id"); err != nil {
			t.Fatalf("state %q: %v", state, err)
		}
	}
}

func TestRenewalFailureKeepsCurrentCertificateServing(t *testing.T) {
	previousRetry := renewalRetry
	renewalRetry = 5 * time.Millisecond
	t.Cleanup(func() { renewalRetry = previousRetry })
	store, err := clientstate.New(filepath.Join(t.TempDir(), "state"), "https://core.example")
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
		time.Now().Add(-time.Millisecond), "cert_current", 1,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := state.MarkInstalled("route.example", material.OrderID, material.Generation); err != nil {
		t.Fatal(err)
	}
	material, found, err := state.Current("route.example")
	if err != nil || !found || !material.Installed {
		t.Fatalf("installed current = %+v, %v, %v", material, found, err)
	}
	leaseToken, _, _, err := credentials.NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	core := &renewalFailureCore{publicCoreStub: new(publicCoreStub), called: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	var logs atomic.Int32
	result := make(chan error, 1)
	go func() {
		result <- runLease(ctx, PublicConfig{
			Core: core, Target: "http://127.0.0.1:3000", State: store, ACMEProfile: "tlsserver",
			RelayProfile: "test", Profiles: map[string]*tailcfg.DERPRegion{"test": {
				RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
			}}, DrainTime: 20 * time.Millisecond, Logf: func(string, ...any) { logs.Add(1) },
		}, corev1.LeaseSetup{
			Route:      corev1.Route{Id: "route_0123456789abcdef0123456789abcdef", Hostname: "route.example"},
			Lease:      corev1.RouteLease{Generation: 1, ExpiresAt: time.Now().Add(time.Minute)},
			LeaseToken: leaseToken.String(), IngressPublicKey: key.NewNode().Public().String(),
		}, state, func() error { return nil })
	}()
	select {
	case <-core.called:
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
	if errors.Is(err, coreclient.ErrCertificateState) || core.orderCalls == 0 || logs.Load() == 0 {
		t.Fatalf("runLease error = %v, renewal calls = %d, logs = %d", err, core.orderCalls, logs.Load())
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
		AllowedClient: key.NewNode().Public(), RelayProfile: "test", Profiles: map[string]*tailcfg.DERPRegion{"test": {
			RegionID: 1, Nodes: []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return route
}

type publicCoreStub struct {
	createCalls     int
	createErr       error
	createErrors    []error
	createSetups    []corev1.LeaseSetup
	created         corev1.CreateRouteRequest
	routes          []corev1.Route
	acquired        corev1.LeaseSetup
	acquiredToken   credentials.RouteToken
	acquireErr      error
	acquireCalls    int
	heartbeatCalls  int
	heartbeatErrors []error
}

type issuanceCore struct {
	*publicCoreStub
	t                 *testing.T
	orders            int
	readyCalls        int
	removedCalls      int
	installedCalls    int
	lastCSR           *x509.CertificateRequest
	currentOrderID    string
	currentGeneration int
	certificate       string
	notBefore         time.Time
	notAfter          time.Time
	renewAt           time.Time
	reuseCurrent      bool
	installErrors     []error
	terminalFirst     bool
}

type renewalFailureCore struct {
	*publicCoreStub
	orderCalls int
	called     chan struct{}
}

type unavailableCertificateCore struct{ *publicCoreStub }

func (*unavailableCertificateCore) CreateCertificateOrder(
	context.Context,
	string,
	uint64,
	credentials.LeaseToken,
	string,
	[]byte,
) (corev1.CertificateOrder, error) {
	return corev1.CertificateOrder{}, coreclient.ErrUnavailable
}

func (c *renewalFailureCore) CreateCertificateOrder(
	context.Context,
	string,
	uint64,
	credentials.LeaseToken,
	string,
	[]byte,
) (corev1.CertificateOrder, error) {
	c.orderCalls++
	select {
	case c.called <- struct{}{}:
	default:
	}
	return corev1.CertificateOrder{}, coreclient.ErrCertificateState
}

func (c *issuanceCore) CreateCertificateOrder(
	_ context.Context,
	_ string,
	generation uint64,
	_ credentials.LeaseToken,
	_ string,
	csrDER []byte,
) (corev1.CertificateOrder, error) {
	c.t.Helper()
	c.orders++
	c.currentOrderID = fmt.Sprintf("cert_%032x", c.orders)
	c.currentGeneration = int(generation)
	request, err := x509.ParseCertificateRequest(csrDER)
	if err != nil || request.CheckSignature() != nil {
		c.t.Fatalf("CSR = %v, %v", request, err)
	}
	c.lastCSR = request
	if c.terminalFirst && c.orders == 1 {
		return corev1.CertificateOrder{
			Id: c.currentOrderID, RouteId: "route_0123456789abcdef0123456789abcdef",
			Generation: c.currentGeneration, Hostname: "route.example", Profile: "tlsserver", State: corev1.Blocked,
			CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}, nil
	}
	if c.reuseCurrent {
		return corev1.CertificateOrder{
			Id: c.currentOrderID, RouteId: "route_0123456789abcdef0123456789abcdef",
			Generation: c.currentGeneration, Hostname: "route.example", Profile: "tlsserver", State: corev1.WaitingForInstall,
			CertificatePem: &c.certificate, NotBefore: &c.notBefore, NotAfter: &c.notAfter,
			RenewAt: &c.renewAt, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}, nil
	}
	digest := sha256.Sum256([]byte(fmt.Sprintf("key authorization %d", c.orders)))
	return corev1.CertificateOrder{
		Id: c.currentOrderID, RouteId: "route_0123456789abcdef0123456789abcdef",
		Generation: c.currentGeneration, Hostname: "route.example", Profile: "tlsserver", State: corev1.WaitingForChallenge,
		Challenge: &corev1.CertificateChallenge{
			Id: fmt.Sprintf("challenge-%d", c.orders), Hostname: "route.example", Digest: base64.RawURLEncoding.EncodeToString(digest[:]),
			ExpiresAt: time.Now().Add(time.Hour),
		},
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}, nil
}

func (c *issuanceCore) CertificateChallengeReady(
	_ context.Context,
	_ string,
	_ credentials.LeaseToken,
) (corev1.CertificateOrder, error) {
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
	return corev1.CertificateOrder{
		Id: c.currentOrderID, RouteId: "route_0123456789abcdef0123456789abcdef",
		Generation: c.currentGeneration, Hostname: "route.example", Profile: "tlsserver", State: corev1.WaitingForInstall,
		CertificatePem: &c.certificate, NotBefore: &c.notBefore, NotAfter: &c.notAfter,
		RenewAt: &c.renewAt, CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}, nil
}

func (c *issuanceCore) CertificateChallengeRemoved(context.Context, string, credentials.LeaseToken) error {
	c.removedCalls++
	return nil
}

func (c *issuanceCore) CertificateInstalled(context.Context, string, uint64, string, credentials.LeaseToken) error {
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

func (c *publicCoreStub) CreateRoute(_ context.Context, request corev1.CreateRouteRequest) (corev1.LeaseSetup, error) {
	index := c.createCalls
	c.createCalls++
	c.created = request
	if index < len(c.createErrors) {
		var setup corev1.LeaseSetup
		if index < len(c.createSetups) {
			setup = c.createSetups[index]
		}
		return setup, c.createErrors[index]
	}
	return corev1.LeaseSetup{}, c.createErr
}

func (c *publicCoreStub) ListRoutes(context.Context) ([]corev1.Route, error) {
	return c.routes, nil
}

func (c *publicCoreStub) AcquireLease(
	_ context.Context,
	_ string,
	token credentials.RouteToken,
) (corev1.LeaseSetup, error) {
	c.acquireCalls++
	c.acquiredToken = token
	return c.acquired, c.acquireErr
}

func (*publicCoreStub) RegisterTransport(
	context.Context,
	string,
	uint64,
	credentials.LeaseToken,
	transportv1.TailcatDescriptor,
) error {
	return nil
}

func (*publicCoreStub) Ready(context.Context, string, uint64, credentials.LeaseToken) error {
	return nil
}

func (c *publicCoreStub) Heartbeat(
	context.Context,
	string,
	uint64,
	credentials.LeaseToken,
) (corev1.HeartbeatResponse, error) {
	index := c.heartbeatCalls
	c.heartbeatCalls++
	if index < len(c.heartbeatErrors) && c.heartbeatErrors[index] != nil {
		return corev1.HeartbeatResponse{}, c.heartbeatErrors[index]
	}
	return corev1.HeartbeatResponse{ExpiresAt: time.Now().Add(time.Minute)}, nil
}

func (*publicCoreStub) CreateCertificateOrder(
	context.Context,
	string,
	uint64,
	credentials.LeaseToken,
	string,
	[]byte,
) (corev1.CertificateOrder, error) {
	return corev1.CertificateOrder{}, nil
}

func (*publicCoreStub) CertificateChallengeReady(
	context.Context,
	string,
	credentials.LeaseToken,
) (corev1.CertificateOrder, error) {
	return corev1.CertificateOrder{}, nil
}

func (*publicCoreStub) CertificateChallengeRemoved(context.Context, string, credentials.LeaseToken) error {
	return nil
}

func (*publicCoreStub) CertificateInstalled(
	context.Context,
	string,
	uint64,
	string,
	credentials.LeaseToken,
) error {
	return nil
}
