package publication

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/0xcadams/tnl/internal/coreclient"
	"github.com/0xcadams/tnl/internal/credentials"
	"github.com/0xcadams/tnl/pkg/protocol/corev1"
	"github.com/0xcadams/tnl/pkg/protocol/transportv1"
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
	heartbeatCalls  int
	heartbeatErrors []error
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
