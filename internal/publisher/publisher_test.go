package publisher

import (
	"context"
	"errors"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestCreateOrLoadRouteReusesDurableRoute(t *testing.T) {
	want := controlv1.Route{
		Id: "route_existing", TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"),
		CanonicalHostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		LifecycleState: controlv1.Enabled,
	}
	control := &publisherControlStub{allowed: []string{"list"}, routes: []controlv1.Route{want}}
	got, created, err := createOrLoadRoute(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Id != want.Id || created || control.created != nil || control.updated != nil {
		t.Fatalf("route = %#v, create request = %#v, update request = %#v", got, control.created, control.updated)
	}
}

func TestCreateOrLoadRouteReconcilesTargetAndIPPolicy(t *testing.T) {
	existingPolicy := []string{"192.0.2.0/24"}
	control := &publisherControlStub{allowed: []string{"list", "update"}, routes: []controlv1.Route{{
		Id: "route_existing", TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"),
		CanonicalHostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		AllowedIpPrefixes: &existingPolicy, LifecycleState: controlv1.Enabled,
	}}}
	wantPolicy := []string{"198.51.100.0/24"}
	got, created, err := createOrLoadRoute(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:4000",
		AllowedIPPrefixes: wantPolicy,
	})
	if err != nil {
		t.Fatal(err)
	}
	if created || control.updated == nil || control.updated.Target != "http://127.0.0.1:4000" ||
		!slices.Equal(control.updated.AllowedIpPrefixes, wantPolicy) ||
		got.Target != "http://127.0.0.1:4000" {
		t.Fatalf("route = %#v, update request = %#v", got, control.updated)
	}
}

func TestCreateOrLoadRouteRejectsDifferentIdentityOrLifecycle(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"list"}, routes: []controlv1.Route{{
		Id: "route_existing", TeamId: "team_1", DomainId: "domain_other",
		CanonicalHostname: "demo.example", RouteScope: controlv1.Shared, Target: "http://127.0.0.1:3000",
	}}}
	_, _, err := createOrLoadRoute(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", Hostname: "demo.example",
		RouteScope: controlv1.Shared, Target: "http://127.0.0.1:3000",
	})
	if err == nil || control.updated != nil {
		t.Fatalf("mismatched route error = %v, update request = %#v", err, control.updated)
	}
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.RouteConflict {
		t.Fatalf("mismatched route diagnostic = %q, %t", code, ok)
	}
}

func TestCreateOrLoadRouteNeverReusesEphemeralRoute(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"create"}, routes: []controlv1.Route{{
		Id: "route_existing", CanonicalHostname: "demo.example", Ephemeral: true,
	}}}
	route, created, err := createOrLoadRoute(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000", Ephemeral: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || route.Id != "route_created" || control.listCalls != 0 || control.created == nil {
		t.Fatalf("route = %#v, created = %t, list calls = %d", route, created, control.listCalls)
	}
}

func TestReconcileRouteRejectsSuspendedRoute(t *testing.T) {
	_, err := reconcileRoute(t.Context(), Config{
		Control: &publisherControlStub{}, Target: "http://127.0.0.1:3000",
	}, controlv1.Route{Id: "route_suspended", LifecycleState: controlv1.Suspended})
	if err == nil || err.Error() != "publisher: route route_suspended is not enabled" {
		t.Fatalf("reconcile error = %v", err)
	}
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.RouteConflict {
		t.Fatalf("reconcile diagnostic = %q, %t", code, ok)
	}
}

func TestCreateOrLoadRouteClassifiesHostnameConflict(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"create"}, createErr: controlclient.ErrNameUnavailable}
	_, _, err := createOrLoadRoute(t.Context(), Config{
		Control: control, TeamID: "team_1", DomainID: "domain_1", MembershipID: "membership_1",
		Hostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000", Ephemeral: true,
	})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.RouteConflict ||
		!errors.Is(err, controlclient.ErrNameUnavailable) {
		t.Fatalf("create route error = %v, diagnostic = %q", err, code)
	}
}

func TestReconcileRouteClassifiesUpdateConflict(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"update"}, updateErr: controlclient.ErrStatusConflict}
	_, err := reconcileRoute(t.Context(), Config{
		Control: control, Target: "http://127.0.0.1:4000",
	}, controlv1.Route{
		Id: "route_existing", LifecycleState: controlv1.Enabled, Target: "http://127.0.0.1:3000",
	})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.RouteConflict ||
		!errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("update route error = %v, diagnostic = %q", err, code)
	}
}

func TestCreateRouteSessionClassifiesLifecycleConflict(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"create_session"}, routeSessionErr: controlclient.ErrStatusConflict}
	_, err := createRouteSession(t.Context(), Config{Control: control}, controlv1.Route{Id: "route_1"})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.RouteConflict ||
		!errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("create route session error = %v, diagnostic = %q", err, code)
	}
}

func TestCreateOrLoadRouteCreatesTeamScopedRoute(t *testing.T) {
	control := &publisherControlStub{allowed: []string{"list", "create"}}
	allowed := []string{"2001:db8::1/64", "192.0.2.9/24"}
	wantAllowed := []string{"192.0.2.0/24", "2001:db8::/64"}
	got, created, err := createOrLoadRoute(t.Context(), Config{
		Control: control, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		Hostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: allowed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !created || got.Id == "" || control.created == nil || control.created.TeamId != "team_1" ||
		control.created.MembershipId == nil || *control.created.MembershipId != "membership_1" ||
		control.created.DomainId != "domain_1" || control.created.CanonicalHostname != "demo.example" ||
		control.created.AllowedIpPrefixes == nil || !slices.Equal(*control.created.AllowedIpPrefixes, wantAllowed) ||
		!slices.Equal(allowed, []string{"2001:db8::1/64", "192.0.2.9/24"}) {
		t.Fatalf("route = %#v, create request = %#v", got, control.created)
	}
}

func TestHeartbeatFallbackSkipsPolicyDenialObservation(t *testing.T) {
	control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
		return controlv1.RouteSessionHeartbeat{}, controlclient.ErrUnavailable
	}}
	response, observed, err := heartbeatResponseOnce(
		t.Context(), control, "session_1", 1, "session-token", time.Now().Add(time.Minute),
	)
	if err != nil || observed || response.PolicyDenials != 0 {
		t.Fatalf("fallback = %#v, observed = %t, error = %v", response, observed, err)
	}
}

func TestExpiredHeartbeatLeavesStaleSessionConflictUnclassified(t *testing.T) {
	control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
		return controlv1.RouteSessionHeartbeat{}, controlclient.ErrUnavailable
	}}
	_, _, err := heartbeatResponseOnce(
		t.Context(), control, "session_1", 1, "session-token", time.Now().Add(-time.Second),
	)
	if !errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("heartbeat error = %v", err)
	}
	if code, ok := diagnostic.CodeOf(err); ok {
		t.Fatalf("stale route-session conflict was classified as %q", code)
	}
}

func TestHeartbeatIgnoresUpdateFailureAfterCancellation(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
			return controlv1.RouteSessionHeartbeat{
				RouteSession:         controlv1.RouteSession{ExpiresAt: time.Now().Add(time.Minute)},
				PublisherConnections: []controlv1.ConnectionAssignment{{PublisherConnectionId: "publisher_connection_1"}},
			}, nil
		}}
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		updateStarted := make(chan struct{})
		releaseUpdate := make(chan struct{})
		done := make(chan error, 1)
		joined := make(chan struct{})
		var once sync.Once
		release := func() { once.Do(func() { close(releaseUpdate) }) }
		go func() {
			defer close(joined)
			done <- heartbeatSessionAfterUpdate(
				ctx, control, "route_session_1", 1, "route-session-token", time.Now().Add(time.Minute),
				func([]controlv1.ConnectionAssignment) error {
					close(updateStarted)
					<-releaseUpdate
					return errors.New("connection manager is draining")
				}, nil, 0,
			)
		}()
		t.Cleanup(func() { cancel(); release(); awaitPublisherTest(t, joined) })
		select {
		case <-updateStarted:
		case <-time.After(heartbeatInterval + time.Second):
			t.Fatal("heartbeat did not begin the connection update")
		}
		cancel()
		release()
		if err := <-done; err != nil {
			t.Fatalf("heartbeat returned a shutdown race: %v", err)
		}
	})
}

func TestRunRequiresAuthoritativeSessionCertificatePlan(t *testing.T) {
	control, _, _ := newCertificateTransactionTest(t)
	config := startCertificateTLSYamuxHarness(t, control)
	control.setup.CertificatePlan = controlv1.CertificatePlan{}
	err := Run(t.Context(), config)
	if err == nil || err.Error() != "publisher: server returned an invalid certificate plan" {
		t.Fatalf("Run error = %v", err)
	}
}

func TestRunRejectsNegativeOptionalDurations(t *testing.T) {
	t.Parallel()
	for _, config := range []Config{
		{Control: &publisherControlStub{}, DrainTime: -time.Second},
		{Control: &publisherControlStub{}, FallbackDelay: -time.Second},
	} {
		if err := Run(t.Context(), config); err == nil || err.Error() != "publisher: drain time and fallback delay cannot be negative" {
			t.Fatalf("Run error = %v", err)
		}
	}
}

func TestRunRejectsNegativeProvisioningStalledDelay(t *testing.T) {
	err := Run(t.Context(), Config{
		Control: &publisherControlStub{}, ProvisioningStalledDelay: -time.Second,
	})
	if err == nil || err.Error() != "publisher: provisioning stalled delay cannot be negative" {
		t.Fatalf("Run error = %v", err)
	}
}

func TestObserveProvisioningStallFiresOnceAndCancels(t *testing.T) {
	setup := controlv1.RouteSessionSetup{
		Route:        controlv1.Route{Id: "route_1", CanonicalHostname: "demo.example"},
		RouteSession: controlv1.RouteSession{RouteVersion: 4},
	}
	var events []Event
	config := Config{ProvisioningStalledDelay: 10 * time.Millisecond, Observe: func(event Event) error {
		events = append(events, event)
		return nil
	}}
	if err := observeProvisioningStall(t.Context(), config, setup); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Type != EventProvisioningStalled || events[0].RouteVersion != 4 ||
		events[0].Hostname != "demo.example" {
		t.Fatalf("provisioning events = %#v", events)
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := observeProvisioningStall(ctx, config, setup); err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 {
		t.Fatalf("canceled warning emitted events = %#v", events)
	}
}

func TestObserveHeartbeatPolicyDenialsReportsCumulativeIncreases(t *testing.T) {
	var events []Event
	config := Config{Observe: func(event Event) error {
		events = append(events, event)
		return nil
	}}
	setup := controlv1.RouteSessionSetup{
		Route:        controlv1.Route{Id: "route_1", CanonicalHostname: "demo.example"},
		RouteSession: controlv1.RouteSession{RouteVersion: 3},
	}
	var previous uint64
	for _, count := range []int64{0, 2, 2, 5} {
		if err := observeHeartbeatPolicyDenials(config, setup, count, &previous); err != nil {
			t.Fatal(err)
		}
	}
	if len(events) != 2 || events[0].PolicyDenials != 2 || events[1].PolicyDenials != 5 ||
		events[1].Type != EventIPPolicyDenials || events[1].RouteVersion != 3 {
		t.Fatalf("policy denial events = %#v", events)
	}
	decreased := int64(4)
	if err := observeHeartbeatPolicyDenials(config, setup, decreased, &previous); err == nil {
		t.Fatal("decreased policy denial count was accepted")
	}
}

type publisherControlStub struct {
	allowed         []string
	calls           []string
	routes          []controlv1.Route
	created         *controlv1.CreateRouteRequest
	updated         *controlv1.UpdateRouteRequest
	deleted         *string
	listCalls       int
	heartbeat       func(context.Context, string, uint64, credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error)
	createErr       error
	updateErr       error
	routeSessionErr error
}

func (s *publisherControlStub) record(operation string) {
	if !slices.Contains(s.allowed, operation) {
		panic("unexpected publisher control operation: " + operation)
	}
	s.calls = append(s.calls, operation)
}

func (s *publisherControlStub) CreateRoute(_ context.Context, body controlv1.CreateRouteRequest, _ string) (controlv1.Route, error) {
	s.record("create")
	s.created = &body
	if s.createErr != nil {
		return controlv1.Route{}, s.createErr
	}
	route := controlv1.Route{
		Id: "route_created", TeamId: body.TeamId, DomainId: body.DomainId, MembershipId: body.MembershipId,
		CanonicalHostname: body.CanonicalHostname, RouteScope: body.RouteScope, Target: body.Target, NextRouteVersion: 1,
		Ephemeral: body.Ephemeral != nil && *body.Ephemeral,
	}
	s.routes = append(s.routes, route)
	return route, nil
}

func (s *publisherControlStub) ListRoutes(context.Context, string) ([]controlv1.Route, error) {
	s.record("list")
	s.listCalls++
	return slices.Clone(s.routes), nil
}

func (s *publisherControlStub) UpdateRoute(_ context.Context, id string, body controlv1.UpdateRouteRequest) (controlv1.Route, error) {
	s.record("update")
	s.updated = &body
	if s.updateErr != nil {
		return controlv1.Route{}, s.updateErr
	}
	for index := range s.routes {
		if s.routes[index].Id == id {
			s.routes[index].Target = body.Target
			s.routes[index].AllowedIpPrefixes = &body.AllowedIpPrefixes
			return s.routes[index], nil
		}
	}
	return controlv1.Route{}, errors.New("update of unknown fixture route")
}

func (s *publisherControlStub) DeleteRoute(_ context.Context, routeID string) error {
	s.record("delete")
	s.deleted = &routeID
	s.routes = slices.DeleteFunc(s.routes, func(existing controlv1.Route) bool { return existing.Id == routeID })
	return nil
}

func (s *publisherControlStub) CreateRouteSession(context.Context, string, string) (controlv1.RouteSessionSetup, error) {
	s.record("create_session")
	if s.routeSessionErr != nil {
		return controlv1.RouteSessionSetup{}, s.routeSessionErr
	}
	return controlv1.RouteSessionSetup{}, errors.New("not implemented")
}

func (*publisherControlStub) CloseRouteSession(context.Context, string, credentials.RouteSessionToken) error {
	panic("unexpected CloseRouteSession")
}

func (*publisherControlStub) MarkRouteSessionReady(context.Context, string, uint64, credentials.RouteSessionToken) error {
	panic("unexpected MarkRouteSessionReady")
}

func (s *publisherControlStub) HeartbeatRouteSession(ctx context.Context, routeID string, version uint64, token credentials.RouteSessionToken) (controlv1.RouteSessionHeartbeat, error) {
	if s.heartbeat != nil {
		return s.heartbeat(ctx, routeID, version, token)
	}
	return controlv1.RouteSessionHeartbeat{}, errors.New("not implemented")
}

func (*publisherControlStub) CreateCertificateIssuance(context.Context, string, uint64, credentials.RouteSessionToken, []byte, string) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) GetCertificateIssuance(context.Context, string, credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) MarkCertificateChallengeReady(context.Context, string, credentials.RouteSessionToken) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) MarkCertificateChallengeRemoved(context.Context, string, credentials.RouteSessionToken) error {
	panic("unexpected MarkCertificateChallengeRemoved")
}

func (*publisherControlStub) MarkRouteSessionCertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.RouteSessionToken) error {
	panic("unexpected MarkRouteSessionCertificateInstalled")
}

func pointer[T any](value T) *T { return &value }
