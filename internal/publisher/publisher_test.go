package publisher

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/diagnostic"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestCreateOrLoadRouteReusesDurableRoute(t *testing.T) {
	want := controlv1.Route{
		Id: "route_existing", TeamId: "team_1", DomainId: "domain_1", MembershipId: pointer("membership_1"),
		CanonicalHostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		LifecycleState: controlv1.Enabled,
	}
	control := &publisherControlStub{routes: []controlv1.Route{want}}
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
	control := &publisherControlStub{routes: []controlv1.Route{{
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
	control := &publisherControlStub{routes: []controlv1.Route{{
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
	control := &publisherControlStub{routes: []controlv1.Route{{
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
	control := &publisherControlStub{createErr: controlclient.ErrNameUnavailable}
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
	control := &publisherControlStub{updateErr: controlclient.ErrStatusConflict}
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
	control := &publisherControlStub{routeSessionErr: controlclient.ErrStatusConflict}
	_, err := createRouteSession(t.Context(), Config{Control: control}, controlv1.Route{Id: "route_1"})
	if code, ok := diagnostic.CodeOf(err); !ok || code != diagnostic.RouteConflict ||
		!errors.Is(err, controlclient.ErrStatusConflict) {
		t.Fatalf("create route session error = %v, diagnostic = %q", err, code)
	}
}

func TestCreateOrLoadRouteCreatesTeamScopedRoute(t *testing.T) {
	control := &publisherControlStub{}
	allowed := []string{"192.0.2.0/24"}
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
		control.created.DomainId != "domain_1" || control.created.CanonicalHostname != "demo.example" {
		t.Fatalf("route = %#v, create request = %#v", got, control.created)
	}
}

func TestHeartbeatFallbackSkipsPolicyDenialObservation(t *testing.T) {
	control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.SessionToken) (controlv1.RouteSessionHeartbeat, error) {
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
	control := &publisherControlStub{heartbeat: func(context.Context, string, uint64, credentials.SessionToken) (controlv1.RouteSessionHeartbeat, error) {
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

func TestRunRequiresCertificatePlan(t *testing.T) {
	connector := muxsession.ConnectorFunc(func(context.Context, muxsession.Endpoint) (muxsession.Session, error) {
		return nil, errors.New("unexpected connection")
	})
	err := Run(t.Context(), Config{
		Control: &publisherControlStub{}, Hostname: "demo.example", Target: "http://127.0.0.1:3000",
		QUICConnector: connector, TCPConnector: connector,
	})
	if err == nil || err.Error() != "publisher: certificate plan is required" {
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
	routes          []controlv1.Route
	created         *controlv1.CreateRouteRequest
	updated         *controlv1.UpdateRouteRequest
	deleted         *controlv1.Route
	listCalls       int
	heartbeat       func(context.Context, string, uint64, credentials.SessionToken) (controlv1.RouteSessionHeartbeat, error)
	createErr       error
	updateErr       error
	routeSessionErr error
}

func (s *publisherControlStub) CreateRoute(_ context.Context, body controlv1.CreateRouteRequest, _ string) (controlv1.Route, error) {
	s.created = &body
	if s.createErr != nil {
		return controlv1.Route{}, s.createErr
	}
	return controlv1.Route{
		Id: "route_created", TeamId: body.TeamId, DomainId: body.DomainId, MembershipId: body.MembershipId,
		CanonicalHostname: body.CanonicalHostname, RouteScope: body.RouteScope, Target: body.Target, NextRouteVersion: 1,
		Ephemeral: body.Ephemeral != nil && *body.Ephemeral,
	}, nil
}

func (s *publisherControlStub) ListRoutes(context.Context, string) ([]controlv1.Route, error) {
	s.listCalls++
	return s.routes, nil
}

func (s *publisherControlStub) UpdateRoute(_ context.Context, _ string, body controlv1.UpdateRouteRequest) (controlv1.Route, error) {
	s.updated = &body
	if s.updateErr != nil {
		return controlv1.Route{}, s.updateErr
	}
	route := s.routes[0]
	route.Target = body.Target
	route.AllowedIpPrefixes = &body.AllowedIpPrefixes
	return route, nil
}

func (s *publisherControlStub) DeleteRoute(_ context.Context, route controlv1.Route) error {
	s.deleted = &route
	return nil
}

func (s *publisherControlStub) CreateRouteSession(context.Context, string, string) (controlv1.RouteSessionSetup, error) {
	if s.routeSessionErr != nil {
		return controlv1.RouteSessionSetup{}, s.routeSessionErr
	}
	return controlv1.RouteSessionSetup{}, errors.New("not implemented")
}

func (*publisherControlStub) CloseRouteSession(context.Context, string, credentials.SessionToken) error {
	return nil
}

func (*publisherControlStub) Ready(context.Context, string, uint64, credentials.SessionToken) error {
	return nil
}

func (s *publisherControlStub) Heartbeat(ctx context.Context, routeID string, version uint64, token credentials.SessionToken) (controlv1.RouteSessionHeartbeat, error) {
	if s.heartbeat != nil {
		return s.heartbeat(ctx, routeID, version, token)
	}
	return controlv1.RouteSessionHeartbeat{}, errors.New("not implemented")
}

func (*publisherControlStub) CreateCertificateIssuance(context.Context, string, uint64, credentials.SessionToken, []byte, string) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) CertificateIssuance(context.Context, string, credentials.SessionToken) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) CertificateChallengeReady(context.Context, string, credentials.SessionToken) (controlv1.CertificateIssuance, error) {
	return controlv1.CertificateIssuance{}, errors.New("not implemented")
}

func (*publisherControlStub) CertificateChallengeRemoved(context.Context, string, credentials.SessionToken) error {
	return nil
}

func (*publisherControlStub) CertificateInstalled(context.Context, string, uint64, string, time.Time, credentials.SessionToken) error {
	return nil
}

func pointer[T any](value T) *T { return &value }
