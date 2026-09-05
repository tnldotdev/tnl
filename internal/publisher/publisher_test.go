package publisher

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestCreateOrLoadRouteReusesDurableRoute(t *testing.T) {
	want := controlv1.Route{Id: "route_existing", TeamId: "team_1", CanonicalHostname: "demo.example"}
	control := &publisherControlStub{routes: []controlv1.Route{want}}
	got, err := createOrLoadRoute(t.Context(), Config{Control: control, TeamID: "team_1", Hostname: "demo.example"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Id != want.Id || control.created != nil {
		t.Fatalf("route = %#v, create request = %#v", got, control.created)
	}
}

func TestCreateOrLoadRouteCreatesTeamScopedRoute(t *testing.T) {
	control := &publisherControlStub{}
	allowed := []string{"192.0.2.0/24"}
	got, err := createOrLoadRoute(t.Context(), Config{
		Control: control, TeamID: "team_1", MembershipID: "membership_1", DomainID: "domain_1",
		Hostname: "demo.example", RouteScope: controlv1.Member, Target: "http://127.0.0.1:3000",
		AllowedIPPrefixes: allowed,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Id == "" || control.created == nil || control.created.TeamId != "team_1" ||
		control.created.MembershipId == nil || *control.created.MembershipId != "membership_1" ||
		control.created.DomainId != "domain_1" || control.created.CanonicalHostname != "demo.example" {
		t.Fatalf("route = %#v, create request = %#v", got, control.created)
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

type publisherControlStub struct {
	routes  []controlv1.Route
	created *controlv1.CreateRouteRequest
}

func (s *publisherControlStub) CreateRoute(_ context.Context, body controlv1.CreateRouteRequest, _ string) (controlv1.Route, error) {
	s.created = &body
	return controlv1.Route{
		Id: "route_created", TeamId: body.TeamId, DomainId: body.DomainId, MembershipId: body.MembershipId,
		CanonicalHostname: body.CanonicalHostname, RouteScope: body.RouteScope, Target: body.Target, NextRouteVersion: 1,
	}, nil
}

func (s *publisherControlStub) ListRoutes(context.Context, string) ([]controlv1.Route, error) {
	return s.routes, nil
}

func (*publisherControlStub) CreateRouteSession(context.Context, controlv1.Route, controlv1.CreateRouteSessionRequest, uint64, string) (controlv1.RouteSessionSetup, error) {
	return controlv1.RouteSessionSetup{}, errors.New("not implemented")
}

func (*publisherControlStub) CloseRouteSession(context.Context, string, credentials.SessionToken) error {
	return nil
}

func (*publisherControlStub) Ready(context.Context, string, uint64, credentials.SessionToken) error {
	return nil
}

func (*publisherControlStub) Heartbeat(context.Context, string, uint64, credentials.SessionToken) (controlv1.RouteSessionHeartbeat, error) {
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
