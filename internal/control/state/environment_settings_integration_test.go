package state

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
)

func TestIntegrationEnvironmentOperationalSettingsStayEnvironmentOwned(t *testing.T) {
	f := newEnvironmentPublisherGrantFixture(t)
	settings := &EnvironmentServiceHTTP{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24"}}, Limits: &config.WorkLimits{Total: new(50), Concurrency: new(2)}}
	request := f.creation
	request.Name, request.IdempotencyKey = "configured", "configured"
	request.DomainID, request.Public = f.environment.DomainID, true
	request.Targets = EnvironmentTargets{"api": {Address: "configured.internal:3000", HTTP: settings}}
	created, err := f.d.CreateEnvironment(t.Context(), request)
	if err != nil || created.DomainID != request.DomainID || !created.Public || len(created.Services) != 1 || !created.Services[0].Public || !reflect.DeepEqual(created.Targets["api"].HTTP, settings) {
		t.Fatal("environment lost explicit domain, reachability or HTTP settings", err)
	}
	changedIntent := request
	changedIntent.Public = false
	if _, err := f.d.CreateEnvironment(t.Context(), changedIntent); !errors.Is(err, ErrServiceConflict) {
		t.Fatal("creation replay changed its original reachability intent", err)
	}
	beforeSibling, err := f.d.GetEnvironment(t.Context(), f.r.TeamID, f.r.ProjectKey, f.environment.ID, f.r.ActorID)
	if err != nil {
		t.Fatal(err)
	}
	service := created.Services[0]
	updated, err := f.d.ApplyEnvironment(t.Context(), ApplyEnvironmentRequest{TeamID: f.r.TeamID, ProjectKey: f.r.ProjectKey, ActorID: f.r.ActorID, Now: f.now,
		EnvironmentApplication: EnvironmentApplication{EnvironmentID: created.ID, ExpectedRevision: created.MutationRevision, DefinitionRevision: created.AppliedDefinitionRevision, Public: new(false)}})
	if err != nil || updated.Public || updated.Services[0].Public || updated.DomainID != created.DomainID || updated.Services[0].ServiceID != service.ServiceID || updated.Services[0].Hostname != service.Hostname || updated.Services[0].Port != service.Port || updated.MutationRevision <= created.MutationRevision || updated.ConfigurationHash == created.ConfigurationHash || !reflect.DeepEqual(updated.Targets, created.Targets) {
		t.Fatal("reachability apply changed endpoints or dropped retained approvals", err)
	}
	q := controlstatedb.New(f.d.pool)
	stored, err := f.d.serviceHTTPSettings(t.Context(), q, service.ServiceID)
	if err != nil || !reflect.DeepEqual(stored, settings) {
		t.Fatal("HTTP policy did not come from the pinned environment", err)
	}
	if err := f.d.serviceHTTPSourceAllowed(t.Context(), q, service.ServiceID, netip.MustParseAddr("192.0.2.10")); err != nil {
		t.Fatal("approved visitor source rejected", err)
	}
	if err := f.d.serviceHTTPSourceAllowed(t.Context(), q, service.ServiceID, netip.MustParseAddr("198.51.100.10")); !errors.Is(err, ErrServiceAccess) {
		t.Fatal("environment IP policy was not enforced on service protocol traffic", err)
	}
	afterSibling, err := f.d.GetEnvironment(t.Context(), f.r.TeamID, f.r.ProjectKey, f.environment.ID, f.r.ActorID)
	if err != nil || beforeSibling.ID != afterSibling.ID || beforeSibling.MutationRevision != afterSibling.MutationRevision || beforeSibling.ConfigurationHash != afterSibling.ConfigurationHash || beforeSibling.DomainID != afterSibling.DomainID || beforeSibling.Public != afterSibling.Public || !reflect.DeepEqual(beforeSibling.Targets, afterSibling.Targets) || !reflect.DeepEqual(beforeSibling.Services, afterSibling.Services) {
		t.Fatal("another environment's operational settings changed", err)
	}
	var grants int
	if err := f.d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.publisher_grants WHERE service_id=$1)+(SELECT count(*) FROM control.visitor_grants WHERE service_id=$1)`, service.ServiceID).Scan(&grants); err != nil || grants != 0 {
		t.Fatal("public reachability manufactured visitor or publisher authorization", grants, err)
	}
}
