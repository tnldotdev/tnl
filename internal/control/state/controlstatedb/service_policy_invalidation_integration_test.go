package controlstatedb_test

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/config"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
)

func TestIntegrationServicePolicyInvalidation(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "service_policy_invalidation")
	if err := controlstate.Migrate(ctx, url); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(ctx, url, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })
	now := time.Now().UTC()
	owner, err := controltest.Session(ctx, d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	actor, team := owner.Identity.Identity.ID, owner.Identity.Memberships[0].TeamID
	revision := func(service string) int64 {
		t.Helper()
		var result int64
		if err := conn.QueryRow(ctx, `SELECT revision FROM control.visitor_policies WHERE resource_id=$1`, service).Scan(&result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	t.Run("declaration", func(t *testing.T) {
		declaration := controlstate.ProjectServiceConfiguration{
			Target: "localhost:3000", Public: new(true),
			HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted"}},
		}
		service, err := d.CreateServiceAt(ctx, team, actor, "web", "web", controlstate.ServicePlacement{}, now, controlstate.ServiceMetadata{}, &declaration)
		if err != nil {
			t.Fatal("create HTTP service with explicit visitor policy", err)
		}
		before := revision(service.ID)
		declaration.HTTP = &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}
		if _, err := d.ConfigureService(ctx, service.ID, actor, service.ServiceMetadata, &declaration, controlstate.ServiceUpdateConditions{UnconditionalConfiguration: true}, now); err != nil {
			t.Fatal(err)
		}
		if revision(service.ID) <= before {
			t.Fatal("HTTP policy change did not invalidate service visitors")
		}
	})
	t.Run("project", func(t *testing.T) {
		request := controlstate.ApplyProjectConfigurationRequest{
			TeamID: team, ActorID: actor, ProjectKey: "policy-project", ProjectLabel: "policy-project",
			Deployment: "production", ServiceDeclarations: map[string]string{"web": "http"},
			SourceFingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", Now: now,
			Configuration: controlstate.ProjectConfiguration{Settings: &controlstate.DeploymentSettings{}, Services: map[string]controlstate.ProjectServiceConfiguration{
				"web": {Target: "localhost:3000", Public: new(true), HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted"}}},
			}},
		}
		applied, err := d.ApplyProjectConfiguration(ctx, request)
		if err != nil {
			t.Fatal(err)
		}
		before := revision(applied.Services[0].ServiceID)
		request.ExpectedRevision = applied.Revision
		request.Configuration.Services["web"] = controlstate.ProjectServiceConfiguration{Target: "localhost:3000", Public: new(true), HTTP: &config.HTTPService{Access: &config.Access{Mode: "anonymous"}}}
		if _, err := d.ApplyProjectConfiguration(ctx, request); err != nil {
			t.Fatal("project change used a retired policy function", err)
		}
		if revision(applied.Services[0].ServiceID) <= before {
			t.Fatal("project policy change did not invalidate service visitors")
		}
	})
	t.Run("guest", func(t *testing.T) {
		if err := d.EnsurePrimaryIngressPool(ctx, "192.0.2.10", "", now); err != nil {
			t.Fatal(err)
		}
		issued, err := controlstate.NewGuestTrialCredential(netip.MustParseAddr("192.0.2.7"))
		if err != nil {
			t.Fatal(err)
		}
		trial, err := d.CreateGuestTrial(ctx, issued, "example.test", now)
		if err != nil {
			t.Fatal(err)
		}
		service, err := d.AllocateGuestDemoService(ctx, controlstate.AllocateGuestDemoServiceRequest{
			Credential:     controlstate.GuestCredential{Token: issued.Token, SourceIP: issued.SourceIP},
			IdempotencyKey: "demo", Target: "http://127.0.0.1:3000", Now: now.Add(time.Second),
		})
		if err != nil {
			t.Fatal("allocate guest HTTP service", err)
		}
		before := revision(service.ID)
		if _, err := conn.Exec(ctx, `UPDATE control.guest_trials SET used_ready_ns=1200000000000 WHERE id=$1`, trial.ID); err != nil {
			t.Fatal("guest expiry used a retired policy function", err)
		}
		if revision(service.ID) <= before {
			t.Fatal("guest READY budget expiry did not invalidate service visitors")
		}
	})
	t.Run("endpoint-release-dns", func(t *testing.T) {
		if err := d.ConfigureIngressServicePorts(ctx, controlstate.PrimaryIngressPoolID, []tcpport.Range{{First: 25443, Last: 25443}}); err != nil {
			t.Fatal(err)
		}
		declaration := controlstate.ProjectServiceConfiguration{Protocol: "tcp", Target: "localhost:5432", Public: new(true)}
		service, err := d.CreateServiceAt(ctx, team, actor, "release", "release", controlstate.ServicePlacement{DNSAutomation: true},
			now, controlstate.ServiceMetadata{}, &declaration)
		if err != nil {
			t.Fatal(err)
		}
		declaration.Public = new(false)
		private, err := d.ConfigureService(ctx, service.ID, actor, service.ServiceMetadata, &declaration, controlstate.ServiceUpdateConditions{UnconditionalConfiguration: true}, now)
		if err != nil {
			t.Fatal(err)
		}
		at := now.Add(2 * time.Second)
		release := func() (controlstate.ServiceRecord, error) {
			return d.ReleaseServiceEndpoint(ctx, service.ID, actor, private.EndpointRevision, private.Endpoint.Port, at)
		}
		if _, err := release(); !errors.Is(err, controlstate.ErrServiceEndpointDNSPending) {
			t.Fatal("release skipped outstanding DNS removal", err)
		}
		work, found, err := d.ClaimServiceEndpointDNSWork(ctx, "release", at, time.Minute)
		if err != nil || !found || work.ServiceID != service.ID || work.State != controlstate.ServiceEndpointDNSRemoving {
			t.Fatal("public disablement did not queue DNS removal", work, found, err)
		}
		if _, err := release(); !errors.Is(err, controlstate.ErrServiceEndpointDNSPending) {
			t.Fatal("release accepted an in-flight DNS operation", err)
		}
		work.State, work.AvailableAt = controlstate.ServiceEndpointDNSRemoved, time.Time{}
		if _, err := d.SaveServiceEndpointDNSWork(ctx, work, at); err != nil {
			t.Fatal(err)
		}
		released, err := release()
		if err != nil || released.Endpoint.Port != 0 || released.Endpoint.Public || released.TrustRevision != service.TrustRevision ||
			released.Endpoint.Hostname != service.Endpoint.Hostname || released.EndpointRevision != private.EndpointRevision+1 {
			t.Fatal("completed DNS removal did not release only the public reservation", released, err)
		}
	})
}
