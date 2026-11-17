package controlstatedb_test

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
)

func TestIntegrationServiceEndpointDNSExposure(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	ctx := t.Context()
	url := testutil.NewDisposablePostgresDatabaseURL(t, "service_endpoint_dns")
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
	actor := owner.Identity.Identity.ID
	team := owner.Identity.Memberships[0].TeamID
	readDNS := func(serviceID string) (string, bool, bool) {
		t.Helper()
		var state string
		var public, automated bool
		if err := conn.QueryRow(ctx, `SELECT dns_state,public,dns_automation FROM control.service_endpoints WHERE service_id=$1 AND retired_at IS NULL`, serviceID).
			Scan(&state, &public, &automated); err != nil {
			t.Fatal(err)
		}
		return state, public, automated
	}
	for _, initiallyPublic := range []bool{false, true} {
		name := "private-first"
		if initiallyPublic {
			name = "public-first"
		}
		t.Run(name, func(t *testing.T) {
			config := controlstate.ProjectServiceConfiguration{Protocol: "http", Target: "localhost:3000", Public: &initiallyPublic}
			service, err := d.CreateServiceAt(ctx, team, actor, name, name, controlstate.ServicePlacement{DNSAutomation: true}, now, controlstate.ServiceMetadata{Protocol: "http"}, &config)
			if err != nil {
				t.Fatal(err)
			}
			wantState := "unmanaged"
			if initiallyPublic {
				wantState = "pending"
			}
			if state, public, automated := readDNS(service.ID); state != wantState || public != initiallyPublic || !automated {
				t.Fatalf("initial endpoint = %q public=%t automated=%t", state, public, automated)
			}
			if initiallyPublic {
				if _, err := conn.Exec(ctx, `UPDATE control.service_endpoints SET dns_state='published',dns_available_at=NULL WHERE service_id=$1`, service.ID); err != nil {
					t.Fatal(err)
				}
			}
			config.Public = new(false)
			private, err := d.ConfigureService(ctx, service.ID, actor, service.ServiceMetadata, &config, controlstate.ServiceUpdateConditions{UnconditionalConfiguration: true}, now)
			if err != nil {
				t.Fatal(err)
			}
			wantState = "unmanaged"
			if initiallyPublic {
				wantState = "removing"
			}
			if state, public, automated := readDNS(service.ID); state != wantState || public || !automated || private.TrustRevision != service.TrustRevision {
				t.Fatalf("private endpoint = %q public=%t automated=%t trust=%d", state, public, automated, private.TrustRevision)
			}
			if initiallyPublic {
				work, found, err := d.ClaimServiceEndpointDNSWork(ctx, "dns-worker", now.Add(time.Minute), time.Minute)
				if err != nil || !found || work.ServiceID != service.ID || work.Public || work.State != controlstate.ServiceEndpointDNSRemoving {
					t.Fatalf("public disablement did not queue DNS removal: %+v found=%t error=%v", work, found, err)
				}
			}
			config.Public = new(true)
			again, err := d.ConfigureService(ctx, service.ID, actor, private.ServiceMetadata, &config, controlstate.ServiceUpdateConditions{UnconditionalConfiguration: true}, now)
			if err != nil {
				t.Fatal(err)
			}
			if state, public, automated := readDNS(service.ID); state != "pending" || !public || !automated || again.TrustRevision != service.TrustRevision {
				t.Fatalf("reenabled endpoint = %q public=%t automated=%t trust=%d", state, public, automated, again.TrustRevision)
			}
		})
	}
}
