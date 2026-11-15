package state

import (
	"strings"
	"testing"
	"time"
)

func TestIntegrationIngressPoolSavedPublicURLsKeepTheirTeamPlacement(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_pool_claims")
	request := oidcRouteRequest(t, database, now)
	first, err := database.CreateServiceAt(t.Context(), request.TeamID, request.ActingIdentityID, "first", "first",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000", Hostname: request.CanonicalHostname, Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	var teamPool, urlPool string
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.teams WHERE id = $1`, request.TeamID).Scan(&teamPool); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.services WHERE id = $1`, first.ID).Scan(&urlPool); err != nil {
		t.Fatal(err)
	}
	if teamPool != "ingress-a" || urlPool != teamPool {
		t.Fatalf("seeded pool: team %q, service %q", teamPool, urlPool)
	}
	second, err := database.CreateServiceAt(t.Context(), request.TeamID, request.ActingIdentityID, "second", "second",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000", Hostname: "second." + strings.TrimPrefix(request.CanonicalHostname, "demo."), Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.services WHERE id=$1`, second.ID).Scan(&urlPool); err != nil || urlPool != teamPool {
		t.Fatalf("saved service changed ingress placement: %q %v", urlPool, err)
	}
}

func TestIntegrationPublicURLPinsTeamIngressPoolAtCreation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_pool_placement")
	request := oidcRouteRequest(t, database, now)
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.ingress_pools
		(id, ipv4_address, state, created_at, updated_at)
		VALUES ('ingress-b', '203.0.113.20', 'enabled', $1, $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET ingress_pool_id = 'ingress-b' WHERE id = $1`, request.TeamID); err != nil {
		t.Fatal(err)
	}
	first, err := database.CreateServiceAt(t.Context(), request.TeamID, request.ActingIdentityID, "first", "first",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000", Hostname: request.CanonicalHostname, Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET ingress_pool_id = 'ingress-a' WHERE id = $1`, request.TeamID); err == nil {
		t.Fatal("team moved to another ingress pool while its member wildcard was saved")
	}
	second, err := database.CreateServiceAt(t.Context(), request.TeamID, request.ActingIdentityID, "second", "second",
		ServicePlacement{}, now, ServiceMetadata{}, &ProjectServiceConfiguration{Target: "localhost:3000", Hostname: "another." + strings.TrimPrefix(request.CanonicalHostname, "demo."), Public: new(true)})
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ id, want string }{{first.ID, "ingress-b"}, {second.ID, "ingress-b"}} {
		var poolID string
		if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.services WHERE id = $1`, entry.id).Scan(&poolID); err != nil {
			t.Fatal(err)
		}
		if poolID != entry.want {
			t.Errorf("service %s pool = %q, want %q", entry.id, poolID, entry.want)
		}
	}
}

func TestIntegrationPrimaryIngressPoolAddressIsPinned(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_pool_inventory")
	ctx := t.Context()
	if err := database.EnsurePrimaryIngressPool(ctx, "192.0.2.10", "2001:db8::10", now); err != nil {
		t.Fatal(err)
	}
	if err := database.EnsurePrimaryIngressPool(ctx, "192.0.2.10", "2001:db8::10", now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	pool, err := database.GetIngressPool(ctx, "ingress-a")
	if err != nil || pool.State != IngressPoolEnabled || pool.IPv4Address.String() != "192.0.2.10" || pool.IPv6Address.String() != "2001:db8::10" {
		t.Fatalf("enabled pool = %#v, %v", pool, err)
	}
	if err := database.EnsurePrimaryIngressPool(ctx, "192.0.2.20", "2001:db8::10", now.Add(time.Hour)); err == nil {
		t.Fatal("a later control process changed the public address for existing service placements")
	}
	var ports bool
	if err := database.pool.QueryRow(ctx, `SELECT to_regclass('control.tcp_port_claims') IS NOT NULL OR to_regclass('control.ingress_pool_ports') IS NOT NULL`).Scan(&ports); err != nil || ports {
		t.Fatalf("obsolete public port tables remain in the schema: %t %v", ports, err)
	}
}
