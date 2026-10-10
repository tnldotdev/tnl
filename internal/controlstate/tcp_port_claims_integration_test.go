package controlstate

import (
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestIntegrationTCPPortAllocationAndQuarantine(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "tcp_port_allocation")
	request := builtinRouteRequest(t, database, now)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.ingress_pools SET ipv4_address = '192.0.2.10', state = 'enabled' WHERE id = 'ingress-a'`); err != nil {
		t.Fatal(err)
	}
	for _, port := range []int{5432, 15432, 3306} {
		if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.ingress_pool_ports
			(ingress_pool_id, port, enabled) VALUES ('ingress-a', $1, true)`, port); err != nil {
			t.Fatal(err)
		}
	}
	create := func(index int, protocol string) PublicURL {
		t.Helper()
		selected := request
		selected.IdempotencyKey = fmt.Sprintf("db-url-%d", index)
		selected.CanonicalHostname = fmt.Sprintf("db%d.%s", index, request.CanonicalHostname)
		url, err := database.CreatePublicURL(t.Context(), selected, now)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls
			SET target = '', service_protocol = $2 WHERE id = $1`, url.ID, protocol); err != nil {
			t.Fatal(err)
		}
		return url
	}
	first := create(1, "postgres")
	firstClaim, err := database.AllocateTCPPort(t.Context(), first.ID, now)
	if err != nil || firstClaim.Port != 5432 || firstClaim.IngressPoolID != "ingress-a" {
		t.Fatalf("first PostgreSQL address = %#v, %v", firstClaim, err)
	}
	repeated, err := database.AllocateTCPPort(t.Context(), first.ID, now.Add(time.Hour))
	if err != nil || repeated != firstClaim {
		t.Fatalf("same saved URL changed port = %#v, %v", repeated, err)
	}
	mysql := create(2, "mysql")
	mysqlClaim, err := database.AllocateTCPPort(t.Context(), mysql.ID, now)
	if err != nil || mysqlClaim.Port != 3306 {
		t.Fatalf("MySQL address = %#v, %v", mysqlClaim, err)
	}
	second := create(3, "postgres")
	secondClaim, err := database.AllocateTCPPort(t.Context(), second.ID, now)
	if err != nil || secondClaim.Port != 15432 {
		t.Fatalf("second PostgreSQL address = %#v, %v", secondClaim, err)
	}
	capacities, err := database.TCPPortPoolCapacities(t.Context())
	if err != nil || len(capacities) != 1 || capacities[0].IngressPoolID != "ingress-a" ||
		capacities[0].ConfiguredPorts != 3 || capacities[0].ClaimedPorts != 3 || capacities[0].AvailablePorts != 0 {
		t.Fatalf("full pool capacity = %#v, %v", capacities, err)
	}
	waiting := create(4, "postgres")
	if _, err := database.AllocateTCPPort(t.Context(), waiting.ID, now); !errors.Is(err, ErrTCPPortPoolFull) {
		t.Fatalf("full pool did not reject another URL: %v", err)
	}
	if err := database.DeletePublicURL(t.Context(), request.ActingIdentityID, first.ID, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		at   time.Time
		want int64
	}{{now.Add(7 * 24 * time.Hour), 0}, {now.Add(7*24*time.Hour + time.Hour), 1}} {
		released, err := database.ReleaseQuarantinedTCPPortClaims(t.Context(), test.at)
		if err != nil || released != test.want {
			t.Fatalf("release at %s = %d, %v; want %d", test.at, released, err, test.want)
		}
	}
	thirdClaim, err := database.AllocateTCPPort(t.Context(), waiting.ID, now.Add(9*24*time.Hour))
	if err != nil || thirdClaim.Port != 5432 {
		t.Fatalf("port after quarantine = %#v, %v", thirdClaim, err)
	}
	if _, err := database.AllocateTCPPort(t.Context(), mysql.ID, now); err != nil {
		t.Fatalf("MySQL port changed after another protocol recycled a port: %v", err)
	}
	httpURL, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.AllocateTCPPort(t.Context(), httpURL.ID, now); !errors.Is(err, ErrPublicURLInvalid) {
		t.Fatalf("HTTP URL obtained TCP port: %v", err)
	}
}
