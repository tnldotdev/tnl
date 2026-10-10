package controlstate

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationIngressPoolClaimsKeepTheirAddressAndHistory(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_pool_claims")
	request := builtinRouteRequest(t, database, now)
	first, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	var teamPool, urlPool string
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.teams WHERE id = $1`, request.TeamID).Scan(&teamPool); err != nil {
		t.Fatal(err)
	}
	if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.public_urls WHERE id = $1`, first.ID).Scan(&urlPool); err != nil {
		t.Fatal(err)
	}
	if teamPool != "ingress-a" || urlPool != teamPool {
		t.Fatalf("seeded pool: team %q, url %q", teamPool, urlPool)
	}
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.ingress_pool_ports (ingress_pool_id, port, enabled) VALUES ('ingress-a', 15432, true)`); err != nil {
		t.Fatal(err)
	}
	insertClaim := func(id, publicURLID, hostname string) error {
		_, err := database.pool.Exec(t.Context(), `INSERT INTO control.tcp_port_claims
			(id, public_url_id, ingress_pool_id, canonical_hostname, port, state, claimed_at)
			VALUES ($1, $2, 'ingress-a', $3, 15432, 'held', $4)`, id, publicURLID, hostname, now)
		return err
	}
	if err := insertClaim("claim_1", first.ID, first.CanonicalHostname); err != nil {
		t.Fatal(err)
	}
	secondRequest := request
	secondRequest.IdempotencyKey = "second-pool-url"
	secondRequest.CanonicalHostname = "second." + request.CanonicalHostname
	second, err := database.CreatePublicURL(t.Context(), secondRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	var constraint *pgconn.PgError
	if err := insertClaim("claim_2", second.ID, second.CanonicalHostname); !errors.As(err, &constraint) || constraint.Code != "23505" {
		t.Fatalf("second public URL claimed an occupied port: %v", err)
	}
	until := now.Add(7 * 24 * time.Hour)
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.tcp_port_claims SET state = 'quarantined', retired_at = $1, reusable_after = $2 WHERE id = 'claim_1'`, now, until); err != nil {
		t.Fatal(err)
	}
	if err := insertClaim("claim_3", second.ID, second.CanonicalHostname); !errors.As(err, &constraint) || constraint.Code != "23505" {
		t.Fatalf("quarantined port was claimed: %v", err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.tcp_port_claims SET state = 'released' WHERE id = 'claim_1'`); err != nil {
		t.Fatal(err)
	}
	if err := insertClaim("claim_4", second.ID, second.CanonicalHostname); err != nil {
		t.Fatalf("port could not be reused by a different hostname: %v", err)
	}
}

func TestIntegrationPublicURLPinsTeamIngressPoolAtCreation(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ingress_pool_placement")
	request := builtinRouteRequest(t, database, now)
	if _, err := database.pool.Exec(t.Context(), `INSERT INTO control.ingress_pools
		(id, ipv4_address, state, created_at, updated_at)
		VALUES ('ingress-b', '203.0.113.20', 'enabled', $1, $1)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET ingress_pool_id = 'ingress-b' WHERE id = $1`, request.TeamID); err != nil {
		t.Fatal(err)
	}
	first, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.teams SET ingress_pool_id = 'ingress-a' WHERE id = $1`, request.TeamID); err == nil {
		t.Fatal("team moved to another ingress pool while its member wildcard was saved")
	}
	secondRequest := request
	secondRequest.IdempotencyKey = "second-ingress-pool"
	secondRequest.CanonicalHostname = "another." + request.CanonicalHostname
	second, err := database.CreatePublicURL(t.Context(), secondRequest, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range []struct{ id, want string }{{first.ID, "ingress-b"}, {second.ID, "ingress-b"}} {
		var poolID string
		if err := database.pool.QueryRow(t.Context(), `SELECT ingress_pool_id FROM control.public_urls WHERE id = $1`, entry.id).Scan(&poolID); err != nil {
			t.Fatal(err)
		}
		if poolID != entry.want {
			t.Errorf("url %s pool = %q, want %q", entry.id, poolID, entry.want)
		}
	}
}
