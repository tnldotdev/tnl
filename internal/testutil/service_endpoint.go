package testutil

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// SeedServicePort gives an isolated fixture an already-retained public binding
// before any run starts. allocation and exposure mutations are tested through
// apply; admission/certificate fixtures can keep their independently owned setup.
func SeedServicePort(t testing.TB, database interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, service string, port int, now time.Time) {
	t.Helper()
	var saved int
	err := database.QueryRow(t.Context(), `WITH claim AS (
		INSERT INTO control.service_port_claims(service_id,ingress_pool_id,port,claimed_at)
		SELECT id,ingress_pool_id,$2,$3 FROM control.services WHERE id=$1
		AND NOT EXISTS(SELECT 1 FROM control.service_runs WHERE service_id=$1)
		RETURNING service_id,port
	) UPDATE control.services service SET service_port=claim.port FROM claim
	WHERE service.id=claim.service_id RETURNING service.service_port`, service, port, now).Scan(&saved)
	if err != nil || saved != port {
		t.Fatalf("seed retained service port before publication: port=%d error=%v", saved, err)
	}
}
