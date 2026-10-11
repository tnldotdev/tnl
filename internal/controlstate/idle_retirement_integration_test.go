package controlstate

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationEphemeralPublicURLCannotBeKeptInStorage(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "ephemeral_keep_storage")
	request := builtinRouteRequest(t, database, now)
	request.Ephemeral = true
	publicURL, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.pool.Exec(t.Context(),
		`UPDATE control.public_urls SET keep_saved = true WHERE id = $1`, publicURL.ID)
	var constraint *pgconn.PgError
	if !errors.As(err, &constraint) || constraint.Code != "23514" {
		t.Fatalf("ephemeral public URL accepted keep setting: %v", err)
	}
}
