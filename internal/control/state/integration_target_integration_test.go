package state

import (
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestIntegrationHandlerBackedPublicURLTargets(t *testing.T) {
	for _, purpose := range []PublicURLPurpose{PublicURLPurposeOAuth, PublicURLPurposeWebhooks} {
		t.Run(string(purpose), func(t *testing.T) {
			d, now := newControlStateIntegrationDatabase(t, "handler_target")
			request := oidcRouteRequest(t, d, now)
			request.Purpose, request.Target = purpose, ""
			for _, target := range []string{"http://127.0.0.1:3000", "invalid"} {
				invalid := request
				invalid.Target = target
				if _, err := d.CreatePublicURL(t.Context(), invalid, now); !errors.Is(err, ErrPublicURLInvalid) {
					t.Fatalf("create integration with target: %v", err)
				}
			}
			invalid := request
			invalid.Ephemeral = true
			if _, err := d.CreatePublicURL(t.Context(), invalid, now); !errors.Is(err, ErrPublicURLInvalid) {
				t.Fatalf("create ephemeral integration: %v", err)
			}
			created := createTestPublicURL(t, d, request, now)
			for _, prefixes := range [][]string{{"192.0.2.10/32"}, {}} {
				update := AuthorizedPublicURLUpdateRequest{PublicURLID: created.ID, TeamID: created.TeamID, ActingIdentityID: request.ActingIdentityID, AllowedIPPrefixes: prefixes, PolicyRevision: uint64(created.PolicyRevision), ExpectedMutationRevision: created.MutationRevision}
				update.Target = "http://127.0.0.1:3000"
				if _, err := d.UpdateAuthorizedPublicURL(t.Context(), update, now); !errors.Is(err, ErrPublicURLInvalid) {
					t.Fatalf("update integration with target: %v", err)
				}
				update.Target = ""
				updated, err := d.UpdateAuthorizedPublicURL(t.Context(), update, now.Add(time.Second))
				if err != nil || updated.Target != "" || updated.Ephemeral || len(updated.AllowedIPPrefixes) != len(prefixes) {
					t.Fatalf("targetless policy update: %+v, %v", updated, err)
				}
				created = updated
			}
			loaded, err := d.GetPublicURL(t.Context(), request.ActingIdentityID, created.ID)
			if err != nil || loaded.Target != "" || loaded.Purpose != purpose || loaded.Ephemeral {
				t.Fatalf("reload integration: %+v, %v", loaded, err)
			}
			for _, statement := range []string{
				`UPDATE control.public_urls SET target='http://127.0.0.1:3000' WHERE id=$1`,
				`UPDATE control.public_urls SET ephemeral=true, expires_at=created_at+interval '1 hour' WHERE id=$1`,
			} {
				_, err := d.pool.Exec(t.Context(), statement, created.ID)
				var pg *pgconn.PgError
				if !errors.As(err, &pg) || pg.Code != "23514" {
					t.Fatalf("database accepted invalid integration target/lifecycle: %v", err)
				}
			}
		})
	}
}
