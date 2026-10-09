package controlstate

import (
	"crypto/sha256"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/observability"
)

func TestIntegrationPublicURLPurposeSurvivesReadAndIsNotRelabeledByRetry(t *testing.T) {
	database, now := newControlStateIntegrationDatabase(t, "public_url_purpose")
	metrics := observability.New("control")
	database.Instrument(metrics)
	request := builtinRouteRequest(t, database, now)
	request.Purpose = PublicURLPurposeWebhooks
	created, err := database.CreatePublicURL(t.Context(), request, now)
	if err != nil || created.Purpose != PublicURLPurposeWebhooks {
		t.Fatalf("created purpose = %q, error=%v", created.Purpose, err)
	}
	replayed, err := database.CreatePublicURL(t.Context(), request, now.Add(time.Second))
	if err != nil || replayed.Purpose != created.Purpose || replayed.ID != created.ID {
		t.Fatalf("idempotent purpose = %q, error=%v", replayed.Purpose, err)
	}
	request.Purpose = PublicURLPurposeOAuth
	if _, err := database.CreatePublicURL(t.Context(), request, now.Add(2*time.Second)); !errors.Is(err, ErrPublicURLIdempotency) {
		t.Fatalf("relabeling idempotent URL = %v", err)
	}
	request.IdempotencyKey, request.RequestDigest = "other", sha256.Sum256([]byte("other"))
	if _, err := database.CreatePublicURL(t.Context(), request, now.Add(3*time.Second)); !errors.Is(err, ErrPublicURLConflict) {
		t.Fatalf("relabeling saved hostname = %v", err)
	}
	var stored string
	if err := database.pool.QueryRow(t.Context(), `SELECT purpose FROM control.public_urls WHERE id = $1`, created.ID).Scan(&stored); err != nil || stored != "webhooks" {
		t.Fatalf("stored purpose = %q, error=%v", stored, err)
	}
	var defaultValue sql.NullString
	if err := database.pool.QueryRow(t.Context(), `SELECT column_default FROM information_schema.columns
		WHERE table_schema = 'control' AND table_name = 'public_urls' AND column_name = 'purpose'`).Scan(&defaultValue); err != nil || defaultValue.Valid {
		t.Fatalf("new public URLs must declare a purpose, default = %v, error=%v", defaultValue, err)
	}
	if _, err := database.pool.Exec(t.Context(), `UPDATE control.public_urls SET purpose = 'unknown' WHERE id = $1`, created.ID); err == nil {
		t.Fatal("database accepted an unknown purpose")
	} else {
		var postgresError *pgconn.PgError
		if !errors.As(err, &postgresError) || postgresError.Code != "23514" {
			t.Fatalf("unknown purpose was rejected for the wrong reason: %v", err)
		}
	}
	metric := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metric, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metric.Body.String(), `tnl_control_public_urls_created_total{purpose="webhooks"} 1`) {
		t.Fatal("creation and retry were not counted once by public URL purpose")
	}
}

func TestIntegrationPublicURLPurposeCountsOnlyFirstReadyTransition(t *testing.T) {
	fixture := newPublishRunFixture(t)
	metrics := observability.New("control")
	fixture.database.Instrument(metrics)
	readyTestSession(t, fixture)
	if _, err := fixture.database.MarkPublishRunReady(t.Context(), fixture.authentication(), fixture.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	metric := httptest.NewRecorder()
	metrics.Handler().ServeHTTP(metric, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if !strings.Contains(metric.Body.String(), `tnl_control_publish_runs_ready_total{purpose="app"} 1`) {
		t.Fatal("ready run was not counted exactly once by saved purpose")
	}
}
