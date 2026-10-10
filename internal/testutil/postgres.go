package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// TestTier identifies an opt-in test suite.
type TestTier string

const (
	TestTierRoutine      TestTier = "routine"
	TestTierIntegration  TestTier = "integration"
	TestTierMySQL        TestTier = "mysql"
	TestTierBinary       TestTier = "binary"
	TestTierDNS          TestTier = "dns"
	TestTierRoute53      TestTier = "route53"
	TestTierDatabaseLoad TestTier = "database-load"
	TestTierRuntimeLoad  TestTier = "runtime-load"
)

var (
	testTier        = flag.String("tnl-test-tier", string(TestTierRoutine), "tnl test tier")
	testPostgresURL = flag.String("tnl-test-postgres-url", "", "disposable PostgreSQL administration URL")
)

// RequireTestTier skips a test unless its suite is selected.
func RequireTestTier(t testing.TB, required TestTier) {
	t.Helper()
	selected := selectedTestTier(t)
	if selected != required {
		t.Skipf("requires the %s test tier", required)
	}
}

// NewDisposablePostgresDatabaseURL creates a uniquely named PostgreSQL
// database and drops it, including any remaining connections, during cleanup.
func NewDisposablePostgresDatabaseURL(t testing.TB, suffix string) string {
	t.Helper()
	directURL := PostgresURL(t)
	parsed := parsePostgresTestURL(t, directURL)
	adminConfig, err := pgx.ParseConfig(directURL)
	if err != nil {
		t.Fatalf("parse -tnl-test-postgres-url: %v", err)
	}
	admin, err := pgx.ConnectConfig(t.Context(), adminConfig)
	if err != nil {
		t.Fatalf("connect using -tnl-test-postgres-url: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := admin.Close(ctx); err != nil {
			t.Errorf("close PostgreSQL test administration connection: %v", err)
		}
	})

	random := make([]byte, 8)
	if _, err := rand.Read(random); err != nil {
		t.Fatalf("create disposable PostgreSQL database name: %v", err)
	}
	databaseName := "tnl_" + postgresDatabaseLabel(suffix) + "_" + hex.EncodeToString(random)
	identifier := pgx.Identifier{databaseName}.Sanitize()
	if _, err := admin.Exec(t.Context(), "CREATE DATABASE "+identifier); err != nil {
		t.Fatalf("create disposable PostgreSQL database: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, err := admin.Exec(ctx, `
			SELECT pg_terminate_backend(pid)
			FROM pg_stat_activity
			WHERE datname = $1 AND pid <> pg_backend_pid()
		`, databaseName); err != nil {
			t.Errorf("terminate connections to disposable PostgreSQL database %q: %v", databaseName, err)
		}
		if _, err := admin.Exec(ctx, "DROP DATABASE IF EXISTS "+identifier+" WITH (FORCE)"); err != nil {
			t.Errorf("drop disposable PostgreSQL database %q: %v", databaseName, err)
		}
	})

	parsed.Path, parsed.RawPath = "/"+databaseName, ""
	return parsed.String()
}

// PostgresURL returns the PostgreSQL administration URL for PostgreSQL-backed tests.
func PostgresURL(t testing.TB) string {
	t.Helper()
	if selectedTestTier(t) == TestTierRoutine {
		t.Skip("requires a PostgreSQL-backed test tier")
	}
	directURL := *testPostgresURL
	if directURL == "" {
		t.Fatal("selected test tier requires -tnl-test-postgres-url")
	}
	return directURL
}

func selectedTestTier(t testing.TB) TestTier {
	t.Helper()
	tier := TestTier(*testTier)
	switch tier {
	case TestTierRoutine, TestTierIntegration, TestTierMySQL, TestTierBinary, TestTierDNS, TestTierRoute53, TestTierDatabaseLoad, TestTierRuntimeLoad:
		return tier
	default:
		t.Fatalf("unknown tnl test tier %q", tier)
		return ""
	}
}

func parsePostgresTestURL(t testing.TB, rawURL string) *url.URL {
	t.Helper()
	if rawURL != strings.TrimSpace(rawURL) {
		t.Fatal("-tnl-test-postgres-url contains surrounding whitespace")
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse -tnl-test-postgres-url: %v", err)
	}
	if parsed.Scheme != "postgres" && parsed.Scheme != "postgresql" {
		t.Fatal("-tnl-test-postgres-url must use the postgres or postgresql scheme")
	}
	if parsed.Opaque != "" || parsed.Fragment != "" || strings.TrimPrefix(parsed.EscapedPath(), "/") == "" {
		t.Fatal("-tnl-test-postgres-url must be a valid URL naming a database")
	}
	return parsed
}

func postgresDatabaseLabel(suffix string) string {
	var label strings.Builder
	for _, character := range strings.ToLower(suffix) {
		if label.Len() == 32 {
			break
		}
		if character >= 'a' && character <= 'z' || character >= '0' && character <= '9' {
			label.WriteRune(character)
		} else if label.Len() > 0 && !strings.HasSuffix(label.String(), "_") {
			label.WriteByte('_')
		}
	}
	normalized := strings.Trim(label.String(), "_")
	if normalized == "" {
		return "test"
	}
	return normalized
}
