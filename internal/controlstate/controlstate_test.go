package controlstate

import (
	"slices"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestCanonicalCertificateIdentifiers(t *testing.T) {
	t.Parallel()

	identifiers, err := canonicalCertificateIdentifiers([]string{"z.example.test", "*.example.test", "a.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"*.example.test", "a.example.test", "z.example.test"}; !slices.Equal(identifiers, want) {
		t.Fatalf("canonical identifiers = %q, want %q", identifiers, want)
	}
	for _, invalid := range [][]string{
		nil,
		{"route.example.test", "route.example.test"},
		{"Route.example.test"},
		{"route.*.example.test"},
	} {
		if _, err := canonicalCertificateIdentifiers(invalid); err == nil {
			t.Errorf("canonicalCertificateIdentifiers(%q) succeeded", invalid)
		}
	}
}

func TestParseDirectConfig(t *testing.T) {
	t.Parallel()

	config, err := parseDirectConfig("postgres://user:secret@database.example:5432/tnl?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if config.Database != "tnl" {
		t.Fatalf("database = %q, want tnl", config.Database)
	}
	if config.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Fatalf("query execution mode = %v, want %v", config.DefaultQueryExecMode, pgx.QueryExecModeExec)
	}
}

func TestParsePoolConfig(t *testing.T) {
	t.Parallel()

	defaultConfig, err := parsePoolConfig("postgresql://user:secret@database.example/tnl?sslmode=require")
	if err != nil {
		t.Fatal(err)
	}
	if defaultConfig.MaxConns != 6 {
		t.Fatalf("default maximum connections = %d, want 6", defaultConfig.MaxConns)
	}

	config, err := parsePoolConfig("postgresql://user:secret@database.example/tnl?sslmode=require&pool_max_conns=7&default_query_exec_mode=cache_statement")
	if err != nil {
		t.Fatal(err)
	}
	if config.MaxConns != 7 {
		t.Fatalf("maximum connections = %d, want 7", config.MaxConns)
	}
	if config.ConnConfig.DefaultQueryExecMode != pgx.QueryExecModeExec {
		t.Fatalf("query execution mode = %v, want %v", config.ConnConfig.DefaultQueryExecMode, pgx.QueryExecModeExec)
	}
}

func TestDatabaseURLValidation(t *testing.T) {
	t.Parallel()

	for _, rawURL := range []string{
		"postgres:///tnl",
		"postgresql://database.example/tnl",
	} {
		if err := validateDatabaseURL(rawURL); err != nil {
			t.Errorf("validateDatabaseURL(%q): %v", rawURL, err)
		}
	}

	for _, rawURL := range []string{
		"",
		" postgres://database.example/tnl",
		"host=database.example dbname=tnl",
		"https://database.example/tnl",
		"postgres://database.example",
		"postgres://database.example/",
		"postgres://database.example/tnl#fragment",
		"postgres://user:supersecret@%zz/tnl",
	} {
		err := validateDatabaseURL(rawURL)
		if err == nil {
			t.Errorf("validateDatabaseURL(%q) succeeded", rawURL)
			continue
		}
		if strings.Contains(err.Error(), "supersecret") {
			t.Errorf("validateDatabaseURL(%q) leaked its password: %v", rawURL, err)
		}
	}
}

func TestDatabaseNilHealthAndReadiness(t *testing.T) {
	t.Parallel()

	var database *Database
	if err := database.Health(t.Context()); err == nil {
		t.Fatal("Health succeeded for a nil database")
	}
	if err := database.Readiness(t.Context()); err == nil {
		t.Fatal("Readiness succeeded for a nil database")
	}
	database.Close()
}
