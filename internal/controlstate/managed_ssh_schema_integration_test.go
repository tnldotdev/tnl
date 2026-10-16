package controlstate_test

import (
	"crypto/ed25519"
	"database/sql"
	"embed"
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/tnldotdev/tnl/internal/controlstate/controlstatedb"
	"github.com/tnldotdev/tnl/internal/testutil"
	"golang.org/x/crypto/ssh"
)

//go:embed migrations/*.sql
var sshSchemaMigrations embed.FS

func newSSHSchemaDatabase(t *testing.T) (*pgxpool.Pool, controlstatedb.InsertPublicURLParams) {
	t.Helper()
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	url := testutil.NewDisposablePostgresDatabaseURL(t, "managed_ssh_schema")
	database, err := sql.Open("pgx", url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := database.Close(); err != nil {
			t.Error(err)
		}
	})
	if _, err := database.ExecContext(t.Context(), "CREATE SCHEMA control"); err != nil {
		t.Fatal(err)
	}
	migrations, err := fs.Sub(sshSchemaMigrations, "migrations")
	if err != nil {
		t.Fatal(err)
	}
	provider, err := goose.NewProvider(goose.DialectPostgres, database, migrations,
		goose.WithTableName("control.goose_db_version"), goose.WithDisableGlobalRegistry(true))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Up(t.Context()); err != nil {
		t.Fatal(err)
	}
	pool, err := pgxpool.New(t.Context(), url)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	now := time.Now().UTC().Truncate(time.Second)
	for _, statement := range []string{
		`INSERT INTO control.identities (id, kind, display_name, created_at, updated_at)
		 VALUES ('owner', 'authority', 'owner', $1, $1), ('visitor', 'authority', 'visitor', $1, $1)`,
		`INSERT INTO control.managed_label_reservations (label, created_at) VALUES ('schema-team', $1), ('schema-member', $1)`,
		`INSERT INTO control.teams (id, kind, display_name, managed_label, created_by_identity_id, created_at, updated_at)
		 VALUES ('team', 'organization', 'schema-team', 'schema-team', 'owner', $1, $1)`,
		`INSERT INTO control.member_slug_reservations (id, team_id, member_slug, state, created_at)
		 VALUES ('slug', 'team', 'owner', 'active', $1)`,
		`INSERT INTO control.team_memberships (id, team_id, identity_id, slug_reservation_id, managed_label, role, authority_revision, created_at, updated_at)
		 VALUES ('member', 'team', 'owner', 'slug', 'schema-member', 'owner', 1, $1, $1)`,
		`INSERT INTO control.domains (id, kind, team_id, canonical_domain, state, authority_revision, created_at, updated_at)
		 VALUES ('domain', 'custom', 'team', 'example.test', 'ready', 1, $1, $1)`,
	} {
		if _, err := pool.Exec(t.Context(), statement, now); err != nil {
			t.Fatal(err)
		}
	}
	key, err := ssh.NewPublicKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public())
	if err != nil {
		t.Fatal(err)
	}
	return pool, controlstatedb.InsertPublicURLParams{
		ID: "ssh", TeamID: "team", DomainID: "domain", CreatedByIdentityID: "owner", IdempotencyKey: "ssh",
		RequestDigestCiphertext: []byte{1}, RequestDigestStorageKeyID: pgtype.Text{String: "test", Valid: true},
		CanonicalHostname: "ssh.example.test", PublicURLScope: "shared", Purpose: "app", ServiceProtocol: "ssh",
		SSHHostKey:    pgtype.Text{String: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))), Valid: true},
		IngressPoolID: "ingress-a", PolicyRevision: 1, IpPolicy: "allow_all", DnsState: "unmanaged",
		AccessMode: "restricted",
		CreatedAt:  pgtype.Timestamptz{Time: now, Valid: true},
	}
}

func TestIntegrationManagedSSHSchemaPersistenceAndPermission(t *testing.T) {
	pool, input := newSSHSchemaDatabase(t)
	q := controlstatedb.New(pool)
	url, err := q.InsertPublicURL(t.Context(), input)
	if err != nil || url.SSHHostKey != input.SSHHostKey || url.Target != "" || url.Ephemeral {
		t.Fatalf("saved SSH shape = %+v, %v", url, err)
	}
	permission := controlstatedb.VisitorPermissionParams{PublicURLID: url.ID, IdentityID: "owner", Now: input.CreatedAt}
	if _, err := q.VisitorPermission(t.Context(), permission); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ownership-only SSH permission = %v", err)
	}
	grantInput := controlstatedb.CreateVisitorGrantParams{
		ID: "grant", PublicURLID: url.ID, TeamID: url.TeamID, Kind: "identity", IdentityID: pgtype.Text{String: "owner", Valid: true},
		CreatedByIdentityID: "owner", IdempotencyKey: "grant", RequestDigest: make([]byte, 32), CreatedAt: input.CreatedAt,
	}
	if _, err := q.CreateVisitorGrant(t.Context(), grantInput); err != nil {
		t.Fatal(err)
	}
	if _, err := q.VisitorPermission(t.Context(), permission); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("SSH grant without account permitted a visit: %v", err)
	}
	grantInput.ID, grantInput.IdempotencyKey = "ssh-grant", "ssh-grant"
	grantInput.SSHUser = pgtype.Text{String: "deploy", Valid: true}
	grant, err := q.CreateVisitorGrant(t.Context(), grantInput)
	if err != nil || grant.SSHUser != grantInput.SSHUser {
		t.Fatalf("SSH grant account = %+v, %v", grant, err)
	}
	decision, err := q.VisitorPermission(t.Context(), permission)
	if err != nil || decision.Reason != "identity_grant" {
		t.Fatalf("explicit SSH permission = %+v, %v", decision, err)
	}
	inventory, err := q.ListVisitorInventory(t.Context(), controlstatedb.ListVisitorInventoryParams{IdentityID: "owner", Now: input.CreatedAt})
	if err != nil || len(inventory) != 1 || inventory[0].SSHHostKey != input.SSHHostKey {
		t.Fatalf("SSH inventory key = %+v, %v", inventory, err)
	}
	invitation, err := q.CreateVisitorInvitation(t.Context(), controlstatedb.CreateVisitorInvitationParams{
		ID: "invitation", PublicURLID: url.ID, TeamID: url.TeamID, NormalizedEmail: "visitor@example.test", TokenDigest: make([]byte, 32),
		SSHUser: grantInput.SSHUser, CreatedByIdentityID: "owner", IdempotencyKey: "invitation", RequestDigest: make([]byte, 32),
		CreatedAt: input.CreatedAt, ExpiresAt: pgtype.Timestamptz{Time: input.CreatedAt.Time.Add(time.Hour), Valid: true},
	})
	if err != nil || invitation.SSHUser != grantInput.SSHUser {
		t.Fatalf("SSH invitation account = %+v, %v", invitation, err)
	}
	for _, table := range []string{"visitor_grants", "visitor_invitations"} {
		for _, user := range []string{"", "root", "Root", "deploy\n", strings.Repeat("a", 33)} {
			_, err := pool.Exec(t.Context(), "UPDATE control."+table+" SET ssh_user=$1", user)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23514" {
				t.Fatalf("invalid SSH account in %s: %v", table, err)
			}
		}
	}
	if err := q.RevokeVisitorGrant(t.Context(), controlstatedb.RevokeVisitorGrantParams{ID: grant.ID, RevokedAt: input.CreatedAt}); err != nil {
		t.Fatal(err)
	}
	if _, err := q.VisitorPermission(t.Context(), permission); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("revoked SSH grant permitted a visit: %v", err)
	}
}

func TestIntegrationManagedSSHSchemaConstraints(t *testing.T) {
	pool, valid := newSSHSchemaDatabase(t)
	q := controlstatedb.New(pool)
	for name, mutate := range map[string]func(*controlstatedb.InsertPublicURLParams){
		"missing-key": func(p *controlstatedb.InsertPublicURLParams) { p.SSHHostKey = pgtype.Text{} },
		"empty-key":   func(p *controlstatedb.InsertPublicURLParams) { p.SSHHostKey.String = "" },
		"blank-key":   func(p *controlstatedb.InsertPublicURLParams) { p.SSHHostKey.String = "   " },
		"large-key":   func(p *controlstatedb.InsertPublicURLParams) { p.SSHHostKey.String = strings.Repeat("a", 1025) },
		"target":      func(p *controlstatedb.InsertPublicURLParams) { p.Target = "http://127.0.0.1:22" },
		"ephemeral": func(p *controlstatedb.InsertPublicURLParams) {
			p.Ephemeral = true
			p.ExpiresAt = pgtype.Timestamptz{Time: p.CreatedAt.Time.Add(time.Hour), Valid: true}
		},
		"http-key": func(p *controlstatedb.InsertPublicURLParams) { p.ServiceProtocol = "http" },
	} {
		t.Run(name, func(t *testing.T) {
			input := valid
			input.ID, input.IdempotencyKey, input.CanonicalHostname = name, name, name+".example.test"
			mutate(&input)
			_, err := q.InsertPublicURL(t.Context(), input)
			var constraint *pgconn.PgError
			if !errors.As(err, &constraint) || constraint.Code != "23514" {
				t.Fatalf("invalid managed SSH shape: %v", err)
			}
		})
	}
	var identity string
	if err := pool.QueryRow(t.Context(), `SELECT baseline_id FROM control.schema_identity WHERE id=1`).Scan(&identity); err != nil || identity != "tnl-control-fresh-v1-managed-ssh" {
		t.Fatalf("managed SSH baseline identity = %q, %v", identity, err)
	}
	if _, err := pool.Exec(t.Context(), `UPDATE control.schema_identity SET baseline_id='tnl-control-fresh-v1' WHERE id=1`); err == nil {
		t.Fatal("baseline identity accepted the previous reset schema")
	}
}
