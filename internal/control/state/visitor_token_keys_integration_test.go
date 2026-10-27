package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
	"github.com/tnldotdev/tnl/internal/security/visitortoken"
)

const testVisitorIssuer = "https://control.example.test"

func signingTestPermission(now time.Time) visitortoken.Permission {
	return visitortoken.Permission{Scope: visitorscope.Scope{Kind: visitorscope.PublicURL, ID: "url_" + strings.Repeat("A", 22)}, Hostname: "preview.example.test", Port: 443,
		VisitorPolicyRevision: 1, Subject: visitortoken.Browser{IdentityID: "ident_" + strings.Repeat("A", 22), SessionID: "cs_" + strings.Repeat("B", 22)}, ExpiresAt: now.Add(5 * time.Minute)}
}

func signStateTestPermission(ctx context.Context, d *Database, issuer string, permission visitortoken.Permission, now time.Time) (visitortoken.Token, error) {
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)
	token, err := d.signVisitorPermission(ctx, tx, issuer, permission, now)
	if err != nil {
		return "", err
	}
	return token, tx.Commit(ctx)
}

func TestIntegrationShortVisitorPermissionsShareSigningKeyRetention(t *testing.T) {
	d, _, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_key_short_retention")
	prepareVisitorTokenKeys(t, d, now)
	permission := signingTestPermission(now)
	retained := func() time.Time {
		t.Helper()
		var until time.Time
		if err := d.pool.QueryRow(t.Context(), `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NULL`).Scan(&until); err != nil {
			t.Fatal(err)
		}
		return until
	}
	if _, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, permission, now); err != nil {
		t.Fatal(err)
	}
	first := retained()
	if !first.After(permission.ExpiresAt) {
		t.Fatal("short token retention did not cover its expiry")
	}
	permission.ExpiresAt = permission.ExpiresAt.Add(time.Second)
	if _, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, permission, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if !retained().Equal(first) {
		t.Fatal("adjacent short token issuance rewrote the shared signing key")
	}
	// a second repeatable-read issuance inside the retained horizon must finish
	// while the first transaction still holds its signing-key lock.
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	if _, err := d.signVisitorPermission(t.Context(), tx, testVisitorIssuer, permission, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	if _, err := signStateTestPermission(ctx, d, testVisitorIssuer, permission, now.Add(time.Second)); err != nil {
		t.Fatalf("issuance within retained horizon waited for another signing-key reader: %v", err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func stateTestVisitorKeys(t *testing.T, d *Database, now time.Time) map[string]ed25519.PublicKey {
	t.Helper()
	tx, err := d.pool.Begin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	keys, err := visitorVerificationKeys(t.Context(), controlstatedb.New(tx), testVisitorIssuer, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	return keys
}

func stateTestVisitorView(permission visitortoken.Permission, keys map[string]ed25519.PublicKey, now time.Time) visitortoken.View {
	return visitortoken.View{Issuer: testVisitorIssuer, Scope: permission.Scope, Hostname: permission.Hostname, Port: permission.Port,
		VisitorPolicyRevision: permission.VisitorPolicyRevision, ObservedAt: now, ValidUntil: now.Add(visitortoken.PolicyLifetime), Keys: keys}
}

func TestIntegrationVisitorSigningKeysAreEncryptedSharedAndIssuerBound(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_signing_keys")
	prepareVisitorTokenKeys(t, d, now)
	other, err := Open(t.Context(), url, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(other.Close)
	permission := signingTestPermission(now)
	var workers sync.WaitGroup
	var mu sync.Mutex
	var tokens []visitortoken.Token
	var failures []error
	for index := range 16 {
		workers.Go(func() {
			issuer := d
			if index%2 != 0 {
				issuer = other
			}
			token, err := signStateTestPermission(t.Context(), issuer, testVisitorIssuer, permission, now)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, err)
			} else {
				tokens = append(tokens, token)
			}
		})
	}
	workers.Wait()
	if len(failures) != 0 {
		t.Fatal(failures)
	}
	keys := stateTestVisitorKeys(t, other, now)
	if len(keys) != 1 || len(tokens) != 16 {
		t.Fatal("control replicas did not share one signing key")
	}
	view := stateTestVisitorView(permission, keys, now)
	for _, token := range tokens {
		if _, err := visitortoken.VerifyBearer(token, view, now); err != nil {
			t.Fatal(err)
		}
	}
	var ciphertext, public []byte
	var storedKey string
	if err := d.pool.QueryRow(t.Context(), `SELECT seed_ciphertext,public_key,storage_key_id FROM control.visitor_token_keys`).Scan(&ciphertext, &public, &storedKey); err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) <= ed25519.SeedSize || len(public) != ed25519.PublicKeySize || storedKey != d.storageKey.CurrentID() {
		t.Fatal("visitor signing key was not protected")
	}
	if _, err := signStateTestPermission(t.Context(), other, "https://other.example.test", permission, now); !errors.Is(err, ErrVisitorSigningKey) {
		t.Fatal("shared database changed its issuer", err)
	}
}

func TestIntegrationConcurrentVisitorSigningKeyCreation(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_signing_unprepared")
	prepareVisitorTokenKeys(t, d, now)
	request := oidcRouteRequest(t, d, now)
	u := createTestPublicURL(t, d, request, now)
	session := newOIDCSession(t, d, now)
	ctx := WithControlPrincipal(t.Context(), ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID})
	if _, err := d.pool.Exec(ctx, `DELETE FROM control.visitor_token_keys`); err != nil {
		t.Fatal(err)
	}
	scope := visitorscope.Scope{Kind: visitorscope.PublicURL, ID: u.ID}
	start := make(chan struct{})
	type issuance struct {
		issued IssuedVisitorToken
		err    error
	}
	results := make(chan issuance, 8)
	var workers sync.WaitGroup
	for range 8 {
		workers.Go(func() {
			<-start
			issued, err := d.IssueVisitorToken(ctx, testVisitorIssuer, scope, BrowserTokenSource{}, now)
			results <- issuance{issued, err}
		})
	}
	close(start)
	workers.Wait()
	close(results)
	verifiedAt := time.Now().UTC()
	keys := stateTestVisitorKeys(t, d, verifiedAt)
	if len(keys) != 1 {
		t.Fatalf("concurrent issuance created %d signing keys, want one", len(keys))
	}
	for result := range results {
		if result.err != nil || result.issued.Token == "" {
			t.Fatalf("concurrent unprepared signing key creation failed: %v", result.err)
		}
		if _, err := visitortoken.VerifyBearer(result.issued.Token, stateTestVisitorView(result.issued.Permission, keys, verifiedAt), verifiedAt); err != nil {
			t.Fatalf("token from unprepared signing key did not verify: %v", err)
		}
	}
}

type pausedVisitorRetentionTx struct {
	pgx.Tx
	paused chan<- struct{}
	resume <-chan struct{}
}

func (tx pausedVisitorRetentionTx) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	if strings.Contains(sql, "UPDATE control.visitor_token_keys SET retain_until") {
		close(tx.paused)
		select {
		case <-tx.resume:
		case <-ctx.Done():
			return pgconn.CommandTag{}, ctx.Err()
		}
	}
	return tx.Tx.Exec(ctx, sql, args...)
}

func TestIntegrationVisitorSigningKeyRotationWaitsBeforeKeyShare(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "visitor_signing_rotation_before_share")
	prepareVisitorTokenKeys(t, d, now)
	permission := signingTestPermission(now)
	if _, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, permission, now); err != nil {
		t.Fatal(err)
	}
	permission.ExpiresAt = permission.ExpiresAt.Add(time.Second)
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	var blocker int32
	if err := tx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	paused := make(chan struct{})
	resume := make(chan struct{})
	defer func() {
		select {
		case <-resume:
		default:
			close(resume)
		}
	}()
	type signingResult struct {
		token visitortoken.Token
		err   error
	}
	signed := make(chan signingResult, 1)
	go func() {
		token, err := d.signVisitorPermission(t.Context(), pausedVisitorRetentionTx{Tx: tx, paused: paused, resume: resume}, testVisitorIssuer, permission, now)
		signed <- signingResult{token, err}
	}()
	select {
	case <-paused:
	case <-time.After(3 * time.Second):
		t.Fatal("signer did not reach retention check")
	}
	rotation := make(chan error, 1)
	go func() {
		rotation <- d.RotateVisitorSigningKey(t.Context(), testVisitorIssuer, false, now.Add(time.Minute))
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	// rotation must wait on the issuer row before the signer even reads the key.
	waitForPostgresBlock(t, ctx, d, blocker, rotation)
	close(resume)
	var result signingResult
	select {
	case result = <-signed:
		if result.err != nil {
			t.Fatal(result.err)
		}
	case <-ctx.Done():
		t.Fatal("signer did not finish after retention check resumed")
	}
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-rotation:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("rotation did not finish after signer committed")
	}
	keys := stateTestVisitorKeys(t, d, now.Add(time.Minute))
	if len(keys) != 2 {
		t.Fatal("rotation did not retain the issued token key")
	}
	if _, err := visitortoken.VerifyBearer(result.token, stateTestVisitorView(permission, keys, now.Add(time.Minute)), now.Add(time.Minute)); err != nil {
		t.Fatalf("token signed before rotation did not verify: %v", err)
	}
}

func TestIntegrationVisitorSigningKeyRotationRetainsLongCredentialsAndRevokesEmergency(t *testing.T) {
	d, _, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_signing_rotation")
	prepareVisitorTokenKeys(t, d, now)
	permission := signingTestPermission(now)
	permission.ExpiresAt = now.Add(24 * time.Hour)
	tx, err := d.pool.BeginTx(t.Context(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(t.Context())
	token, err := d.signVisitorPermission(t.Context(), tx, testVisitorIssuer, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	var blocker int32
	if err := tx.QueryRow(t.Context(), `SELECT pg_backend_pid()`).Scan(&blocker); err != nil {
		t.Fatal(err)
	}
	rotation := make(chan error, 1)
	go func() {
		rotation <- d.RotateVisitorSigningKey(t.Context(), testVisitorIssuer, false, now.Add(time.Minute))
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	waitForPostgresBlock(t, ctx, d, blocker, rotation)
	if err := tx.Commit(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-rotation:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("rotation did not finish after the signing-key reader committed")
	}
	keys := stateTestVisitorKeys(t, d, now.Add(time.Minute))
	if len(keys) != 2 {
		t.Fatal("ordinary rotation dropped a still-valid token key")
	}
	if _, err := visitortoken.VerifyBearer(token, stateTestVisitorView(permission, keys, now.Add(time.Minute)), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var retained time.Time
	if err := d.pool.QueryRow(t.Context(), `SELECT retain_until FROM control.visitor_token_keys WHERE retired_at IS NOT NULL`).Scan(&retained); err != nil || !retained.Equal(permission.ExpiresAt) {
		t.Fatal("key retention did not follow issued credential lifetime", err)
	}
	if err := d.RotateVisitorSigningKey(t.Context(), testVisitorIssuer, true, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	keys = stateTestVisitorKeys(t, d, now.Add(2*time.Minute))
	if len(keys) != 1 {
		t.Fatal("emergency rotation retained a revoked verification key")
	}
	if _, err := visitortoken.VerifyBearer(token, stateTestVisitorView(permission, keys, now.Add(2*time.Minute)), now.Add(2*time.Minute)); !errors.Is(err, visitortoken.ErrKey) {
		t.Fatal("emergency rotation accepted old token", err)
	}
}

func TestIntegrationStorageRotationIncludesVisitorSigningKeys(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_signing_storage_rotation")
	prepareVisitorTokenKeys(t, d, now)
	permission := signingTestPermission(now)
	first, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	firstKeys := stateTestVisitorKeys(t, d, now)
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{19}, 32))
	rotating, err := Open(t.Context(), url, newKey, testStorageKey)
	if err != nil {
		t.Fatal(err)
	}
	checkLockedRotationCount(t, rotating, `SELECT id FROM control.visitor_token_keys FOR UPDATE`)
	if err := rotating.CompleteStorageKeyRotation(t.Context()); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(t.Context(), url, newKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	second, err := signStateTestPermission(t.Context(), reopened, testVisitorIssuer, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	keys := stateTestVisitorKeys(t, reopened, now)
	if len(keys) != 1 {
		t.Fatal("storage rotation replaced the visitor signing key")
	}
	for id, key := range firstKeys {
		if !bytes.Equal(key, keys[id]) {
			t.Fatal("storage rotation changed verification keys")
		}
	}
	for _, token := range []visitortoken.Token{first, second} {
		if _, err := visitortoken.VerifyBearer(token, stateTestVisitorView(permission, keys, now), now); err != nil {
			t.Fatal(err)
		}
	}
}
