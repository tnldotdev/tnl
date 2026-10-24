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

func TestIntegrationVisitorSigningKeyRotationRetainsLongCredentialsAndRevokesEmergency(t *testing.T) {
	d, _, now := newControlStateIntegrationDatabaseWithURL(t, "visitor_signing_rotation")
	prepareVisitorTokenKeys(t, d, now)
	permission := signingTestPermission(now)
	permission.ExpiresAt = now.Add(24 * time.Hour)
	token, err := signStateTestPermission(t.Context(), d, testVisitorIssuer, permission, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.RotateVisitorSigningKey(t.Context(), testVisitorIssuer, false, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
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
