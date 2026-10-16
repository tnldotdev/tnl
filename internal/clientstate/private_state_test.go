package clientstate

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestPublisherSigningScopesUseOneInstalledKey(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := database.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := PublisherSigningIdentity{ID: id, PublicValue: []byte(fmt.Sprintf(`{"client_id":%q}`, id)), PrivateValue: private}
	if err := store.SavePublisherSigningIdentity(t.Context(), "publisher:"+id, identity); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePublisherSigningIdentity(t.Context(), "default-namespace", identity); err != nil {
		t.Fatal(err)
	}
	selected, found, err := store.PublisherSigningIdentity(t.Context(), "default-namespace")
	if err != nil || !found || selected.ID != id || !bytes.Equal(selected.PrivateValue, private) {
		t.Fatalf("selected identity = %q, found=%v: %v", selected.ID, found, err)
	}
	var identities int
	if err := database.db.QueryRowContext(t.Context(), `SELECT count(*) FROM publisher_identities`).Scan(&identities); err != nil || identities != 1 {
		t.Fatalf("installed key rows = %d: %v", identities, err)
	}
}

func TestPublisherEnrollmentScopeRetainsOneRetryKey(t *testing.T) {
	database := openFileDatabase(t, filepath.Join(t.TempDir(), "state"))
	store, err := database.Server(t.Context(), "https://server.example")
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	if err != nil {
		t.Fatal(err)
	}
	secretBytes := make([]byte, 32)
	if _, err := rand.Read(secretBytes); err != nil {
		t.Fatal(err)
	}
	secret := []byte(id + "." + base64.RawURLEncoding.EncodeToString(secretBytes))
	scope := "owner-namespace:team-domain"
	pending := PublisherSigningIdentity{ID: id, PublicValue: []byte("{}"), PrivateValue: secret}
	if err := store.SavePublisherSigningIdentity(t.Context(), scope, pending); err != nil {
		t.Fatal(err)
	}
	initial, found, err := store.PublisherSigningIdentity(t.Context(), "enrollment:"+id)
	if err != nil || !found || len(initial.PrivateValue) != ed25519.PrivateKeySize {
		t.Fatalf("pending key = %d bytes, found=%v: %v", len(initial.PrivateValue), found, err)
	}
	if err := store.SavePublisherSigningIdentity(t.Context(), scope, pending); err != nil {
		t.Fatal(err)
	}
	retry, found, err := store.PublisherSigningIdentity(t.Context(), "enrollment:"+id)
	if err != nil || !found || !bytes.Equal(retry.PrivateValue, initial.PrivateValue) {
		t.Fatalf("enrollment retry changed the signing key: found=%v, %v", found, err)
	}
	identityID, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	installed := PublisherSigningIdentity{ID: identityID, PublicValue: []byte(fmt.Sprintf(`{"client_id":%q}`, identityID)), PrivateValue: retry.PrivateValue}
	if err := store.SavePublisherSigningIdentity(t.Context(), "enrollment:"+id, installed); err != nil {
		t.Fatal(err)
	}
	selected, found, err := store.PublisherSigningIdentity(t.Context(), scope)
	if err != nil || !found || selected.ID != identityID || !bytes.Equal(selected.PrivateValue, retry.PrivateValue) {
		t.Fatalf("enrollment did not promote the scoped identity: found=%v, id=%q, %v", found, selected.ID, err)
	}
}
