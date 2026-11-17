package state

import (
	"bytes"
	"encoding/base64"
	"reflect"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationStorageRotationRestoredLockedServicePolicyCount(t *testing.T) {
	d, databaseURL, now := newControlStateIntegrationDatabaseWithURL(t, "restored_locked_policy")
	ctx := t.Context()
	actor := oidcRouteRequest(t, d, now)
	declaration := &ProjectServiceConfiguration{Target: "localhost:3000",
		HTTP: &config.HTTPService{Access: &config.Access{Mode: "restricted", IP: []string{"192.0.2.0/24", "2001:db8::/64"}}}}
	service, err := d.CreateServiceAt(ctx, actor.TeamID, actor.ActingIdentityID, "locked-policy", "locked-policy",
		ServicePlacement{}, now, ServiceMetadata{Protocol: "http"}, declaration)
	if err != nil {
		t.Fatal(err)
	}
	before, digest, err := d.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	var oldCipher []byte
	var oldKey string
	if err := d.pool.QueryRow(ctx, `SELECT configuration_ciphertext,storage_key_id FROM control.services WHERE id=$1`,
		service.ID).Scan(&oldCipher, &oldKey); err != nil {
		t.Fatal(err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	rotating, err := Open(ctx, databaseURL, newKey, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotating.Close)
	gate, err := rotating.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer rollbackTestTransaction(t, gate)
	if _, err := gate.Exec(ctx, `SELECT id FROM control.services WHERE id=$1 FOR UPDATE`, service.ID); err != nil {
		t.Fatal(err)
	}
	for {
		n, err := rotating.ReencryptStorageSecrets(ctx, 1)
		if err != nil || n > 1 {
			t.Fatal("bounded storage rotation failed", n, err)
		}
		if n == 0 {
			break
		}
	}
	if remaining, err := rotating.countPreviousStorageSecrets(ctx); err != nil || remaining != 1 {
		t.Fatalf("locked service policy omitted from previous-key count: remaining=%d, want 1: %v", remaining, err)
	}
	if err := gate.Rollback(ctx); err != nil {
		t.Fatal(err)
	}
	if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
		t.Fatal(err)
	}
	rotating.Close()
	reopened, err := Open(ctx, databaseURL, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	after, nextDigest, err := reopened.GetServiceConfiguration(ctx, service.ID, actor.ActingIdentityID)
	if err != nil || !reflect.DeepEqual(after, before) || nextDigest != digest {
		t.Fatal("retiring the old key changed the exact protected IP policy or digest", err)
	}
	var cipher []byte
	var key string
	if err := reopened.pool.QueryRow(ctx, `SELECT configuration_ciphertext,storage_key_id FROM control.services WHERE id=$1`,
		service.ID).Scan(&cipher, &key); err != nil || key == oldKey || bytes.Equal(cipher, oldCipher) ||
		bytes.Contains(cipher, []byte("192.0.2.")) || bytes.Contains(cipher, []byte("2001:db8")) {
		t.Fatal("locked service policy was not privately re-encrypted", err)
	}
}
