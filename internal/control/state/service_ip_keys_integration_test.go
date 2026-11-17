package state

import (
	"bytes"
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationServiceDigestPrivacyAndStorageRotation(t *testing.T) {
	f := newServiceHTTPFixture(t)
	d, ctx := f.database, t.Context()
	otherService := f.local(t, "isolated", nil).ID
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := controlstatedb.New(tx)
	purposes := []string{serviceAuditIPKeyPurpose, publicVisitorIPKeyPurpose, "connector-audit-binding"}
	digests := make(map[string]string, len(purposes))
	var originalKey []byte
	for _, purpose := range purposes {
		digest, err := d.serviceIPDigest(ctx, q, f.service.ID, purpose, netip.MustParseAddr("192.0.2.1"))
		if err != nil {
			t.Fatal(err)
		}
		for previous, value := range digests {
			if value == digest {
				t.Fatal("private key purposes shared a digest", previous, purpose)
			}
		}
		digests[purpose] = digest
		key, err := d.readServiceIPKey(ctx, q, f.service.ID, purpose)
		if err != nil || len(key) != 32 {
			t.Fatal("missing private service key", err)
		}
		if purpose == serviceAuditIPKeyPurpose {
			originalKey = key
		}
		other, err := d.ensureServiceIPKey(ctx, q, otherService, purpose)
		if err != nil || bytes.Equal(other, key) {
			t.Fatal("services shared an IP key", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	old, err := controlstatedb.New(d.pool).ReadServiceIPKey(ctx, controlstatedb.ReadServiceIPKeyParams{ServiceID: f.service.ID, Purpose: serviceAuditIPKeyPurpose})
	if err != nil || bytes.Contains(old.KeyCiphertext, originalKey) {
		t.Fatal("service key was not encrypted", err)
	}
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))
	rotating, err := Open(ctx, d.pool.Config().ConnString(), newKey, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer rotating.Close()
	if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(ctx, d.pool.Config().ConnString(), newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	for purpose, original := range digests {
		after, err := reopened.readServiceIPDigest(ctx, controlstatedb.New(reopened.pool), f.service.ID, purpose, netip.MustParseAddr("::ffff:192.0.2.1"))
		if err != nil || after != original {
			t.Fatal("storage-key rotation changed a private source binding", purpose, err)
		}
	}
	current, err := controlstatedb.New(reopened.pool).ReadServiceIPKey(ctx, controlstatedb.ReadServiceIPKeyParams{ServiceID: f.service.ID, Purpose: serviceAuditIPKeyPurpose})
	if err != nil || current.StorageKeyID != reopened.storageKey.CurrentID() || bytes.Equal(current.KeyCiphertext, old.KeyCiphertext) {
		t.Fatal("rotation retained the old wrapping key", err)
	}
}
