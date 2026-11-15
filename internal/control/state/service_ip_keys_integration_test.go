package state

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/control/state/controlstatedb"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/policy/httpprotection"
	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
	"github.com/tnldotdev/tnl/internal/policy/visitorscope"
)

func TestIntegrationHTTPProtectionDigestPrivacyAndStorageRotation(t *testing.T) {
	f := newProtectionServiceFixture(t, httpprotection.Settings{TemporaryBlocks: true})
	d, ctx := f.database, t.Context()
	scope := visitorscope.Scope{Kind: visitorscope.Service, ID: f.service.ID}
	policy, err := d.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now)
	if err != nil || len(policy.TemporaryBlockKey) != 32 {
		t.Fatal("missing protected service key", err)
	}
	evidence := rejectionEvidence(f.now)
	evidence.SourceDigest, err = ippolicy.HashAddress([32]byte(policy.TemporaryBlockKey), netip.MustParseAddr("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	if err := d.ReportHTTPProtectionRejections(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, evidence, f.now); err != nil {
		t.Fatal(err)
	}
	var persisted string
	if err := d.pool.QueryRow(ctx, `SELECT row_to_json(b)::text FROM control.http_temporary_blocks b WHERE service_id=$1`, scope.ID).Scan(&persisted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(persisted, "192.0.2.1") || !strings.Contains(persisted, evidence.SourceDigest) {
		t.Fatal("block retained a raw address or lost its digest")
	}
	tx, err := d.pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback(ctx)
	q := controlstatedb.New(tx)
	private, err := d.ensureServiceIPKey(ctx, q, scope.ID, "test-private-audit")
	if err != nil || bytes.Equal(private, policy.TemporaryBlockKey) {
		t.Fatal("unrelated purpose reused the distributed key", err)
	}
	other, err := d.ensureServiceIPKey(ctx, q, f.local(t, "isolated", nil).ID, temporaryBlockIPKeyPurpose)
	if err != nil || bytes.Equal(other, policy.TemporaryBlockKey) {
		t.Fatal("services shared an IP key", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	old, err := controlstatedb.New(d.pool).ReadServiceIPKey(ctx, controlstatedb.ReadServiceIPKeyParams{ServiceID: scope.ID, Purpose: temporaryBlockIPKeyPurpose})
	if err != nil || bytes.Contains(old.KeyCiphertext, policy.TemporaryBlockKey) {
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
	after, err := reopened.ReadPublisherVisitorPolicy(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, 0, f.now)
	if err != nil || !bytes.Equal(after.TemporaryBlockKey, policy.TemporaryBlockKey) || len(after.TemporaryBlocks) != 1 {
		t.Fatal("storage rotation lost an active source binding", err)
	}
	if !after.TemporaryBlocks[0].ExpiresAt.Equal(f.now.Add(time.Minute)) {
		t.Fatal("rotation changed block expiry")
	}
	if err := reopened.ReportHTTPProtectionRejections(ctx, scope, f.run.RunID, f.run.RunNumber, f.run.Token, evidence, f.now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	current, err := controlstatedb.New(reopened.pool).ReadServiceIPKey(ctx, controlstatedb.ReadServiceIPKeyParams{ServiceID: scope.ID, Purpose: temporaryBlockIPKeyPurpose})
	if err != nil || current.StorageKeyID != reopened.storageKey.CurrentID() || bytes.Equal(current.KeyCiphertext, old.KeyCiphertext) {
		t.Fatal("rotation retained the old wrapping key", err)
	}
	encoded, err := json.Marshal(after)
	if err != nil || bytes.Contains(encoded, []byte("192.0.2.1")) {
		t.Fatal("policy snapshot exposed a raw blocked address", err)
	}
	blocks, err := httpprotection.DecodeBlocks(after.TemporaryBlockKey, after.TemporaryBlocks)
	if err != nil || !blocks.Blocked(netip.MustParseAddr("::ffff:192.0.2.1"), f.now) ||
		blocks.Blocked(netip.MustParseAddr("192.0.2.1"), f.now.Add(time.Minute)) {
		t.Fatal("rotation changed matching or local expiry", err)
	}
}
