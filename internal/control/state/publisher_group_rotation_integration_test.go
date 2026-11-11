package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming"
)

func TestIntegrationStorageRotationPublisherGroupBindings(t *testing.T) {
	d, url, now := newControlStateIntegrationDatabaseWithURL(t, "rotation_group_bindings")
	ctx := t.Context()
	r := appliedProjectRequest(t, d, now)
	r.Configuration = ProjectConfiguration{PublisherGroups: map[string]ProjectPublisherGroup{"customer": {Template: true}}, Services: map[string]ProjectServiceConfiguration{"api": {PublisherGroup: "customer", Protocol: "http", TargetBinding: "group"}}}
	current, err := d.ApplyProjectConfiguration(ctx, r)
	if err != nil {
		t.Fatal(err)
	}
	groups := []PublisherGroupResource{}
	digest := sha256.Sum256([]byte("tnl-target-tls/v1\x00equipment.internal\x00"))
	for _, name := range []string{"active", "retired"} {
		group, err := d.CreateBoundPublisherGroup(ctx, CreateBoundPublisherGroupRequest{TeamID: r.TeamID, ProjectKey: r.ProjectKey, ActorID: r.ActorID, ExpectedRevision: current.Revision, Now: now, Creation: PublisherGroupCreation{Name: name, Template: "customer", Bindings: PublisherGroupBindings{"api": {Target: name + ".internal:8443", TargetTLS: &ProjectTargetTLS{Hostname: "equipment.internal", Digest: hex.EncodeToString(digest[:])}}}}})
		if err != nil {
			t.Fatal(err)
		}
		current.Revision = group.Revision
		groups = append(groups, group)
	}
	if _, err := d.RemovePublisherGroup(ctx, r.TeamID, r.ProjectKey, groups[1].ID, r.ActorID, current.Revision, false, now); err != nil {
		t.Fatal(err)
	}
	d.Close()
	newKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{17}, 32))
	rotating, err := Open(ctx, url, newKey, testStorageKey, naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(rotating.Close)
	// one active row stays locked while all other old-key rows, including the
	// retired binding, rotate. completion must still count the locked binding.
	checkLockedRotationCount(t, rotating, fmt.Sprintf(`SELECT group_id FROM control.publisher_group_bindings WHERE group_id='%s' FOR UPDATE`, groups[0].ID))
	if err := rotating.CompleteStorageKeyRotation(ctx); err != nil {
		t.Fatal(err)
	}
	if remaining, err := rotating.countPreviousStorageSecrets(ctx); err != nil || remaining != 0 {
		t.Fatal("rotation left old-key material", remaining, err)
	}
	rotating.Close()
	reopened, err := Open(ctx, url, newKey, "", naming.ManagedURLModeGenerated)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(reopened.Close)
	for i, before := range groups {
		after, err := reopened.GetManagedPublisherGroup(ctx, r.TeamID, r.ProjectKey, before.ID, r.ActorID)
		if err != nil || after.ID != before.ID || after.Name != before.Name || after.Retired != (i == 1) {
			t.Fatal("group identity lost after retiring old storage key", after, err)
		}
		binding := after.Bindings["api"]
		if binding.Target != before.Bindings["api"].Target || binding.TargetTLS == nil || *binding.TargetTLS != *before.Bindings["api"].TargetTLS || binding.protocol != "http" {
			t.Fatal("saved target/TLS/protocol lost during rotation", binding)
		}
		if i == 0 && (len(after.Services) != 1 || after.Services[0].ServiceID != before.Services[0].ServiceID || after.Services[0].Hostname != before.Services[0].Hostname || after.Services[0].Port != before.Services[0].Port) {
			t.Fatal("active endpoint changed during rotation", after.Services)
		}
		var preserved bool
		if err := reopened.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM control.services WHERE id=$1)`, before.Services[0].ServiceID).Scan(&preserved); err != nil || !preserved {
			t.Fatal("rotation discarded saved service identity", err)
		}
	}
}
