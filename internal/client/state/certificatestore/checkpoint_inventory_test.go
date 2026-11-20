package certificatestore

import (
	"bytes"
	"fmt"
	"testing"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestCertificateCheckpointInventoryBeyond1024Plans(t *testing.T) {
	storage := newHostStorage()
	scope := Scope{ControlURL: "https://control.example", TeamID: "team", PublisherIdentityID: "pub_0123456789abcdefghijkl"}
	plans := make([]controlv1.CertificatePlan, 1025)
	var first Pending
	for i := range plans {
		name := fmt.Sprintf("app-%d.example", i)
		plans[i] = controlv1.CertificatePlan{CacheKey: name, Scope: name, Identifiers: []string{name}, ChallengeMethod: controlv1.Dns01}
		cache, err := New(storage, scope, plans[i])
		if err != nil {
			t.Fatal(err)
		}
		pending, err := cache.Pending(t.Context(), name)
		if err != nil {
			t.Fatalf("plan %d: %v", i, err)
		}
		if i == 0 {
			first = pending
		}
	}
	cache, err := New(storage, scope, plans[0])
	if err != nil {
		t.Fatal(err)
	}
	checkpoints, err := cache.checkpoints(t.Context())
	if err != nil || len(checkpoints) != len(plans) {
		t.Fatal("checkpoint inventory was truncated", len(checkpoints), err)
	}
	recovered, err := cache.Pending(t.Context(), plans[0].CacheKey)
	if err != nil || !bytes.Equal(first.CSRDER, recovered.CSRDER) {
		t.Fatal("growing history replaced an older key", err)
	}
	if err := RequirePlans(t.Context(), storage, scope, plans); err != nil {
		t.Fatal(err)
	}
	entries := make([]string, 0, len(storage.records))
	for name := range storage.records {
		entries = append(entries, name)
	}
	if found, err := MaterialExists(t.Context(), storage, scope, entries); err != nil || !found {
		t.Fatal("complete inventory did not recover", err)
	}
	delete(storage.records, certificateFilename(cache.planJSON))
	if err := RequirePlans(t.Context(), storage, scope, plans); err == nil {
		t.Fatal("missing old key escaped the full control inventory")
	}
	if _, err := MaterialExists(t.Context(), storage, scope, entries); err == nil {
		t.Fatal("partial restoration escaped the durable checkpoint")
	}
}
