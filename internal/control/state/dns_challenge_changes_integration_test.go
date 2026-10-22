package controlstate

import (
	"crypto/sha256"
	"testing"
	"time"
)

func TestIntegrationDNSChallengeChangeReceiptSurvivesRestart(t *testing.T) {
	databaseURL := newDisposableControlStateDatabaseURL(t, "dns_change_receipt")
	if err := Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	first, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	const recordName = "_acme-challenge.member.example.test"
	oldDigest := sha256.Sum256([]byte("old TXT values"))
	if err := first.SaveDNSChallengeChange(t.Context(), "ZMANAGED", recordName, oldDigest, "/change/old", time.Now()); err != nil {
		t.Fatal(err)
	}
	first.Close()

	restarted, err := Open(t.Context(), databaseURL, testStorageKey, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(restarted.Close)
	change, found, err := restarted.GetDNSChallengeChange(t.Context(), "ZMANAGED", recordName)
	if err != nil || !found || change.ChangeID != "/change/old" || change.DesiredDigest != oldDigest {
		t.Fatalf("restarted change = %#v, found=%t, error=%v", change, found, err)
	}
	newDigest := sha256.Sum256([]byte("values after another authorization finished"))
	if err := restarted.SaveDNSChallengeChange(t.Context(), "ZMANAGED", recordName, newDigest, "/change/new", time.Now()); err != nil {
		t.Fatal(err)
	}
	change, found, err = restarted.GetDNSChallengeChange(t.Context(), "ZMANAGED", recordName)
	if err != nil || !found || change.ChangeID != "/change/new" || change.DesiredDigest != newDigest {
		t.Fatalf("superseding change = %#v, found=%t, error=%v", change, found, err)
	}
	if _, found, err := restarted.GetDNSChallengeChange(t.Context(), "ZOTHER", recordName); err != nil || found {
		t.Fatalf("unrelated zone receipt: found=%t, error=%v", found, err)
	}
}
