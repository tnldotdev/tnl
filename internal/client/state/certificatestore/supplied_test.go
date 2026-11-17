package certificatestore

import (
	"bytes"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil/certificatetest"
)

func TestSuppliedCertificateDurableTransitions(t *testing.T) {
	files := newHostStorage()
	cache := hostCache(t, files)
	now := time.Now()
	issuer := certificatetest.New(t, now)
	first := issuer.Issue(t, []string{"route.example"}, now, now.Add(time.Hour), nil)
	staged, err := cache.StageSupplied(t.Context(), "route.example", first.Chain, first.Key)
	if err != nil || staged.Fingerprint == "" || staged.IssuanceID != "" {
		t.Fatal("supplied staging failed or invented an issuance", err)
	}
	if _, found, err := cache.CurrentSupplied(t.Context(), "route.example"); err != nil || found {
		t.Fatal("staging exposed unacknowledged material", found, err)
	}
	if err := cache.PromoteSupplied(t.Context(), "route.example", "wrong"); err == nil {
		t.Fatal("another fingerprint was promoted")
	}
	if err := cache.PromoteSupplied(t.Context(), "route.example", staged.Fingerprint); err != nil {
		t.Fatal(err)
	}
	restored := hostCache(t, files)
	current, found, err := restored.CurrentSupplied(t.Context(), "route.example")
	if err != nil || !found || current.Fingerprint != staged.Fingerprint ||
		!bytes.Equal(current.Certificate.Certificate[0], first.Certificate.Certificate[0]) {
		t.Fatal("restore lost exact supplied key or leaf", err)
	}
	if _, _, err := restored.Current(t.Context(), "route.example"); err == nil {
		t.Fatal("managed path adopted supplied material as an issuance")
	}
	second := issuer.Issue(t, []string{"route.example"}, now, now.Add(2*time.Hour), nil)
	replacement, err := cache.StageSupplied(t.Context(), "route.example", second.Chain, second.Key)
	if err != nil {
		t.Fatal(err)
	}
	current, found, err = restored.CurrentSupplied(t.Context(), "route.example")
	if err != nil || !found || current.Fingerprint != staged.Fingerprint {
		t.Fatal("unacknowledged replacement displaced the current key", err)
	}
	if err := restored.PromoteSupplied(t.Context(), "route.example", replacement.Fingerprint); err != nil {
		t.Fatal(err)
	}
	current, found, err = cache.CurrentSupplied(t.Context(), "route.example")
	if err != nil || !found || current.Fingerprint != replacement.Fingerprint {
		t.Fatal("replacement did not become current", err)
	}
	if _, err := cache.StageSupplied(t.Context(), "other.example", first.Chain, first.Key); err == nil {
		t.Fatal("storage accepted a hostname outside the plan")
	}
}
