package state

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

func TestPublisherCertificateCacheIsolationAndOwnReuse(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	store := testStore(t, root, "https://server.example")
	firstID, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	secondID, err := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	plan := exactCertificateTestPlan()
	first, err := store.CertificatesForPublisher("team", firstID, plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.CertificatesForPublisher("team", secondID, plan)
	if err != nil {
		t.Fatal(err)
	}
	firstPending, err := first.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	secondPending, err := second.Pending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	if firstPending.Key.PublicKey.Equal(&secondPending.Key.PublicKey) || bytes.Equal(firstPending.CSRDER, secondPending.CSRDER) {
		t.Fatal("private keys/CSRs crossed publisher boundaries")
	}
	if first.plan.CacheKey != plan.CacheKey || second.plan.CacheKey != plan.CacheKey {
		t.Fatal("local cache scoping changed the server's certificate plan")
	}
	lock, err := first.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	otherLock, err := second.Lock(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = otherLock.Close()
	duplicate, err := store.CertificatesForPublisher("team", firstID, plan)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if duplicateLock, err := duplicate.Lock(ctx); !errors.Is(err, context.DeadlineExceeded) {
		if duplicateLock != nil {
			_ = duplicateLock.Close()
		}
		t.Fatalf("same publisher did not serialize its cache: %v", err)
	}
	renewAt := time.Now().Add(time.Hour)
	if _, err = second.Stage(t.Context(), "route.example", firstPending, signedCertificate(t, firstPending.Key, "route.example"), renewAt, "foreign"); err == nil {
		t.Fatal("one publisher staged another publisher's pending key")
	}
	firstMaterial, err := first.Stage(t.Context(), "route.example", firstPending, signedCertificate(t, firstPending.Key, "route.example"), renewAt, "first-issuance")
	if err != nil {
		t.Fatal(err)
	}
	secondMaterial, err := second.Stage(t.Context(), "route.example", secondPending, signedCertificate(t, secondPending.Key, "route.example"), renewAt, "second-issuance")
	if err != nil {
		t.Fatal(err)
	}
	if err = first.Promote(t.Context(), "route.example", secondMaterial.IssuanceID); err == nil {
		t.Fatal("foreign issuance was promoted into this publisher")
	}
	if err = first.Promote(t.Context(), "route.example", firstMaterial.IssuanceID); err != nil {
		t.Fatal(err)
	}
	if err = second.Promote(t.Context(), "route.example", secondMaterial.IssuanceID); err != nil {
		t.Fatal(err)
	}
	if err = lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err = store.database.Close(); err != nil {
		t.Fatal(err)
	}
	store = testStore(t, root, "https://server.example")
	first, err = store.CertificatesForPublisher("team", firstID, plan)
	if err != nil {
		t.Fatal(err)
	}
	second, err = store.CertificatesForPublisher("team", secondID, plan)
	if err != nil {
		t.Fatal(err)
	}
	for _, selected := range []struct {
		cache       *CertificateCache
		issuance    string
		certificate []byte
	}{{first, firstMaterial.IssuanceID, firstMaterial.Certificate.Certificate[0]}, {second, secondMaterial.IssuanceID, secondMaterial.Certificate.Certificate[0]}} {
		current, found, err := selected.cache.Current(t.Context(), "route.example")
		if err != nil || !found || current.IssuanceID != selected.issuance || !bytes.Equal(current.Certificate.Certificate[0], selected.certificate) {
			t.Fatalf("publisher lost own reusable certificate after reopening: %t %v", found, err)
		}
	}
	old, err := first.NewPending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	newer, err := first.NewPending(t.Context(), "route.example")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = first.Stage(t.Context(), "route.example", old, signedCertificate(t, old.Key, "route.example"), renewAt, "old-renewal"); err == nil {
		t.Fatal("stale pending renewal replaced a newer CSR")
	}
	currentPending, err := first.Pending(t.Context(), "route.example")
	if err != nil || !bytes.Equal(newer.CSRDER, currentPending.CSRDER) {
		t.Fatal("rejected renewal changed the pending key", err)
	}
}

func TestPublisherHostnameLocksAllowExplicitPoolPeers(t *testing.T) {
	store := testStore(t, filepath.Join(t.TempDir(), "state"), "https://server.example")
	firstID, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	secondID, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	first, err := LockPublisherHostnameContext(t.Context(), store, "route.example", firstID)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := LockPublisherHostnameContext(t.Context(), store, "route.example", secondID)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Millisecond)
	defer cancel()
	if repeated, err := LockPublisherHostnameContext(ctx, store, "route.example", firstID); !errors.Is(err, context.DeadlineExceeded) {
		if repeated != nil {
			_ = repeated.Close()
		}
		t.Fatalf("publisher's concurrent invocation did not share hostname lock: %v", err)
	}
	if _, err = store.CertificatesForPublisher("team", "", exactCertificateTestPlan()); err == nil {
		t.Fatal("certificate cache accepted an empty publisher identity")
	}
}
