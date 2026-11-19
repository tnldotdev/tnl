package state

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSDKPublisherEnrollmentFilesAreSealedAndSlotBound(t *testing.T) {
	root := filepath.Join(t.TempDir(), "state")
	open := func() *Database {
		t.Helper()
		db, err := OpenWithOptions(t.Context(), root, OpenOptions{Protection: ProtectionFile})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	slot := func(db *Database, name string) *PublisherEnrollmentFiles {
		t.Helper()
		files, err := db.PublisherEnrollmentFiles(name)
		if err != nil {
			t.Fatal(err)
		}
		return files
	}

	db := open()
	files := slot(db, "default")
	if _, found, err := files.Read(t.Context(), "identity.json", 8192); found || err != nil {
		t.Fatal("fresh slot was not empty", found, err)
	}
	key := []byte(`{"private_key":"local-secret-must-not-be-in-the-file"}`)
	if err := files.Write(t.Context(), "identity.json", key); err != nil {
		t.Fatal(err)
	}
	sealed, err := os.ReadFile(filepath.Join(root, "sdk-publisher-default.sealed"))
	if err != nil || bytes.Contains(sealed, key) {
		t.Fatal("publisher enrollment was not encrypted", err)
	}
	second := open()
	value, found, err := slot(second, "default").Read(t.Context(), "identity.json", 8192)
	if err != nil || !found || !bytes.Equal(value, key) {
		t.Fatal("reopen did not recover the encrypted slot", found, err)
	}
	other := slot(second, "replica")
	if err := os.WriteFile(filepath.Join(root, "sdk-publisher-replica.sealed"), sealed, 0600); err != nil {
		t.Fatal(err)
	}
	if _, found, err := other.Read(t.Context(), "identity.json", 8192); found || err == nil {
		t.Fatal("a copied record was accepted under another slot", found, err)
	}
	if _, _, err := files.Read(t.Context(), "identity.json", 1); err == nil {
		t.Fatal("record read did not enforce the caller's bound")
	}

	lock, err := files.Lock(t.Context(), "enrollment-owner")
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	blocked, cancel := context.WithTimeout(t.Context(), 40*time.Millisecond)
	defer cancel()
	if _, err := slot(second, "default").Lock(blocked, "enrollment-owner"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("a second owner acquired the same publisher slot", err)
	}
	independent, err := other.Lock(t.Context(), "enrollment-owner")
	if err != nil {
		t.Fatal("another slot was blocked", err)
	}
	if err := independent.Close(); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := slot(second, "default").Lock(t.Context(), "enrollment-owner")
	if err != nil {
		t.Fatal("close did not release the slot", err)
	}
	if err := next.Close(); err != nil {
		t.Fatal(err)
	}
}
