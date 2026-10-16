package credentialfile

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func fixture(t *testing.T) File {
	t.Helper()
	id := func(prefix string) string {
		v, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	url := id(opaqueid.PublicURLPrefix)
	f, err := New("https://control.example", authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), TeamId: "team", Kind: "saved_url", PublicUrlId: &url}, key)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestPortableFileRejectsReplacementSymlinkAndPermissiveModes(t *testing.T) {
	f := fixture(t)
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := Write(path, f); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, f); !errors.Is(err, ErrExists) {
		t.Fatalf("overwrote existing key: %v", err)
	}
	loaded, err := Read(path)
	if err != nil || loaded.PrivateKey != f.PrivateKey || loaded.ControlURL != f.ControlURL || loaded.PublicURLID == nil || *loaded.PublicURLID != *f.PublicURLID {
		t.Fatalf("portable file round trip: %v", err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); err != nil {
		t.Fatalf("read-only file: %v", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("permissive file accepted: %v", err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("other.json", path); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("symlink accepted: %v", err)
	}
	if err := Write(path, f); !errors.Is(err, ErrExists) {
		t.Fatalf("symlink replaced: %v", err)
	}
}

func TestPortableFileFailsClosedOnMalformedScopeAndUnknownFields(t *testing.T) {
	f := fixture(t)
	for _, change := range []func(*File){
		func(f *File) { f.Version = 2 },
		func(f *File) { f.ControlURL = "https://CONTROL.example/" },
		func(f *File) { f.Kind = "namespace" },
		func(f *File) { f.PrivateKey = strings.Repeat("A", 86) },
	} {
		invalid := f
		change(&invalid)
		if _, _, err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid scope accepted: %+v, %v", invalid.Kind, err)
		}
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"unknown":"secret"}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(path); !errors.Is(err, ErrInvalid) {
		t.Fatalf("unknown fields accepted: %v", err)
	}
	if strings.Contains(ErrInvalid.Error(), f.PrivateKey) {
		t.Fatal("key in error")
	}
}
