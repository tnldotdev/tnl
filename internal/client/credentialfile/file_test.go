package credentialfile

import (
	"crypto/ed25519"
	"crypto/rand"
	json "encoding/json/v2"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	f, err := New("https://control.example", authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), TeamId: "team", Kind: "saved_public_url", PublicUrlId: &url}, key)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestApplicationCredentialSelectsExplicitOperationsWithoutDefaultWidening(t *testing.T) {
	f := fixture(t)
	publish := f.Grants[0]
	visit := publish
	visit.ID, visit.Operation = "pgrant_"+strings.Repeat("V", 22), controlv1.ApplicationVisit
	domain, namespace := "dom_"+strings.Repeat("D", 22), "member.example.test"
	allocate := Grant{ID: "pgrant_" + strings.Repeat("N", 22), Operation: controlv1.ApplicationAllocate, Kind: "namespace", DomainID: &domain, Namespace: &namespace}
	f.Grants = append(f.Grants, visit, allocate)
	private, err := f.Validate()
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range f.Grants {
		resource, _ := grant.resource()
		selected, err := f.Select(grant.Operation, resource)
		if err != nil || selected.ID != grant.ID {
			t.Fatal("operation selection changed an exact grant", err)
		}
	}
	if _, err := f.Select(controlv1.ApplicationVisit, domain); !errors.Is(err, ErrGrant) {
		t.Fatal("visit selection borrowed allocation authority", err)
	}
	if _, _, err := f.Publisher(""); !errors.Is(err, ErrGrant) {
		t.Fatal("several publication grants silently selected a default", err)
	}
	if identity, _, err := f.Publisher(*publish.PublicURLID); err != nil || identity.GrantId != publish.ID {
		t.Fatal("exact publication selection lost its grant", err)
	}
	visitOnly := f
	visitOnly.Grants = []Grant{visit}
	if _, _, err := visitOnly.Publisher(""); !errors.Is(err, ErrGrant) {
		t.Fatal("visit-only document became a publisher", err)
	}
	deadline := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	f.Grants[1].ExpiresAt = &deadline
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := Parse(data)
	if err != nil || loaded.ClientID != f.ClientID || len(loaded.Grants) != 3 || !loaded.Grants[1].ExpiresAt.Equal(deadline) {
		t.Fatal("credential document lost captured operation or expiry", err)
	}
	key, err := loaded.Validate()
	if err != nil || !key.Equal(private) {
		t.Fatal("several capabilities acquired different signing keys", err)
	}
	for _, format := range []string{"%v", "%+v", "%#v"} {
		if strings.Contains(fmt.Sprintf(format, f), f.PrivateKey) {
			t.Fatal("credential formatting exposed the signing key")
		}
	}
}

func TestApplicationCredentialRejectsLegacyAmbiguityAndAllNestedNulls(t *testing.T) {
	f := fixture(t)
	data, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(string(data), `"grants":[`, `"grants":[null,`, 1),
		strings.Replace(string(data), `"grants":[{`, `"grants":[{"service_id":null,`, 1),
		strings.Replace(string(data), `"grants":[{`, `"grants":[{"unknown":"private-value",`, 1),
		strings.Replace(string(data), `"version":1`, `"version":1,"version":1`, 1),
		`{"version":1,"publisher_identity_id":"old","grant_id":"old","kind":"saved_public_url","private_key":"private-value"}`,
	} {
		if _, err := Parse([]byte(raw)); !errors.Is(err, ErrInvalid) {
			t.Fatal("superseded or ambiguous credential shape was accepted", err)
		}
	}
	for _, fault := range []string{"duplicate ID", "duplicate binding", "empty", "overflow"} {
		invalid := f
		invalid.Grants = append([]Grant{}, f.Grants...)
		switch fault {
		case "duplicate ID":
			other := invalid.Grants[0]
			id := "url_" + strings.Repeat("Z", 22)
			other.PublicURLID = &id
			invalid.Grants = append(invalid.Grants, other)
		case "duplicate binding":
			other := invalid.Grants[0]
			other.ID = "pgrant_" + strings.Repeat("Z", 22)
			invalid.Grants = append(invalid.Grants, other)
		case "empty":
			invalid.Grants = nil
		case "overflow":
			invalid.Grants = make([]Grant, 65)
		}
		if _, err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatal("ambiguous grant list was accepted", fault, err)
		}
	}
}

func TestApplicationCredentialMaximumGrantDocumentIsBoundedAndComplete(t *testing.T) {
	f := fixture(t)
	f.Grants = make([]Grant, 64)
	for index := range f.Grants {
		domain := fmt.Sprintf("dom_%022d", index)
		namespace := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
		expires := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
		f.Grants[index] = Grant{ID: fmt.Sprintf("pgrant_%022d", index), Operation: controlv1.ApplicationAllocate, Kind: "namespace", DomainID: &domain, Namespace: &namespace, ExpiresAt: &expires}
	}
	data, err := json.Marshal(f)
	if err != nil || len(data) > MaxBytes {
		t.Fatal("maximum credential exceeds its byte budget", err)
	}
	parsed, err := Parse(data)
	if err != nil || len(parsed.Grants) != 64 {
		t.Fatal("maximum credential was rejected or truncated", err)
	}
	for _, grant := range f.Grants {
		if selected, err := parsed.Select(controlv1.ApplicationAllocate, *grant.DomainID); err != nil || selected.ID != grant.ID {
			t.Fatal("maximum credential changed an exact grant", err)
		}
	}
}

func TestServiceGrantRoundTripsOnlyExactBinding(t *testing.T) {
	base := fixture(t)
	id, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	base.Grants[0].Kind, base.Grants[0].PublicURLID, base.Grants[0].ServiceID = "service", nil, &id
	identity, key, err := base.Publisher("")
	if err != nil || identity.ServiceId == nil || *identity.ServiceId != id {
		t.Fatalf("private binding: %v", err)
	}
	portable, err := New(base.ControlURL, identity, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := Write(path, portable); err != nil {
		t.Fatal(err)
	}
	loaded, err := Read(path)
	if err != nil || len(loaded.Grants) != 1 || loaded.Grants[0].ServiceID == nil || *loaded.Grants[0].ServiceID != id || loaded.Grants[0].PublicURLID != nil || loaded.Grants[0].DomainID != nil || loaded.Grants[0].Namespace != nil {
		t.Fatalf("private file round trip: %v", err)
	}
	url, domain, namespace := "url_invalid", "dom_invalid", "member.example"
	for _, change := range []func(*File){
		func(f *File) { f.Grants[0].ServiceID = nil },
		func(f *File) { f.Grants[0].ServiceID = &url },
		func(f *File) { f.Grants[0].PublicURLID = &url },
		func(f *File) { f.Grants[0].DomainID = &domain },
		func(f *File) { f.Grants[0].Namespace = &namespace },
		func(f *File) { f.Grants[0].Kind = "namespace" },
		func(f *File) { f.Grants[0].Kind = "saved_public_url" },
	} {
		invalid := base
		invalid.Grants = append([]Grant{}, base.Grants...)
		change(&invalid)
		if _, err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid private binding accepted: %v", err)
		}
	}
	for _, body := range []string{`{"version":1,"version":1}`, `{"version":1,"service_id":null}`} {
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := Read(path); !errors.Is(err, ErrInvalid) {
			t.Fatalf("ambiguous file accepted: %v", err)
		}
	}
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
	if err != nil || loaded.PrivateKey != f.PrivateKey || loaded.ControlURL != f.ControlURL || len(loaded.Grants) != 1 || loaded.Grants[0].PublicURLID == nil || *loaded.Grants[0].PublicURLID != *f.Grants[0].PublicURLID {
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
		func(f *File) { f.Grants[0].Kind = "namespace" },
		func(f *File) { f.PrivateKey = strings.Repeat("A", 86) },
	} {
		invalid := f
		invalid.Grants = append([]Grant{}, f.Grants...)
		change(&invalid)
		if _, err := invalid.Validate(); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid scope accepted: %v", err)
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
