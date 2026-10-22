package credentialfile

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func groupFixture(t *testing.T) GroupFile {
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
	value, err := NewGroup("https://control.example", "replica-1", controlv1.PublisherGroupMember{TeamId: id(opaqueid.TeamPrefix), ProjectKey: "shop", GroupName: "production", GroupId: id("pgrp_"), PublisherIdentityId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix)}, key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestGroupIdentityUsesAppliedProjectKeyBounds(t *testing.T) {
	value := groupFixture(t)
	for _, key := range []string{"project-" + strings.Repeat("a", 48), strings.Repeat("a", 63)} {
		value.Member.ProjectKey = key
		if _, err := value.Validate(value.ControlURL, key, value.Member.GroupName, value.Instance); err != nil {
			t.Fatalf("valid applied project key rejected: %v", err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseGroup(encoded); err != nil {
			t.Fatalf("valid portable project key rejected: %v", err)
		}
	}
	value.Member.ProjectKey = strings.Repeat("a", 64)
	if _, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.GroupName, value.Instance); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized project key accepted: %v", err)
	}
}

func TestGroupIdentityFileAndInjectedJSONHaveTheSamePrivateContract(t *testing.T) {
	value := groupFixture(t)
	path := filepath.Join(t.TempDir(), "replica-1.json")
	if err := WriteGroup(path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("export did not create a private file", err)
	}
	loaded, err := ReadGroup(path)
	if err != nil || loaded != value {
		t.Fatal("private group file did not round trip", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	injected, err := ParseGroup(data)
	if err != nil || injected != value {
		t.Fatal("ECS JSON injection changed the identity", err)
	}
	if err := WriteGroup(path, groupFixture(t)); !errors.Is(err, ErrExists) {
		t.Fatal("export overwrote a provisioned identity", err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGroup(path); err != nil {
		t.Fatal("read-only secret mount rejected", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGroup(path); !errors.Is(err, ErrInvalid) {
		t.Fatal("public-readable identity accepted", err)
	}
	link := filepath.Join(filepath.Dir(path), "symlink.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadGroup(link); !errors.Is(err, ErrInvalid) {
		t.Fatal("symlink accepted", err)
	}
	if err := WriteGroup(link, value); !errors.Is(err, ErrExists) {
		t.Fatal("symlink replaced", err)
	}
	for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), ErrInvalid.Error()} {
		if strings.Contains(rendered, value.PrivateKey) {
			t.Fatal("private key leaked in diagnostic formatting")
		}
	}
}

func TestGroupIdentityRejectsAmbiguousJSONAndDifferentDeploymentScope(t *testing.T) {
	value := groupFixture(t)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	for _, invalid := range []string{
		"", "null", valid + valid, strings.Repeat(" ", 8193),
		strings.Replace(valid, `"version":1`, `"version":1,"version":1`, 1),
		strings.Replace(valid, `"version":1`, `"version":1,"session":"must-not-be-accepted"`, 1),
		strings.Replace(valid, `"member":{`, `"member":{"extra":true,`, 1),
		strings.Replace(valid, `"member":{`, `"member":{"team_id":null,`, 1),
		strings.Replace(valid, `"version":1`, `"version":null`, 1),
		strings.Replace(valid, value.PrivateKey, base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)), 1),
	} {
		if _, err := ParseGroup([]byte(invalid)); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid or ambiguous group identity accepted", err)
		}
	}
	for _, scope := range [][4]string{
		{"https://other.example", "shop", "production", "replica-1"},
		{value.ControlURL, "other", "production", "replica-1"},
		{value.ControlURL, "shop", "production", "replica-2"},
	} {
		if _, err := value.Validate(scope[0], scope[1], scope[2], scope[3]); !errors.Is(err, ErrInvalid) {
			t.Fatal("identity accepted for another deployment scope", err)
		}
	}
}
