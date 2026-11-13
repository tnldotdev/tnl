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
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func deploymentFixture(t *testing.T) DeploymentFile {
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
	value, err := NewDeployment("https://control.example", "replica-1", controlv1.DeploymentPublisherIdentity{TeamId: id(opaqueid.TeamPrefix), ProjectKey: "shop", DeploymentName: "production", DeploymentId: id("dpl_"), PublisherIdentityId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix)}, key)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func TestDeploymentIdentityUsesAppliedProjectKeyBounds(t *testing.T) {
	value := deploymentFixture(t)
	for _, key := range []string{"project-" + strings.Repeat("a", 48), strings.Repeat("a", 63)} {
		value.Member.ProjectKey = key
		if _, err := value.Validate(value.ControlURL, key, value.Member.DeploymentName, value.Instance); err != nil {
			t.Fatalf("valid applied project key rejected: %v", err)
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseDeployment(encoded); err != nil {
			t.Fatalf("valid portable project key rejected: %v", err)
		}
	}
	value.Member.ProjectKey = strings.Repeat("a", 64)
	if _, err := value.Validate(value.ControlURL, value.Member.ProjectKey, value.Member.DeploymentName, value.Instance); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized project key accepted: %v", err)
	}
}

func TestDeploymentIdentityFileAndInjectedJSONHaveTheSamePrivateContract(t *testing.T) {
	value := deploymentFixture(t)
	path := filepath.Join(t.TempDir(), "replica-1.json")
	if err := WriteDeployment(path, value); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("export did not create a private file", err)
	}
	loaded, err := ReadDeployment(path)
	if err != nil || loaded != value {
		t.Fatal("private deployment file did not round trip", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	injected, err := ParseDeployment(data)
	if err != nil || injected != value {
		t.Fatal("ECS JSON injection changed the identity", err)
	}
	if err := WriteDeployment(path, deploymentFixture(t)); !errors.Is(err, ErrExists) {
		t.Fatal("export overwrote a provisioned identity", err)
	}
	if err := os.Chmod(path, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDeployment(path); err != nil {
		t.Fatal("read-only secret mount rejected", err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDeployment(path); !errors.Is(err, ErrInvalid) {
		t.Fatal("public-readable identity accepted", err)
	}
	link := filepath.Join(filepath.Dir(path), "symlink.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadDeployment(link); !errors.Is(err, ErrInvalid) {
		t.Fatal("symlink accepted", err)
	}
	if err := WriteDeployment(link, value); !errors.Is(err, ErrExists) {
		t.Fatal("symlink replaced", err)
	}
	for _, rendered := range []string{fmt.Sprint(value), fmt.Sprintf("%#v", value), ErrInvalid.Error()} {
		if strings.Contains(rendered, value.PrivateKey) {
			t.Fatal("private key leaked in diagnostic formatting")
		}
	}
}

func TestDeploymentIdentityRejectsAmbiguousJSONAndDifferentDeploymentScope(t *testing.T) {
	value := deploymentFixture(t)
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
		strings.Replace(valid, `"deployment_id":`, `"group_id":`, 1),
		strings.Replace(valid, `"deployment_name":`, `"group_name":`, 1),
		strings.Replace(valid, `"dpl_`, `"pgrp_`, 1),
		strings.Replace(valid, value.PrivateKey, base64.RawURLEncoding.EncodeToString(make([]byte, ed25519.PrivateKeySize)), 1),
	} {
		if _, err := ParseDeployment([]byte(invalid)); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid or ambiguous deployment identity accepted", err)
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
