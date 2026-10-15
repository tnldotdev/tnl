package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
)

func TestPublisherCurrentShowsFileScopeWithoutItsSigningKey(t *testing.T) {
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	keyID, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	domain, _ := opaqueid.New(opaqueid.DomainPrefix)
	namespace := "member.example.test"
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: keyID, GrantId: grant, TeamId: "team", Kind: "namespace", DomainId: &domain, Namespace: &namespace}
	file, err := credentialfile.New("https://control.example.test", identity, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := credentialfile.Write(path, file); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TNL_PUBLISHER_FILE", path)
	var output bytes.Buffer
	if err := runPublisherCurrent(t.Context(), publisherCurrentCommand{Output: statusOutputJSON}, &output); err != nil {
		t.Fatal(err)
	}
	var result publisherCurrentResult
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Source != "publisher file" || result.Scope != namespace || result.PublisherID != id || result.GrantID != grant || result.Checked || strings.Contains(output.String(), file.PrivateKey) || strings.Contains(output.String(), "private_key") {
		t.Fatalf("unsafe publisher selection: %s", output.String())
	}
	t.Setenv("TNL_PUBLISHER_FILE", "")
	if err := runPublisherCurrent(t.Context(), publisherCurrentCommand{}, &output); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatalf("empty publisher file selected a fallback identity: %v", err)
	}
}
