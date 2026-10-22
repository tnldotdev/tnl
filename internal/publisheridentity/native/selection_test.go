package native

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type scopedAuthority struct {
	identity authorityv1.PublisherEnrollmentResult
	calls    int
	accesses int
}

func (a *scopedAuthority) RedeemPublisherEnrollment(context.Context, string, ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	a.calls++
	return a.identity, nil
}
func (a *scopedAuthority) ExchangePublisherAssertion(context.Context, string, string, string, ed25519.PrivateKey) (string, error) {
	a.accesses++
	return "scoped-access", nil
}

func TestResolveAdHocRequiresExplicitSetupAndFailsClosedOnInvalidFile(t *testing.T) {
	t.Setenv("TNL_PUBLISHER_FILE", "")
	if err := os.Unsetenv("TNL_PUBLISHER_FILE"); err != nil {
		t.Fatal(err)
	}
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const server = "https://control.example"
	state, err := d.Server(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	url, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	keyID, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a := &scopedAuthority{identity: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: keyID, GrantId: grant, TeamId: "team", Kind: "saved_url", PublicUrlId: &url}}
	control := &unusedControl{}
	if _, err := ResolveAdHoc(t.Context(), state, control, a, server, "team", "domain", "member.example", "", "", "", nil); !errors.Is(err, ErrSetupRequired) {
		t.Fatalf("setup was not required: %v", err)
	}
	f, err := credentialfile.New(server, a.identity, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := credentialfile.Write(path, f); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAdHoc(t.Context(), state, control, a, server, "team", "domain", "member.example", path, "", "", nil); !errors.Is(err, ErrScope) {
		t.Fatalf("saved URL used for ad-hoc: %v", err)
	}
	if _, err := ResolveAdHoc(t.Context(), state, control, a, server, "team", "domain", "member.example", path+".missing", "", "", nil); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatalf("invalid file fell back to local state: %v", err)
	}
	t.Setenv("TNL_PUBLISHER_FILE", path+".missing")
	if _, err := ResolveAdHoc(t.Context(), state, control, a, server, "team", "domain", "member.example", "", "", "", nil); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatalf("invalid environment file fell back to local state: %v", err)
	}
}

func TestExplicitSetupReusesNamespaceKeyWithoutNewEnrollment(t *testing.T) {
	d, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	state, err := d.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	key, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	domain, _ := opaqueid.New(opaqueid.DomainPrefix)
	enrollment, _ := opaqueid.New(opaqueid.PublisherEnrollmentPrefix)
	const team, namespace = "team", "member.example"
	c := &ownerEnrollmentControl{enrollment: controlv1.PublisherEnrollment{Id: enrollment, EnrollmentKey: enrollment + ".secret", ExpiresAt: time.Now().Add(time.Minute), TeamId: team, DomainId: &domain, Namespace: ptr(namespace), Kind: "namespace"}}
	a := &scopedAuthority{identity: authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: team, DomainId: &domain, Namespace: ptr(namespace), Kind: "namespace"}}
	for range 2 {
		if _, _, err := EnsureNamespace(t.Context(), state, c, a, team, domain, namespace); err != nil {
			t.Fatal(err)
		}
	}
	if c.calls != 1 || a.calls != 1 {
		t.Fatalf("setup re-enrolled: created=%d redeemed=%d", c.calls, a.calls)
	}
	if _, err := LoadLocalNamespace(t.Context(), state, c, a, team, domain, namespace); err != nil {
		t.Fatal(err)
	}
	if selected, err := LoadDefaultNamespace(t.Context(), state, c, a); err != nil || selected.PublisherID() != id {
		t.Fatalf("explicit setup did not select a usable default namespace: %v", err)
	}
	if _, err := LoadLocalNamespace(t.Context(), state, c, a, team, domain, "other.example"); !errors.Is(err, ErrScope) {
		t.Fatalf("scope widened: %v", err)
	}
	t.Setenv("TNL_PUBLISHER_FILE", "")
	if err := os.Unsetenv("TNL_PUBLISHER_FILE"); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAdHoc(t.Context(), state, c, a, "https://control.example", team, domain, namespace, "", "", "", nil); err != nil {
		t.Fatalf("local namespace default: %v", err)
	}
	if _, err := ResolveAdHoc(t.Context(), state, c, a, "https://control.example", "", "", "", "", "", "", nil); err != nil {
		t.Fatalf("local setup required a control session during publication: %v", err)
	}
	saved, found, err := state.PublisherIdentity(t.Context(), id)
	if err != nil || !found {
		t.Fatalf("read installed publisher: %v", err)
	}
	file, err := credentialfile.New("https://control.example", a.identity, saved.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := credentialfile.Write(path, file); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveAdHoc(t.Context(), state, c, a, "https://control.example", "other-team", "other-domain", "other.example", path, "", "", nil); err != nil {
		t.Fatalf("explicit file did not override local selection: %v", err)
	}
	if _, err := ResolveAdHoc(t.Context(), state, c, a, "https://control.example", team, domain, namespace, path+".missing", "", "", nil); !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatalf("invalid explicit file fell back to local setup: %v", err)
	}
	t.Setenv("TNL_PUBLISHER_FILE", path+".missing")
	if _, err := ResolveAdHoc(t.Context(), state, c, a, "https://control.example", team, domain, namespace, "", "", id, nil); errors.Is(err, ErrSelection) || errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatalf("explicit publisher ID was overridden by environment file: %v", err)
	}
}

func TestPortableNamespaceFileAuthorizesWithoutLocalSetup(t *testing.T) {
	t.Setenv("TNL_PUBLISHER_FILE", "")
	if err := os.Unsetenv("TNL_PUBLISHER_FILE"); err != nil {
		t.Fatal(err)
	}
	const server = "https://control.example"
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := opaqueid.New(opaqueid.PublisherIdentityPrefix)
	key, _ := opaqueid.New(opaqueid.PublisherIdentityKeyPrefix)
	grant, _ := opaqueid.New(opaqueid.PublisherGrantPrefix)
	domain, _ := opaqueid.New(opaqueid.DomainPrefix)
	namespace := "member.example"
	a := &scopedAuthority{}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: id, KeyId: key, GrantId: grant, TeamId: "team", Kind: "namespace", DomainId: &domain, Namespace: &namespace}
	f, err := credentialfile.New(server, identity, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := credentialfile.Write(path, f); err != nil {
		t.Fatal(err)
	}
	n, err := ResolveAdHoc(t.Context(), nil, &unusedControl{}, a, server, "", "", "", path, "", "", nil)
	if err != nil || n.PublisherID() != id || a.accesses != 1 {
		t.Fatalf("portable namespace file: %v", err)
	}
	if _, err := ResolveAdHoc(t.Context(), nil, &unusedControl{}, a, "https://other.example", "", "", "", path, "", "", nil); !errors.Is(err, ErrScope) {
		t.Fatalf("file used with wrong control: %v", err)
	}
}

func ptr(v string) *string { return &v }
