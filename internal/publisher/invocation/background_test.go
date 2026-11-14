package invocation

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type installedCandidateControl struct {
	publisheridentity.ServiceControl
	services map[string]controlv1.Service
}

func (*installedCandidateControl) ControlURL() string { return "https://control.example" }

func (c *installedCandidateControl) GetPublisherService(_ context.Context, id, access string) (controlv1.Service, error) {
	if access != id {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	value, ok := c.services[id]
	if !ok {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	return value, nil
}

type installedCandidateAuthority struct {
	publisheridentity.EnrollmentAuthority
	identities map[string]authorityv1.PublisherEnrollmentResult
	keys       map[string]ed25519.PublicKey
}

func (a *installedCandidateAuthority) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	identity, ok := a.identities[client]
	if !ok || grant != identity.GrantId || key != identity.KeyId || !private.Public().(ed25519.PublicKey).Equal(a.keys[client]) {
		return "", publisheridentity.ErrScope
	}
	return *identity.ServiceId, nil
}

func installedCandidateFixture(t *testing.T) (*clientstate.Store, *installedCandidateControl, *installedCandidateAuthority, InstallScope) {
	t.Helper()
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "client"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	profile, err := database.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	return profile, &installedCandidateControl{services: make(map[string]controlv1.Service)}, &installedCandidateAuthority{identities: make(map[string]authorityv1.PublisherEnrollmentResult), keys: make(map[string]ed25519.PublicKey)},
		InstallScope{ProjectKey: "project", SourceFingerprint: "fingerprint", WorktreeKey: "worktree", Service: "web", Protocol: "http", TeamID: "team", DomainID: "domain", Hostname: "web.example"}
}

func saveInstalledCandidate(t *testing.T, profile *clientstate.Store, control *installedCandidateControl, authority *installedCandidateAuthority, scope InstallScope) (controlv1.Service, ed25519.PrivateKey) {
	t.Helper()
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	service := controlv1.Service{Id: id(opaqueid.ServicePrefix), TeamId: scope.TeamID, DomainId: &scope.DomainID, Name: scope.Service, Protocol: controlv1.ServiceProtocol(scope.Protocol), Enabled: true, TrustRevision: 1,
		Source:   &controlv1.LocalServiceSource{ProjectKey: scope.ProjectKey, SourceFingerprint: scope.SourceFingerprint, WorktreeKey: scope.WorktreeKey, Service: scope.Service},
		Endpoint: &controlv1.ServiceEndpoint{Hostname: scope.Hostname, Port: 443, Public: true}}
	if scope.Protocol != "http" {
		service.Endpoint.Port, service.Endpoint.Public = 0, false
	}
	identity := authorityv1.PublisherEnrollmentResult{Kind: authorityv1.Service, ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), TeamId: scope.TeamID, ServiceId: &service.Id}
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.InstallPublisherIdentity(t.Context(), clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: data, SigningKey: private}, clientstate.PublisherSelection{Kind: "project", Key: "project-publisher:service:" + service.Id}); err != nil {
		t.Fatal(err)
	}
	control.services[service.Id], authority.identities[identity.ClientId], authority.keys[identity.ClientId] = service, identity, public
	return service, private
}

func TestConfiguredInstalledSelectionUsesSignedExactServiceAfterLogout(t *testing.T) {
	for _, protocol := range []string{"http", "postgres"} {
		t.Run(protocol, func(t *testing.T) {
			profile, control, authority, scope := installedCandidateFixture(t)
			scope.Protocol = protocol
			saved, original := saveInstalledCandidate(t, profile, control, authority, scope)
			unrelatedScope := scope
			unrelatedScope.WorktreeKey = "other-worktree"
			unrelated, _ := saveInstalledCandidate(t, profile, control, authority, unrelatedScope)
			native, identity, key, current, err := SelectConfiguredPublisherCandidates(t.Context(), control.ControlURL(), profile, []string{unrelated.Id, saved.Id, saved.Id}, scope, publisheridentity.NativeControl{Services: control}, authority)
			if err != nil || native == nil || current.Id != saved.Id || identity.ServiceId == nil || *identity.ServiceId != saved.Id || !bytes.Equal(key, original) {
				t.Fatal("selection changed its service or original signing key", err)
			}
			if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
				t.Fatal("installed selection acquired an operator session", err)
			}
			if _, _, _, _, err := SelectConfiguredPublisherCandidates(t.Context(), control.ControlURL(), profile, []string{unrelated.Id}, scope, publisheridentity.NativeControl{Services: control}, authority); err == nil {
				t.Fatal("another worktree's same-label service was selected")
			}
		})
	}
}

func TestConfiguredInstalledSelectionRejectsSourceDriftAndAmbiguity(t *testing.T) {
	for _, name := range []string{"source", "project", "worktree", "service", "protocol", "team", "domain", "hostname", "ephemeral", "revoked", "ambiguous"} {
		t.Run(name, func(t *testing.T) {
			profile, control, authority, scope := installedCandidateFixture(t)
			saved, _ := saveInstalledCandidate(t, profile, control, authority, scope)
			ids := []string{saved.Id}
			switch name {
			case "source":
				saved.Source.SourceFingerprint = "other"
			case "project":
				saved.Source.ProjectKey = "other"
			case "worktree":
				saved.Source.WorktreeKey = "other"
			case "service":
				saved.Source.Service = "other"
			case "protocol":
				saved.Protocol = controlv1.Tcp
			case "team":
				saved.TeamId = "other"
			case "domain":
				saved.DomainId = new("other")
			case "hostname":
				saved.Endpoint.Hostname = "other.example"
			case "ephemeral":
				saved.Ephemeral = true
			case "revoked":
				delete(control.services, saved.Id)
			case "ambiguous":
				other, _ := saveInstalledCandidate(t, profile, control, authority, scope)
				ids = append(ids, other.Id)
			}
			if name != "revoked" {
				control.services[saved.Id] = saved
			}
			if _, _, _, _, err := SelectConfiguredPublisherCandidates(t.Context(), control.ControlURL(), profile, ids, scope, publisheridentity.NativeControl{Services: control}, authority); err == nil {
				t.Fatal("drift or ambiguity selected a replacement grant")
			}
		})
	}
	if _, _, _, _, err := SelectConfiguredPublisherCandidates(t.Context(), "", nil, nil, InstallScope{}, publisheridentity.NativeControl{}, nil); !errors.Is(err, installedjobs.ErrScope) {
		t.Fatal("missing protected state was accepted", err)
	}
}
