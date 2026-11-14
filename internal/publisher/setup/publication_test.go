package setup

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"testing"

	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type publicationControl struct {
	publisheridentity.ServiceOwnerControl
	t                *testing.T
	service          controlv1.Service
	enrollment       controlv1.PublisherEnrollment
	identity         authorityv1.PublisherEnrollmentResult
	public           ed25519.PublicKey
	creates, redeems int
	loseReply        bool
}

func (*publicationControl) ControlURL() string { return "https://control.example" }

func (c *publicationControl) CreatePublisherEnrollment(_ context.Context, request controlv1.CreatePublisherEnrollmentRequest) (controlv1.PublisherEnrollment, error) {
	if request.ServiceId == nil || *request.ServiceId != c.service.Id || request.PublicUrlId != nil || request.DomainId != nil || request.TeamId != c.service.TeamId {
		c.t.Error("setup broadened the exact service grant")
		return controlv1.PublisherEnrollment{}, publisheridentity.ErrScope
	}
	c.creates++
	return c.enrollment, nil
}

func (c *publicationControl) RedeemPublisherEnrollment(_ context.Context, secret string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	c.redeems++
	if secret != c.enrollment.EnrollmentKey || c.public != nil && !bytes.Equal(c.public, public) {
		c.t.Error("setup retry changed its secret or original signing key")
		return authorityv1.PublisherEnrollmentResult{}, publisheridentity.ErrScope
	}
	c.public = bytes.Clone(public)
	if c.loseReply {
		c.loseReply = false
		return authorityv1.PublisherEnrollmentResult{}, errLostReply
	}
	return c.identity, nil
}

func (c *publicationControl) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != c.identity.ClientId || grant != c.identity.GrantId || key != c.identity.KeyId || !bytes.Equal(private.Public().(ed25519.PublicKey), c.public) {
		c.t.Error("setup signed with another grant or key")
		return "", publisheridentity.ErrScope
	}
	return "service-access", nil
}

func (c *publicationControl) GetPublisherService(_ context.Context, id, access string) (controlv1.Service, error) {
	if id != c.service.Id || access != "service-access" {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	return c.service, nil
}

func publicationFixture(t *testing.T, protocol controlv1.ServiceProtocol) (*clientstate.Store, *publicationControl) {
	t.Helper()
	id := func(prefix string) string {
		value, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	service := controlv1.Service{Id: id(opaqueid.ServicePrefix), TeamId: "team", Name: "app", Enabled: true, Protocol: protocol, TrustRevision: 3}
	enrollmentID := id(opaqueid.PublisherEnrollmentPrefix)
	c := &publicationControl{t: t, service: service,
		enrollment: controlv1.PublisherEnrollment{Id: enrollmentID, Kind: "service", TeamId: service.TeamId, ServiceId: &service.Id, EnrollmentKey: enrollmentID + ".secret"},
		identity:   authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), Kind: authorityv1.Service, TeamId: service.TeamId, ServiceId: &service.Id}}
	database, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "setup"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	store, err := database.Server(t.Context(), c.ControlURL())
	if err != nil {
		t.Fatal(err)
	}
	return store, c
}

func TestPublicationSetupRetainsExactServiceGrantAndOriginalKey(t *testing.T) {
	for _, protocol := range []controlv1.ServiceProtocol{controlv1.ServiceProtocolHTTP, controlv1.Postgres} {
		t.Run(string(protocol), func(t *testing.T) {
			store, control := publicationFixture(t, protocol)
			control.loseReply = true
			clients := publisheridentity.NativeControl{Services: control}
			if _, err := EnsurePublication(t.Context(), store, control, clients, control, control.ControlURL(), control.service); !errors.Is(err, errLostReply) {
				t.Fatal("lost redemption reply was accepted", err)
			}
			var original ed25519.PrivateKey
			for range 2 {
				file, err := EnsurePublication(t.Context(), store, control, clients, control, control.ControlURL(), control.service)
				if err != nil {
					t.Fatal(err)
				}
				identity, private, err := file.Validate()
				if err != nil || identity.Kind != authorityv1.Service || identity.ServiceId == nil || *identity.ServiceId != control.service.Id || identity.PublicUrlId != nil {
					t.Fatal("setup did not return the exact service grant", err)
				}
				if original != nil && !bytes.Equal(original, private) {
					t.Fatal("installation retry replaced the signing key")
				}
				original = bytes.Clone(private)
			}
			if control.creates != 1 || control.redeems != 2 {
				t.Fatal("retry recreated enrollment", control.creates, control.redeems)
			}
			if _, found, err := store.ControlSession(t.Context()); err != nil || found {
				t.Fatal("private setup copied an operator session", err)
			}
		})
	}
}

func TestPublicationSetupRejectsCurrentServiceDriftWithoutReenrollment(t *testing.T) {
	store, control := publicationFixture(t, controlv1.ServiceProtocolHTTP)
	clients := publisheridentity.NativeControl{Services: control}
	selected := control.service
	if _, err := EnsurePublication(t.Context(), store, control, clients, control, control.ControlURL(), selected); err != nil {
		t.Fatal(err)
	}
	control.service.TrustRevision++
	if _, err := EnsurePublication(t.Context(), store, control, clients, control, control.ControlURL(), selected); !errors.Is(err, publisheridentity.ErrScope) {
		t.Fatal("stale approval became an installed credential", err)
	}
	if control.creates != 1 || control.redeems != 1 {
		t.Fatal("service drift silently replaced the original grant")
	}
}
