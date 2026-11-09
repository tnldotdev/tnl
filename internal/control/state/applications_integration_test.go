package state

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/security/publisherproof"
)

func applicationRequest(t *testing.T, d *Database, now time.Time) (RegisterApplicationRequest, ed25519.PrivateKey) {
	t.Helper()
	urlRequest := oidcRouteRequest(t, d, now)
	url := createTestPublicURL(t, d, urlRequest, now)
	service, err := d.CreateServiceAt(t.Context(), url.TeamID, urlRequest.ActingIdentityID, "app-db", "app-db", ServicePlacement{}, now, ServiceMetadata{Protocol: "postgres"})
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return RegisterApplicationRequest{TeamID: url.TeamID, ActingIdentityID: urlRequest.ActingIdentityID, Name: "application", Ownership: "member", IdempotencyKey: "register-app", PublicKey: public, Grants: []ApplicationGrantRequest{
		{Operation: ApplicationVisit, Scope: PublisherScope{TeamID: url.TeamID, Kind: "service", ServiceID: service.ID}},
		{Operation: ApplicationPublish, Scope: PublisherScope{TeamID: url.TeamID, Kind: "saved_public_url", PublicURLID: url.ID}},
		{Operation: ApplicationAllocate, Scope: PublisherScope{TeamID: url.TeamID, Kind: "namespace", DomainID: url.DomainID}},
		{Operation: ApplicationVisit, Scope: PublisherScope{TeamID: url.TeamID, Kind: "saved_public_url", PublicURLID: url.ID}},
		{Operation: ApplicationPublish, Scope: PublisherScope{TeamID: url.TeamID, Kind: "service", ServiceID: service.ID}},
	}}, private
}

func TestIntegrationApplicationRegistersOneKeyWithSeveralExplicitOperations(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "application_registration")
	r, private := applicationRequest(t, d, now)
	registered, err := d.RegisterApplication(t.Context(), r, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(registered.Grants) != len(r.Grants) {
		t.Fatal("registration lost explicit grants")
	}
	var identities, keys, grants int
	if err := d.pool.QueryRow(t.Context(), `SELECT (SELECT count(*) FROM control.publisher_identities WHERE id=$1),
	    (SELECT count(*) FROM control.publisher_identity_keys WHERE publisher_identity_id=$1),
	    (SELECT count(*) FROM control.publisher_grants WHERE publisher_identity_id=$1)`, registered.ID).Scan(&identities, &keys, &grants); err != nil || identities != 1 || keys != 1 || grants != 5 {
		t.Fatal("one registration created several identities or keys", identities, keys, grants, err)
	}
	for index, grant := range registered.Grants {
		if grant.Operation != r.Grants[index].Operation {
			t.Fatal("operation was inferred from a resource")
		}
		assertion, err := publisherproof.Sign(registered.ID, registered.KeyID, grant.ID, "https://control.example/token", private, now)
		if err != nil {
			t.Fatal(err)
		}
		access, err := d.ExchangePublisherAssertion(t.Context(), registered.ID, grant.ID, "https://control.example/token", assertion, "", now)
		if err != nil {
			t.Fatal("one key could not select each exact grant", err)
		}
		if _, err := d.ExchangePublisherAssertion(t.Context(), registered.ID, grant.ID, "https://control.example/token", assertion, "", now); !errors.Is(err, ErrPublisherIdentity) {
			t.Fatal("application proof replay was accepted", err)
		}
		if access.Operation != grant.Operation || access.ID != registered.ID || access.KeyID != registered.KeyID {
			t.Fatal("exchange changed the registration or operation")
		}
		_, authErr := d.AuthenticatePublisherAccess(t.Context(), access.Token, "", now)
		if grant.Operation == ApplicationVisit {
			if !errors.Is(authErr, ErrPublisherIdentity) {
				t.Fatal("visit access became publisher access", authErr)
			}
			if allowed, err := d.PublisherMayStartRun(t.Context(), access.PublisherIdentity, grant.Scope.PublicURLID); allowed || !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("visit grant authorized a publish run", err)
			}
			if grant.Scope.Kind == "service" {
				if _, err := d.PrepareServiceRun(t.Context(), grant.Scope.ServiceID, access.PublisherIdentity, "attempt", now, ServiceMetadata{Protocol: "postgres"}); !errors.Is(err, ErrServiceAccess) {
					t.Fatal("visit grant prepared a service publication", err)
				}
			}
		} else if authErr != nil {
			t.Fatal("explicit publication capability was denied", authErr)
		}
		if grant.Operation != ApplicationAllocate {
			if _, err := d.AllocatePublisherPublicURL(t.Context(), access.PublisherIdentity, "ivk_"+strings.Repeat("A", 22), "http://127.0.0.1:3000", nil, nil, now); !errors.Is(err, ErrPublisherIdentity) {
				t.Fatal("non-allocation grant allocated a public URL", err)
			}
		} else {
			allocated, err := d.AllocatePublisherPublicURL(t.Context(), access.PublisherIdentity, "ivk_"+strings.Repeat("A", 22), "http://127.0.0.1:3000", nil, nil, now)
			if err != nil || !strings.HasSuffix(allocated.CanonicalHostname, "."+grant.Scope.Namespace) {
				t.Fatal("explicit allocation grant failed", err)
			}
		}
	}
	retried, err := d.RegisterApplication(t.Context(), r, now.Add(time.Second))
	if err != nil || !reflect.DeepEqual(retried, registered) {
		t.Fatal("lost registration reply could not be recovered exactly", err)
	}
	changed := r
	changed.Name = "different"
	if _, err := d.RegisterApplication(t.Context(), changed, now); !errors.Is(err, ErrApplicationIdempotency) {
		t.Fatal("registration retry changed its captured request", err)
	}
}

func TestIntegrationApplicationRegistrationIsAtomicAndConcurrentRetriesConverge(t *testing.T) {
	d, now := newControlStateIntegrationDatabase(t, "application_registration_atomic")
	r, _ := applicationRequest(t, d, now)
	invalid := r
	invalid.Grants = append(append([]ApplicationGrantRequest{}, r.Grants...), r.Grants[0])
	if _, err := d.RegisterApplication(t.Context(), invalid, now); !errors.Is(err, ErrAuthorityConflict) {
		t.Fatal("duplicate operation/resource was not rejected", err)
	}
	var count int
	if err := d.pool.QueryRow(t.Context(), `SELECT count(*) FROM control.publisher_identities WHERE kind='application'`).Scan(&count); err != nil || count != 0 {
		t.Fatal("failed registration left an identity or partial grants", count, err)
	}
	var workers sync.WaitGroup
	results := make(chan ApplicationRegistration, 8)
	errorsFound := make(chan error, 8)
	for range 8 {
		workers.Go(func() {
			result, err := d.RegisterApplication(t.Context(), r, now)
			if err != nil {
				errorsFound <- err
				return
			}
			results <- result
		})
	}
	workers.Wait()
	close(results)
	close(errorsFound)
	for err := range errorsFound {
		t.Fatal(err)
	}
	var first *ApplicationRegistration
	for result := range results {
		if first == nil {
			first = &result
		} else if !reflect.DeepEqual(*first, result) {
			t.Fatal("concurrent registration retries created different identities")
		}
	}
	if first == nil {
		t.Fatal("no registration completed")
	}
}
