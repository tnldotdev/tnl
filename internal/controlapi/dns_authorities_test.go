package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestDNSAuthorityServiceLifecycle(t *testing.T) {
	now := time.Date(2026, time.September, 5, 12, 0, 0, 0, time.UTC)
	store := &dnsAuthorityStoreStub{authority: controlstate.DNSAuthority{
		Reference: "dns_authority_0123456789abcdef0123456789abcdef",
		TeamID:    "team_1", DomainID: "domain_1", CanonicalDomain: "example.test", State: "pending",
		RequiredRecords: []controlstate.DNSRecord{{Name: "example.test", Type: "NS", Value: "ns-1.example.test"}},
		CreatedAt:       now, UpdatedAt: now,
	}}
	handler := NewHandler(Config{
		AuthorityEndpoint: "https://authority.example.test", HostedSecret: testHostedSecret,
		HTTPClient: http.DefaultClient, DNSAutomation: true,
	}, store, nil)

	create := httptest.NewRequest(http.MethodPost, "/v1/service/dns-authorities", bytes.NewBufferString(`{
		"team_id":"team_1","domain_id":"domain_1","canonical_domain":"example.test"
	}`))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Authorization", "Bearer "+testHostedSecret)
	create.Header.Set("Idempotency-Key", "create-domain-1")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, create)
	if response.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", response.Code, response.Body.String())
	}
	if store.created.TeamID != "team_1" || store.created.DomainID != "domain_1" ||
		store.created.CanonicalDomain != "example.test" || store.created.IdempotencyKey != "create-domain-1" ||
		store.created.RequestDigest == ([32]byte{}) {
		t.Fatalf("create request = %#v", store.created)
	}
	var created controlv1.DNSAuthority
	if err := json.Unmarshal(response.Body.Bytes(), &created); err != nil || created.Reference != store.authority.Reference ||
		len(created.RequiredRecords) != 1 {
		t.Fatalf("create response = %#v, %v", created, err)
	}

	get := httptest.NewRequest(http.MethodGet, "/v1/service/dns-authorities/"+store.authority.Reference, nil)
	get.Header.Set("Authorization", "Bearer "+testHostedSecret)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, get)
	if response.Code != http.StatusOK || store.gotReference != store.authority.Reference {
		t.Fatalf("get = status %d, reference %q", response.Code, store.gotReference)
	}

	release := httptest.NewRequest(http.MethodDelete, "/v1/service/dns-authorities/"+store.authority.Reference, nil)
	release.Header.Set("Authorization", "Bearer "+testHostedSecret)
	release.Header.Set("Idempotency-Key", "release-domain-1")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, release)
	if response.Code != http.StatusAccepted || store.releasedReference != store.authority.Reference ||
		store.releaseIdempotencyKey != "release-domain-1" {
		t.Fatalf("release = status %d, reference %q, key %q", response.Code, store.releasedReference, store.releaseIdempotencyKey)
	}
}

func TestDNSAuthorityServiceRejectsWrongSecret(t *testing.T) {
	store := &dnsAuthorityStoreStub{}
	handler := NewHandler(Config{
		AuthorityEndpoint: "https://authority.example.test", HostedSecret: testHostedSecret,
		HTTPClient: http.DefaultClient,
	}, store, nil)
	request := httptest.NewRequest(http.MethodGet, "/v1/service/dns-authorities/dns_authority_0123456789abcdef0123456789abcdef", nil)
	request.Header.Set("Authorization", "Bearer wrong-secret-012345678901234567890")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || store.gotReference != "" {
		t.Fatalf("unauthorized get = status %d, reference %q", response.Code, store.gotReference)
	}
}

type dnsAuthorityStoreStub struct {
	Store
	authority             controlstate.DNSAuthority
	created               controlstate.CreateDNSAuthorityRequest
	gotReference          string
	releasedReference     string
	releaseIdempotencyKey string
}

func (s *dnsAuthorityStoreStub) CreateDNSAuthority(
	_ context.Context,
	request controlstate.CreateDNSAuthorityRequest,
	_ time.Time,
) (controlstate.DNSAuthority, error) {
	s.created = request
	return s.authority, nil
}

func (s *dnsAuthorityStoreStub) GetDNSAuthority(_ context.Context, reference string) (controlstate.DNSAuthority, error) {
	s.gotReference = reference
	return s.authority, nil
}

func (s *dnsAuthorityStoreStub) ReleaseDNSAuthority(
	_ context.Context,
	reference, idempotencyKey string,
	_ time.Time,
) (controlstate.DNSAuthority, error) {
	s.releasedReference, s.releaseIdempotencyKey = reference, idempotencyKey
	return s.authority, nil
}
