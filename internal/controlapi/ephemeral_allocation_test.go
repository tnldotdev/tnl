package controlapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
)

func TestEphemeralAllocationBindsCredentialAndCurrentSourceIP(t *testing.T) {
	token, _, hash, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	store := &publicURLCreationStore{result: controlstate.PublicURL{
		ID: "url_ephemeral", CanonicalHostname: "eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.member.example.test",
		TeamID: "team_1", DomainID: "domain_1", PublicURLScope: controlstate.PublicURLScopeMember,
		Target: "http://127.0.0.1:3000", Ephemeral: true, Purpose: controlstate.PublicURLPurposeApp,
	}}
	credentialsStore := &scopedCredentialStoreStub{credential: controlstate.PublicURLPublishCredential{
		ID: "upc_credential", Kind: controlstate.PublishCredentialEphemeral,
		TeamID: "team_1", DomainID: "domain_1", Namespace: "member.example.test", IdentityID: "identity_1", PolicyRevision: 1,
	}}
	h := &handler{store: store, publishCredentials: credentialsStore, config: Config{DNSAutomation: true}}
	request := httptest.NewRequest(http.MethodPost, "/v1/publish-credentials/allocate", strings.NewReader(`{"invocation_id":"`+invocation+`","target":"http://127.0.0.1:3000","allow_ip":["198.51.100.9"],"limits":{"requests":2}}`))
	request.RemoteAddr = "192.0.2.9:5353"
	request.Header.Set("Authorization", "Bearer "+token.String())
	response := httptest.NewRecorder()
	h.AllocateEphemeralPublicURL(response, request)
	if response.Code != http.StatusCreated || len(store.requests) != 1 {
		t.Fatalf("allocation = %d %s; requests %#v", response.Code, response.Body.String(), store.requests)
	}
	selected := store.requests[0]
	if selected.CanonicalHostname != "" || selected.EphemeralCredentialID != credentialsStore.credential.ID ||
		selected.EphemeralTokenDigest != hash || !selected.Ephemeral || selected.DNSState != controlstate.PublicURLDNSPending ||
		selected.IdempotencyKey != credentialsStore.credential.ID+":"+invocation ||
		!strings.Contains(strings.Join(selected.AllowedIPPrefixes, ","), "192.0.2.9/32") ||
		!strings.Contains(strings.Join(selected.AllowedIPPrefixes, ","), "198.51.100.9/32") {
		t.Fatalf("control did not own the name or policy: %#v", selected)
	}
}

func TestEphemeralAllocationRejectsNonLoopbackTarget(t *testing.T) {
	store := &publicURLCreationStore{}
	h := &handler{store: store, publishCredentials: &scopedCredentialStoreStub{}, config: Config{DNSAutomation: true}}
	invocation, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/publish-credentials/allocate", strings.NewReader(`{"invocation_id":"`+invocation+`","target":"http://example.test:3000"}`))
	response := httptest.NewRecorder()
	h.AllocateEphemeralPublicURL(response, request)
	if response.Code != http.StatusBadRequest || len(store.requests) != 0 {
		t.Fatalf("nonloopback allocation = %d, requests = %#v", response.Code, store.requests)
	}
}
