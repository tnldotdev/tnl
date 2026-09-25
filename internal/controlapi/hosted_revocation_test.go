package controlapi

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

const (
	testHostedSecret         = "hosted-secret-current-012345678901"
	testHostedSecretPrevious = "hosted-secret-previous-0123456789"
)

func TestRevokeHostedPolicyAuthenticatesAndAppliesRevision(t *testing.T) {
	store := &hostedRevocationStoreStub{}
	handler := testHandler(t, Config{
		AuthorityEndpoint: "https://authority.example.test", HostedSecret: testHostedSecret,
		HostedSecretPrevious: testHostedSecretPrevious, HTTPClient: http.DefaultClient,
	}, store, nil, nil)
	for _, secret := range []string{testHostedSecret, testHostedSecretPrevious} {
		request := httptest.NewRequest(http.MethodPost, "/v1/service/revoke", bytes.NewBufferString(`{
			"team_id":"team_1",
			"policy_revision":7,
			"all_sessions":false,
			"membership_ids":["membership_1"],
			"domain_ids":["domain_1"]
		}`))
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer "+secret)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("status = %d, want %d: %s", response.Code, http.StatusNoContent, response.Body.String())
		}
	}
	if store.calls != 2 || store.issuer != "https://authority.example.test" || store.teamID != "team_1" ||
		store.policyRevision != 7 || store.allSessions || len(store.membershipIDs) != 1 ||
		store.membershipIDs[0] != "membership_1" || len(store.domainIDs) != 1 || store.domainIDs[0] != "domain_1" {
		t.Fatalf("hosted revocation = %#v", store)
	}
}

func TestRevokeHostedPolicyRejectsWrongSecret(t *testing.T) {
	store := &hostedRevocationStoreStub{}
	handler := testHandler(t, Config{
		AuthorityEndpoint: "https://authority.example.test", HostedSecret: testHostedSecret,
		HTTPClient: http.DefaultClient,
	}, store, nil, nil)
	request := httptest.NewRequest(http.MethodPost, "/v1/service/revoke", bytes.NewBufferString(`{
		"team_id":"team_1","policy_revision":7,"all_sessions":true,"membership_ids":[],"domain_ids":[]
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer wrong-hosted-secret-0123456789012")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || store.calls != 0 {
		t.Fatalf("unauthorized revocation = status %d, calls %d", response.Code, store.calls)
	}
}

type hostedRevocationStoreStub struct {
	Store
	calls          int
	issuer         string
	teamID         string
	policyRevision uint64
	allSessions    bool
	membershipIDs  []string
	domainIDs      []string
}

func (s *hostedRevocationStoreStub) ApplyHostedPolicyRevocation(
	_ context.Context,
	issuer, teamID string,
	policyRevision uint64,
	allSessions bool,
	membershipIDs []string,
	domainIDs []string,
	_ time.Time,
) (bool, int, error) {
	s.calls++
	s.issuer, s.teamID, s.policyRevision, s.allSessions = issuer, teamID, policyRevision, allSessions
	s.membershipIDs = append([]string(nil), membershipIDs...)
	s.domainIDs = append([]string(nil), domainIDs...)
	return true, 1, nil
}
