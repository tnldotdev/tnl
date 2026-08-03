package credentials

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

func TestAccessTokenRoundTrip(t *testing.T) {
	token, lookupID, hash, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token.String(), accessPrefix) {
		t.Fatalf("token = %q, want access prefix", token)
	}

	parsedID, parsedHash, err := ParseAccessToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if parsedID != lookupID {
		t.Fatalf("lookup ID = %q, want %q", parsedID, lookupID)
	}
	if parsedHash != hash {
		t.Fatal("parsed hash differs from generated hash")
	}
	if !SecretHashMatches(hash[:], parsedHash) {
		t.Fatal("matching hash rejected")
	}

	otherHash := hash
	otherHash[0] ^= 1
	if SecretHashMatches(hash[:], otherHash) {
		t.Fatal("different hash accepted")
	}
}

func TestParseAccessTokenRejectsMalformedAndWrongClass(t *testing.T) {
	token, _, _, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}

	for _, candidate := range []AccessToken{
		"",
		AccessToken(strings.Replace(token.String(), accessPrefix, "tnl_route_", 1)),
		accessPrefix,
		accessPrefix + "AA.AA",
		token + ".extra",
		token + "=",
	} {
		if _, _, err := ParseAccessToken(candidate); !errors.Is(err, ErrInvalidAccessToken) {
			t.Errorf("ParseAccessToken(%q) error = %v", candidate, err)
		}
	}
}

func TestLoginTokenRoundTripAndClassIsolation(t *testing.T) {
	token, err := NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := ParseLoginToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token.String(), loginPrefix) || !verifier.Matches(token) {
		t.Fatal("generated login token did not match")
	}

	other, err := NewLoginToken()
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Matches(other) {
		t.Fatal("different login token matched")
	}
	if verifier.Matches(LoginToken(strings.Replace(token.String(), loginPrefix, accessPrefix, 1))) {
		t.Fatal("access-class token matched login verifier")
	}
	if _, err := ParseLoginToken(LoginToken("tnl_route_invalid")); !errors.Is(err, ErrInvalidLoginToken) {
		t.Fatalf("wrong-class error = %v", err)
	}
}

func TestDataPlaneTokenClasses(t *testing.T) {
	route, routeID, routeHash, err := NewRouteToken()
	if err != nil {
		t.Fatal(err)
	}
	if gotID, gotHash, err := ParseRouteToken(route); err != nil || gotID != routeID || gotHash != routeHash {
		t.Fatalf("route round trip = %q, %x, %v", gotID, gotHash, err)
	}

	lease, leaseID, leaseHash, err := NewLeaseToken()
	if err != nil {
		t.Fatal(err)
	}
	if gotID, gotHash, err := ParseLeaseToken(lease); err != nil || gotID != leaseID || gotHash != leaseHash {
		t.Fatalf("lease round trip = %q, %x, %v", gotID, gotHash, err)
	}
	if _, _, err := ParseRouteToken(RouteToken(lease)); !errors.Is(err, ErrInvalidRouteToken) {
		t.Fatalf("lease as route error = %v", err)
	}
	if _, _, err := ParseLeaseToken(LeaseToken(route)); !errors.Is(err, ErrInvalidLeaseToken) {
		t.Fatalf("route as lease error = %v", err)
	}

	worker, verifier, err := NewWorkerToken()
	if err != nil {
		t.Fatal(err)
	}
	if !verifier.Matches(worker) || verifier.Matches(WorkerToken(route)) {
		t.Fatal("worker verifier did not enforce its credential class")
	}

	service, serviceVerifier, err := NewServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	parsedService, err := ParseServiceToken(service)
	if err != nil || !serviceVerifier.Matches(service) || !parsedService.Matches(service) {
		t.Fatalf("service round trip failed: %v", err)
	}
	if _, err := ParseServiceToken(ServiceToken(worker)); !errors.Is(err, ErrInvalidServiceToken) {
		t.Fatalf("worker as service error = %v", err)
	}
}

func TestTokenExchangeFixturesUseCanonicalCredentials(t *testing.T) {
	var request struct {
		LoginToken LoginToken `json:"login_token"`
	}
	readJSONFixture(t, "../../api/fixtures/server/v1/token-exchange-request.json", &request)
	if _, err := ParseLoginToken(request.LoginToken); err != nil {
		t.Fatalf("login fixture: %v", err)
	}

	var response struct {
		AccessToken  AccessToken  `json:"access_token"`
		CredentialID CredentialID `json:"credential_id"`
	}
	readJSONFixture(t, "../../api/fixtures/server/v1/token-exchange-response.json", &response)
	credentialID, _, err := ParseAccessToken(response.AccessToken)
	if err != nil {
		t.Fatalf("access fixture: %v", err)
	}
	if credentialID != response.CredentialID {
		t.Fatalf("credential ID = %q, want %q", credentialID, response.CredentialID)
	}
}

func readJSONFixture(t *testing.T, path string, value any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, value); err != nil {
		t.Fatal(err)
	}
}
