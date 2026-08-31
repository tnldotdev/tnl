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

func TestBootstrapTokenRoundTripAndClassIsolation(t *testing.T) {
	token, err := NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := ParseBootstrapToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(token.String(), bootstrapPrefix) || !verifier.Matches(token) {
		t.Fatal("generated bootstrap token did not match")
	}

	other, err := NewBootstrapToken()
	if err != nil {
		t.Fatal(err)
	}
	if verifier.Matches(other) {
		t.Fatal("different bootstrap token matched")
	}
	if verifier.Matches(BootstrapToken(strings.Replace(token.String(), bootstrapPrefix, accessPrefix, 1))) {
		t.Fatal("access-class token matched bootstrap verifier")
	}
	if _, err := ParseBootstrapToken(BootstrapToken("tnl_route_invalid")); !errors.Is(err, ErrInvalidBootstrapToken) {
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

	workload, workloadVerifier, err := NewWorkloadToken()
	if err != nil {
		t.Fatal(err)
	}
	parsedWorkload, err := ParseWorkloadToken(workload)
	if err != nil || !workloadVerifier.Matches(workload) || !parsedWorkload.Matches(workload) {
		t.Fatalf("workload round trip failed: %v", err)
	}
	if _, err := ParseWorkloadToken(WorkloadToken(worker)); !errors.Is(err, ErrInvalidWorkloadToken) {
		t.Fatalf("worker as workload error = %v", err)
	}
}

func TestTokenExchangeFixturesUseCanonicalCredentials(t *testing.T) {
	var request struct {
		BootstrapToken BootstrapToken `json:"bootstrap_token"`
	}
	readJSONFixture(t, "../../api/fixtures/core/v1/token-exchange-request.json", &request)
	if _, err := ParseBootstrapToken(request.BootstrapToken); err != nil {
		t.Fatalf("bootstrap fixture: %v", err)
	}

	var response struct {
		AccessToken  AccessToken  `json:"access_token"`
		CredentialID CredentialID `json:"credential_id"`
	}
	readJSONFixture(t, "../../api/fixtures/core/v1/token-exchange-response.json", &response)
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
