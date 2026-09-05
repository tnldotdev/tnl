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

func TestRefreshTokenRoundTripAndClassIsolation(t *testing.T) {
	token, lookupID, hash, err := NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	parsedID, parsedHash, err := ParseRefreshToken(token)
	if err != nil || parsedID != lookupID || parsedHash != hash || !strings.HasPrefix(token.String(), refreshPrefix) {
		t.Fatalf("refresh round trip = %q, %x, %v", parsedID, parsedHash, err)
	}
	access, _, _, err := NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseRefreshToken(RefreshToken(access)); !errors.Is(err, ErrInvalidRefreshToken) {
		t.Fatalf("access as refresh error = %v", err)
	}
}

func TestInvitationTokenRoundTrip(t *testing.T) {
	token, hash, err := NewInvitationToken()
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseInvitationToken(token)
	if err != nil || !SecretHashMatches(hash[:], parsed) {
		t.Fatalf("parsed invitation token = %x, %v", parsed, err)
	}
	if _, err := ParseInvitationToken(InvitationToken("not-an-invitation")); !errors.Is(err, ErrInvalidInvitationToken) {
		t.Fatalf("invalid invitation token error = %v", err)
	}
	derived, derivedHash, err := DeriveInvitationToken(make([]byte, 32), "team_1/invitation_1")
	if err != nil {
		t.Fatal(err)
	}
	repeated, repeatedHash, err := DeriveInvitationToken(make([]byte, 32), "team_1/invitation_1")
	if err != nil || repeated != derived || repeatedHash != derivedHash {
		t.Fatalf("repeated derived invitation token = %q, %x, %v", repeated, repeatedHash, err)
	}
	other, _, err := DeriveInvitationToken(make([]byte, 32), "team_1/invitation_2")
	if err != nil || other == derived {
		t.Fatalf("other derived invitation token = %q, %v", other, err)
	}
}

func TestDataPlaneTokenClasses(t *testing.T) {
	session, sessionID, sessionHash, err := NewSessionToken()
	if err != nil {
		t.Fatal(err)
	}
	if gotID, gotHash, err := ParseSessionToken(session); err != nil || gotID != sessionID || gotHash != sessionHash {
		t.Fatalf("session round trip = %q, %x, %v", gotID, gotHash, err)
	}
	connection, connectionHash, err := NewPublisherConnectionCredential()
	if err != nil {
		t.Fatal(err)
	}
	if gotHash, err := ParsePublisherConnectionCredential(connection); err != nil || gotHash != connectionHash {
		t.Fatalf("publisher connection round trip = %x, %v", gotHash, err)
	}
	if _, err := ParsePublisherConnectionCredential(PublisherConnectionCredential(session)); !errors.Is(err, ErrInvalidPublisherConnectionCredential) {
		t.Fatalf("session as publisher connection error = %v", err)
	}
	derivedConnection, derivedHash, err := DerivePublisherConnectionCredential(session, "connection_1/1")
	if err != nil {
		t.Fatal(err)
	}
	repeatedConnection, repeatedHash, err := DerivePublisherConnectionCredential(session, "connection_1/1")
	if err != nil || repeatedConnection != derivedConnection || repeatedHash != derivedHash {
		t.Fatalf("repeated derived publisher connection = %q, %x, %v", repeatedConnection, repeatedHash, err)
	}
	otherConnection, _, err := DerivePublisherConnectionCredential(session, "connection_2/1")
	if err != nil || otherConnection == derivedConnection {
		t.Fatalf("other derived publisher connection = %q, %v", otherConnection, err)
	}
	if parsedHash, err := ParsePublisherConnectionCredential(derivedConnection); err != nil || parsedHash != derivedHash {
		t.Fatalf("derived publisher connection parse = %x, %v", parsedHash, err)
	}

	service, err := NewServiceToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseServiceToken(service); err != nil {
		t.Fatalf("service round trip failed: %v", err)
	}
	if err := ParseServiceToken(ServiceToken(session)); !errors.Is(err, ErrInvalidServiceToken) {
		t.Fatalf("session as service error = %v", err)
	}
}

func TestTokenExchangeFixturesUseCanonicalCredentials(t *testing.T) {
	var request struct {
		LoginToken LoginToken `json:"login_token"`
	}
	readJSONFixture(t, "../../api/fixtures/authority/v1/token-exchange-request.json", &request)
	if _, err := ParseLoginToken(request.LoginToken); err != nil {
		t.Fatalf("login fixture: %v", err)
	}

	var response struct {
		AccessToken  AccessToken  `json:"access_token"`
		RefreshToken RefreshToken `json:"refresh_token"`
	}
	readJSONFixture(t, "../../api/fixtures/authority/v1/token-exchange-response.json", &response)
	if _, _, err := ParseAccessToken(response.AccessToken); err != nil {
		t.Fatalf("access fixture: %v", err)
	}
	if _, _, err := ParseRefreshToken(response.RefreshToken); err != nil {
		t.Fatalf("refresh fixture: %v", err)
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
