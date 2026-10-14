package controlapi

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/authorityapi"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationPublisherIdentityAPIFromEnrollmentToRevokedRun(t *testing.T) {
	f := newFeedbackPolicyAPIFixture(t, Config{})
	authority, err := authorityapi.NewHandler(authorityapi.Config{ControlURL: "https://control.example"}, f.database)
	if err != nil {
		t.Fatal(err)
	}
	issue := f.call(http.MethodPost, "/v1/publisher/enrollments",
		fmt.Sprintf(`{"team_id":%q,"public_url_id":%q,"name":"device-ssh","kind":"installed"}`, f.publicURL.TeamID, f.publicURL.ID),
		f.owner.AccessToken.String(), "", http.StatusCreated)
	var enrollment controlv1.IssuedPublisherEnrollment
	if err := json.Unmarshal(issue.Body.Bytes(), &enrollment); err != nil || enrollment.EnrollmentKey == "" {
		t.Fatalf("enrollment response = %s, %v", issue.Body.String(), err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	callAuthority := func(path, body, contentType string, status int) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		response := httptest.NewRecorder()
		authority.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("authority POST %s = %d %s, want %d", path, response.Code, response.Body.String(), status)
		}
		return response
	}
	redeemed := callAuthority("/v1/publisher/enrollments/redeem",
		fmt.Sprintf(`{"enrollment_key":%q,"public_key":%q}`, enrollment.EnrollmentKey, base64.RawURLEncoding.EncodeToString(public)),
		"application/json", http.StatusOK)
	var identity authorityv1.PublisherEnrollmentResult
	if err := json.Unmarshal(redeemed.Body.Bytes(), &identity); err != nil || identity.PublicUrlId == nil || *identity.PublicUrlId != f.publicURL.ID {
		t.Fatalf("publisher identity = %s, %v", redeemed.Body.String(), err)
	}
	const audience = "https://control.example/v1/publisher/token"
	assertion, err := publisheridentity.Sign(identity.ClientId, identity.KeyId, audience, private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {publisheridentity.GrantType}, "client_id": {identity.ClientId},
		"client_assertion_type": {publisheridentity.AssertionType}, "client_assertion": {assertion}, "scope": {identity.GrantId}}
	exchanged := callAuthority("/v1/publisher/token", form.Encode(), "application/x-www-form-urlencoded", http.StatusOK)
	var token authorityv1.PublisherTokenResponse
	if err := json.Unmarshal(exchanged.Body.Bytes(), &token); err != nil || token.Scope != identity.GrantId || token.AccessToken == "" {
		t.Fatalf("publisher token = %s, %v", exchanged.Body.String(), err)
	}
	bound := f.call(http.MethodGet, "/v1/publisher/public-url", "", token.AccessToken, "", http.StatusOK)
	var selected controlv1.PublicURL
	if err := json.Unmarshal(bound.Body.Bytes(), &selected); err != nil || selected.Id != f.publicURL.ID {
		t.Fatalf("publisher public URL = %s, %v", bound.Body.String(), err)
	}
	f.call(http.MethodPatch, "/v1/public-urls/"+selected.Id, `{"target":"http://127.0.0.1:1","allowed_ip_prefixes":[]}`, token.AccessToken, "", http.StatusUnauthorized)
	f.call(http.MethodPut, "/v1/public-urls/"+selected.Id+"/ip-policy", `{"allowed_ip_prefixes":["192.0.2.7"]}`, token.AccessToken, "", http.StatusUnauthorized)
	f.call(http.MethodPost, "/v1/public-urls/"+selected.Id+"/ip-entries", `{"prefix":"192.0.2.7","expires_in_seconds":3600}`, token.AccessToken, "", http.StatusUnauthorized)
	f.call(http.MethodPost, "/v1/publish-runs/"+f.run.PublishRunID+"/heartbeat",
		fmt.Sprintf(`{"publish_run_number":%d}`, f.run.PublishRunNumber), f.run.PublishRunToken.String(), "", http.StatusUnauthorized)
	const idempotency = "ik_publisher_run"
	proof, err := publisheridentity.SignRun(private, selected.Id, idempotency)
	if err != nil {
		t.Fatal(err)
	}
	started := f.call(http.MethodPost, "/v1/public-urls/"+selected.Id+"/publish-runs",
		fmt.Sprintf(`{"publisher_proof":%q}`, proof), token.AccessToken, idempotency, http.StatusCreated)
	var setup controlv1.PublishRunSetup
	if err := json.Unmarshal(started.Body.Bytes(), &setup); err != nil || setup.PublishRun.PublishRunNumber <= int64(f.run.PublishRunNumber) {
		t.Fatalf("machine publish run = %s, %v", started.Body.String(), err)
	}
	f.call(http.MethodDelete, "/v1/publisher-identities/"+identity.ClientId+"?team_id="+f.publicURL.TeamID,
		"", f.owner.AccessToken.String(), "", http.StatusNoContent)
	f.call(http.MethodPost, "/v1/publish-runs/"+setup.PublishRun.Id+"/heartbeat",
		fmt.Sprintf(`{"publish_run_number":%d}`, setup.PublishRun.PublishRunNumber), setup.PublishRunToken, "", http.StatusUnauthorized)
	f.call(http.MethodGet, "/v1/publisher/public-url", "", token.AccessToken, "", http.StatusUnauthorized)
}

func TestIntegrationPublisherNamespaceAllocationUsesOnlyGrantedScope(t *testing.T) {
	f := newFeedbackPolicyAPIFixture(t, Config{DNSAutomation: true})
	authority, err := authorityapi.NewHandler(authorityapi.Config{ControlURL: "https://control.example"}, f.database)
	if err != nil {
		t.Fatal(err)
	}
	issued := f.call(http.MethodPost, "/v1/publisher/enrollments",
		fmt.Sprintf(`{"team_id":%q,"domain_id":%q,"public_url_scope":"shared","name":"namespace-app","kind":"installed"}`,
			f.publicURL.TeamID, f.publicURL.DomainID), f.owner.AccessToken.String(), "", http.StatusCreated)
	var enrollment controlv1.IssuedPublisherEnrollment
	if err := json.Unmarshal(issued.Body.Bytes(), &enrollment); err != nil || enrollment.Namespace == nil {
		t.Fatalf("namespace enrollment = %s, %v", issued.Body.String(), err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	callAuthority := func(path, body, contentType string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		request.Header.Set("Content-Type", contentType)
		response := httptest.NewRecorder()
		authority.ServeHTTP(response, request)
		if response.Code != http.StatusOK {
			t.Fatalf("authority POST %s = %d %s", path, response.Code, response.Body.String())
		}
		return response
	}
	redeemed := callAuthority("/v1/publisher/enrollments/redeem",
		fmt.Sprintf(`{"enrollment_key":%q,"public_key":%q}`, enrollment.EnrollmentKey, base64.RawURLEncoding.EncodeToString(public)), "application/json")
	var identity authorityv1.PublisherEnrollmentResult
	if err := json.Unmarshal(redeemed.Body.Bytes(), &identity); err != nil || identity.Namespace == nil || *identity.Namespace != *enrollment.Namespace {
		t.Fatalf("namespace identity = %s, %v", redeemed.Body.String(), err)
	}
	assertion, err := publisheridentity.Sign(identity.ClientId, identity.KeyId, "https://control.example/v1/publisher/token", private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {publisheridentity.GrantType}, "client_id": {identity.ClientId},
		"client_assertion_type": {publisheridentity.AssertionType}, "client_assertion": {assertion}, "scope": {identity.GrantId}}
	exchanged := callAuthority("/v1/publisher/token", form.Encode(), "application/x-www-form-urlencoded")
	var token authorityv1.PublisherTokenResponse
	if err := json.Unmarshal(exchanged.Body.Bytes(), &token); err != nil || token.AccessToken == "" {
		t.Fatalf("namespace token = %s, %v", exchanged.Body.String(), err)
	}
	f.call(http.MethodGet, "/v1/publisher/public-url", "", token.AccessToken, "", http.StatusForbidden)
	const invocation = "ivk_0123456789abcdefghijkl"
	body := fmt.Sprintf(`{"invocation_id":%q,"target":"http://127.0.0.1:3000","allow_all_ips":true}`, invocation)
	allocated := f.call(http.MethodPost, "/v1/ephemeral-public-urls", body, token.AccessToken, "", http.StatusCreated)
	var route controlv1.PublicURL
	if err := json.Unmarshal(allocated.Body.Bytes(), &route); err != nil || !route.Ephemeral ||
		!strings.HasSuffix(route.CanonicalHostname, "."+*identity.Namespace) {
		t.Fatalf("allocated URL = %s, %v", allocated.Body.String(), err)
	}
	retry := f.call(http.MethodPost, "/v1/ephemeral-public-urls", body, token.AccessToken, "", http.StatusCreated)
	var same controlv1.PublicURL
	if err := json.Unmarshal(retry.Body.Bytes(), &same); err != nil || same.Id != route.Id {
		t.Fatalf("invocation retry = %s, %v", retry.Body.String(), err)
	}
	proof, err := publisheridentity.SignRun(private, route.Id, "namespace-run")
	if err != nil {
		t.Fatal(err)
	}
	started := f.call(http.MethodPost, "/v1/public-urls/"+route.Id+"/publish-runs",
		fmt.Sprintf(`{"publisher_proof":%q}`, proof), token.AccessToken, "namespace-run", http.StatusCreated)
	var run controlv1.PublishRunSetup
	if err := json.Unmarshal(started.Body.Bytes(), &run); err != nil || run.PublishRun.PublicUrlId != route.Id {
		t.Fatalf("namespace publish run = %s, %v", started.Body.String(), err)
	}
	f.call(http.MethodDelete, "/v1/ephemeral-public-urls/"+route.Id, "", token.AccessToken, "", http.StatusNoContent)
	if _, err := f.database.GetPublicURLForAuthorization(t.Context(), route.Id); !errors.Is(err, controlstate.ErrPublicURLNotFound) {
		t.Fatalf("temporary URL remained after cleanup: %v", err)
	}
}

func TestIntegrationGuestPublisherIdentityCannotAcquireTeamScope(t *testing.T) {
	f := newFeedbackPolicyAPIFixture(t, Config{GuestDemoEnabled: true, DNSAutomation: true})
	authority, err := authorityapi.NewHandler(authorityapi.Config{ControlURL: "https://control.example"}, f.database)
	if err != nil {
		t.Fatal(err)
	}
	created := f.call(http.MethodPost, "/v1/guest-demo", "", "", "", http.StatusCreated)
	var guest controlv1.GuestDemoSession
	if err := json.Unmarshal(created.Body.Bytes(), &guest); err != nil || guest.AccessToken == "" {
		t.Fatalf("guest trial = %s, %v", created.Body.String(), err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registered := f.call(http.MethodPost, "/v1/guest-publisher/identity",
		fmt.Sprintf(`{"public_key":%q}`, base64.RawURLEncoding.EncodeToString(public)),
		guest.AccessToken, "", http.StatusCreated)
	var identity controlv1.GuestPublisherIdentity
	if err := json.Unmarshal(registered.Body.Bytes(), &identity); err != nil || identity.TeamId != guest.TeamId || identity.Namespace != guest.Namespace {
		t.Fatalf("guest publisher = %s, %v", registered.Body.String(), err)
	}
	assertion, err := publisheridentity.Sign(identity.ClientId, identity.KeyId, "https://control.example/v1/publisher/token", private, f.now)
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"grant_type": {publisheridentity.GrantType}, "client_id": {identity.ClientId},
		"client_assertion_type": {publisheridentity.AssertionType}, "client_assertion": {assertion}, "scope": {identity.GrantId}}
	request := httptest.NewRequest(http.MethodPost, "/v1/publisher/token", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	authority.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("guest publisher token = %d %s", response.Code, response.Body.String())
	}
	var token authorityv1.PublisherTokenResponse
	if err := json.Unmarshal(response.Body.Bytes(), &token); err != nil || token.AccessToken == "" {
		t.Fatalf("guest scoped token = %s, %v", response.Body.String(), err)
	}
	f.call(http.MethodGet, "/v1/public-urls/"+f.publicURL.ID, "", token.AccessToken, "", http.StatusUnauthorized)
	f.call(http.MethodGet, "/v1/publisher/public-url", "", token.AccessToken, "", http.StatusForbidden)
	f.call(http.MethodPost, "/v1/ephemeral-public-urls",
		`{"invocation_id":"ivk_0123456789abcdefghijkl","target":"http://127.0.0.1:3000","allow_all_ips":true}`,
		token.AccessToken, "", http.StatusUnauthorized)
	number := f.call(http.MethodPost, "/v1/guest-demo/number", "", guest.AccessToken, "", http.StatusOK)
	var reserved controlv1.GuestDemoNumber
	if err := json.Unmarshal(number.Body.Bytes(), &reserved); err != nil || reserved.Number != 1 {
		t.Fatalf("guest demo number = %s, %v", number.Body.String(), err)
	}
	hostname := "demo-1." + guest.Namespace
	createdURL := f.call(http.MethodPost, "/v1/public-urls",
		fmt.Sprintf(`{"team_id":%q,"domain_id":%q,"canonical_hostname":%q,"target":"http://127.0.0.1:3000","public_url_scope":"member","purpose":"demo","ephemeral":true,"allowed_ip_prefixes":["192.0.2.1/32"]}`,
			guest.TeamId, guest.DomainId, hostname), guest.AccessToken, "guest-demo-url", http.StatusCreated)
	var route controlv1.PublicURL
	if err := json.Unmarshal(createdURL.Body.Bytes(), &route); err != nil || route.CanonicalHostname != hostname {
		t.Fatalf("guest public URL = %s, %v", createdURL.Body.String(), err)
	}
	proof, err := publisheridentity.SignRun(private, route.Id, "guest-run")
	if err != nil {
		t.Fatal(err)
	}
	started := f.call(http.MethodPost, "/v1/public-urls/"+route.Id+"/publish-runs",
		fmt.Sprintf(`{"publisher_proof":%q}`, proof), token.AccessToken, "guest-run", http.StatusCreated)
	var run controlv1.PublishRunSetup
	if err := json.Unmarshal(started.Body.Bytes(), &run); err != nil || run.PublishRun.PublicUrlId != route.Id {
		t.Fatalf("guest publish run = %s, %v", started.Body.String(), err)
	}
	changedIP := httptest.NewRequest(http.MethodPost, "/v1/public-urls/"+route.Id+"/publish-runs",
		strings.NewReader(fmt.Sprintf(`{"publisher_proof":%q}`, proof)))
	changedIP.RemoteAddr = "192.0.2.8:1234"
	changedIP.Header.Set("Authorization", "Bearer "+token.AccessToken)
	changedIP.Header.Set("Idempotency-Key", "changed-ip")
	blocked := httptest.NewRecorder()
	f.mux.ServeHTTP(blocked, changedIP)
	if blocked.Code != http.StatusForbidden {
		t.Fatalf("changed guest IP = %d %s", blocked.Code, blocked.Body.String())
	}
}
