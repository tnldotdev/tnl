package invocation

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	clientauth "github.com/tnldotdev/tnl/internal/client/auth"
	authorityclient "github.com/tnldotdev/tnl/internal/client/authority"
	controlclient "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	publisheridentity "github.com/tnldotdev/tnl/internal/security/publisherproof"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type publicationHTTPTransport func(*http.Request) (*http.Response, error)

func (f publicationHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestForegroundPublicationReusesItsIdentityAndNeverCreatesRunsWithTheSession(t *testing.T) {
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(t.TempDir(), "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	const server = "https://control.example"
	store, err := state.Server(t.Context(), server)
	if err != nil {
		t.Fatal(err)
	}
	newID := func(prefix string) string {
		t.Helper()
		id, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	prefixes := []string{}
	route := controlv1.PublicURL{Id: newID(opaqueid.PublicURLPrefix), TeamId: newID(opaqueid.TeamPrefix), DomainId: newID(opaqueid.DomainPrefix), CanonicalHostname: "app.example", ServiceProtocol: controlv1.Http, PublicUrlScope: controlv1.Shared, Purpose: controlv1.App, LifecycleState: controlv1.Enabled, PolicyRevision: 1, NextPublishRunNumber: 1, CreatedAt: time.Now(), UpdatedAt: time.Now(), AllowedIpPrefixes: &prefixes}
	enrollmentID := newID(opaqueid.PublisherEnrollmentPrefix)
	enrollmentKey := enrollmentID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	identity := authorityv1.PublisherEnrollmentResult{ClientId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix), GrantId: newID(opaqueid.PublisherGrantPrefix), TeamId: route.TeamId, PublicUrlId: &route.Id, Kind: authorityv1.SavedUrl}
	sessionToken, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	var public ed25519.PublicKey
	enrollments, redemptions, runs := 0, 0, 0
	httpClient := &http.Client{Transport: publicationHTTPTransport(func(r *http.Request) (*http.Response, error) {
		var value any
		status := http.StatusOK
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/public-urls":
			if r.URL.Query().Get("team_id") != route.TeamId || r.URL.Query().Get("canonical_hostname") != route.CanonicalHostname {
				t.Errorf("publication selected an unfiltered URL lookup: %s", r.URL)
			}
			value = controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{route}}
		case "POST /v1/publisher-enrollments":
			enrollments++
			var body controlv1.CreatePublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if body.PublicUrlId == nil || *body.PublicUrlId != route.Id || body.DomainId != nil || body.TeamId != route.TeamId || r.Header.Get("Authorization") != "Bearer "+sessionToken.String() {
				t.Errorf("foreground owner did not request its exact saved URL: %+v", body)
			}
			status = http.StatusCreated
			value = controlv1.PublisherEnrollment{Id: enrollmentID, EnrollmentKey: enrollmentKey, ExpiresAt: time.Now().Add(time.Minute), PublicUrlId: &route.Id, TeamId: route.TeamId, Kind: "saved_url"}
		case "POST /v1/publisher-enrollments/redeem":
			redemptions++
			var body authorityv1.RedeemPublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if body.EnrollmentKey != enrollmentKey {
				t.Error("foreground owner redeemed a different enrollment")
			}
			public, err = base64.RawURLEncoding.DecodeString(body.PublicKey)
			if err != nil {
				return nil, err
			}
			value = identity
		case "POST /v1/publisher-token":
			var body authorityv1.PublisherTokenRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if _, err := publisheridentity.Verify(body.ClientAssertion, identity.ClientId, identity.KeyId, identity.GrantId, server+"/v1/publisher-token", public, time.Now()); err != nil {
				return nil, err
			}
			value = authorityv1.PublisherTokenResponse{AccessToken: "publisher-access", TokenType: "Bearer", ExpiresIn: 60, GrantId: identity.GrantId}
		case "POST /v1/public-urls/" + route.Id + "/publish-runs":
			runs++
			if r.Header.Get("Authorization") != "Bearer publisher-access" {
				t.Error("publish run used the team session")
			}
			if _, err := publisheridentity.VerifyRun(public, r.Header.Get("Publisher-Run-Proof"), route.Id, r.Header.Get("Idempotency-Key")); err != nil {
				return nil, err
			}
			status = http.StatusServiceUnavailable
			value = map[string]string{"code": "unavailable"}
		default:
			return nil, errors.New("unexpected publication request: " + r.Method + " " + r.URL.Path)
		}
		data, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
	})}
	control, err := controlclient.New(server, httpClient, sessionToken)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(server, httpClient, sessionToken)
	if err != nil {
		t.Fatal(err)
	}
	services := publisherServices{state: store, hostname: route.CanonicalHostname, teamID: route.TeamId, domainID: route.DomainId, publicURLScope: controlv1.Shared, routes: control, authenticated: &clientauth.Client{ServerEndpoint: server, Control: control, Authority: authority}}
	for range 2 {
		cfg := services.config("http://127.0.0.1:3000", prefixes, publisher.ApplicationLimits{})
		cfg.ServiceProtocol = controlv1.Http
		cleanup, err := selectForegroundPublisher(t.Context(), state, services, &cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !cfg.PreserveSavedURLTarget || cfg.Target != "http://127.0.0.1:3000" {
			t.Fatalf("private foreground target = %+v", cfg)
		}
		if _, err := cfg.Control.CreatePublishRun(t.Context(), route.Id, newID(opaqueid.IdempotencyPrefix)); !errors.Is(err, controlclient.ErrUnavailable) {
			t.Fatalf("signed run request = %v", err)
		}
		if err := cleanup(); err != nil {
			t.Fatal(err)
		}
	}
	if enrollments != 1 || redemptions != 1 || runs != 2 {
		t.Fatalf("enrollments=%d, redemptions=%d, signed runs=%d", enrollments, redemptions, runs)
	}
}
