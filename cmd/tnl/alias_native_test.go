package main

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

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/localproxy"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisheridentity"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestProjectAliasPreparesAnExactNativePublisherOnlyForTheSelectedReadyReceiver(t *testing.T) {
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
	project, target := t.TempDir(), "https://127.0.0.1:3000"
	group := project + "\x00member.example"
	parentID := newID(opaqueid.PublicURLPrefix)
	tunnel, err := state.BeginTunnel(t.Context(), clientstate.BeginTunnelOptions{Command: clientstate.TunnelCommandPublish, Server: server, Project: project, Service: "web", Target: target, IntegrationGroup: group})
	if err != nil {
		t.Fatal(err)
	}
	defer tunnel.Finish(t.Context(), nil)
	if err := tunnel.SetPublicURL(t.Context(), parentID, "web.member.example"); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.SetProvisioning(t.Context(), 1); err != nil {
		t.Fatal(err)
	}
	prefixes := []string{"192.0.2.1/32"}
	membership := "membership"
	route := controlv1.PublicURL{Id: newID(opaqueid.PublicURLPrefix), TeamId: "team", DomainId: "domain", MembershipId: &membership, CanonicalHostname: "review.member.example", ServiceProtocol: controlv1.Http, PublicUrlScope: controlv1.Member, Purpose: controlv1.Alias, LifecycleState: controlv1.Enabled, AccessMode: controlv1.Restricted, AllowedIpPrefixes: &prefixes}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix), GrantId: newID(opaqueid.PublisherGrantPrefix), TeamId: route.TeamId, PublicUrlId: &route.Id, Kind: authorityv1.SavedUrl}
	enrollmentID := newID(opaqueid.PublisherEnrollmentPrefix)
	enrollmentKey := enrollmentID + "." + base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	requests, creations, enrollments, redemptions, runs := 0, 0, 0, 0, 0
	var public ed25519.PublicKey
	transport := publicationHTTPTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		status, token := http.StatusOK, r.Header.Get("Authorization")
		var value any
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/public-urls":
			if token != "Bearer session" {
				t.Error("saved URL lookup did not use setup authority")
			}
			page := controlv1.PublicURLPage{PublicUrls: []controlv1.PublicURL{}}
			if creations != 0 {
				page.PublicUrls = append(page.PublicUrls, route)
			}
			value = page
		case "POST /v1/public-urls":
			var body controlv1.CreatePublicURLRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if token != "Bearer session" || body.Target != "" || body.Purpose != controlv1.Alias || body.PublicUrlScope != controlv1.Member || body.MembershipId == nil || *body.MembershipId != membership || body.CanonicalHostname != route.CanonicalHostname {
				t.Errorf("alias reservation changed target, purpose, or ownership: %+v", body)
			}
			creations++
			status, value = http.StatusCreated, route
		case "POST /v1/publisher-enrollments":
			var body controlv1.CreatePublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if token != "Bearer session" || body.TeamId != route.TeamId || body.PublicUrlId == nil || *body.PublicUrlId != route.Id || body.DomainId != nil {
				t.Error("alias enrollment widened its grant")
			}
			enrollments++
			status, value = http.StatusCreated, controlv1.PublisherEnrollment{Id: enrollmentID, EnrollmentKey: enrollmentKey, ExpiresAt: time.Now().Add(time.Minute), PublicUrlId: &route.Id, TeamId: route.TeamId, Kind: "saved_url"}
		case "POST /v1/publisher-enrollments/redeem":
			var body authorityv1.RedeemPublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if body.EnrollmentKey != enrollmentKey || token != "" {
				t.Error("alias redemption used another enrollment or a person token")
			}
			public, err = base64.RawURLEncoding.DecodeString(body.PublicKey)
			if err != nil {
				return nil, err
			}
			redemptions++
			value = identity
		case "POST /v1/publisher-token":
			var body authorityv1.PublisherTokenRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if _, err := publisheridentity.Verify(body.ClientAssertion, identity.ClientId, identity.KeyId, identity.GrantId, server+"/v1/publisher-token", public, time.Now()); err != nil {
				return nil, err
			}
			if token != "" {
				t.Error("alias assertion exchange used person credentials")
			}
			value = authorityv1.PublisherTokenResponse{AccessToken: "alias-access", TokenType: "Bearer", ExpiresIn: 60, GrantId: identity.GrantId}
		case "POST /v1/public-urls/" + route.Id + "/publish-runs":
			if token != "Bearer alias-access" {
				t.Error("alias run used the person session")
			}
			if _, err := publisheridentity.VerifyRun(public, r.Header.Get("Publisher-Run-Proof"), route.Id, r.Header.Get("Idempotency-Key")); err != nil {
				return nil, err
			}
			runs++
			status, value = http.StatusServiceUnavailable, map[string]string{"code": "unavailable"}
		default:
			return nil, errors.New("unexpected alias request: " + r.Method + " " + r.URL.Path)
		}
		data, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(bytes.NewReader(data)), Request: r}, nil
	})
	previous := http.DefaultTransport
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = previous }()
	control, err := controlclient.New(server, &http.Client{Transport: transport}, "session")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(server, &http.Client{Transport: transport}, "session")
	if err != nil {
		t.Fatal(err)
	}
	services := publisherServices{state: store, hostname: route.CanonicalHostname, teamID: route.TeamId, domainID: route.DomainId, membershipID: membership, namespace: "member.example", publicURLScope: controlv1.Member, routes: control, authenticated: &clientauth.Client{ServerEndpoint: server, Control: control, Authority: authority}}
	scope := clientstate.AliasScope{Server: server, ProjectKey: project, TeamID: route.TeamId, MembershipID: membership, Namespace: services.namespace, Name: "review"}
	selection, err := state.RegisterAlias(t.Context(), clientstate.AliasRegistration{Scope: scope, Hostname: route.CanonicalHostname, Service: "web", TunnelID: tunnel.ID(), IntegrationGroup: group})
	if err != nil {
		t.Fatal(err)
	}
	admissions, responses := 0, 0
	base := publisher.Config{Target: target, TargetOptions: localproxy.TargetOptions{ServerName: "web.internal"}, Mounts: []localproxy.Mount{{Prefix: "/api", Target: "http://127.0.0.1:4000"}}, Feedback: true, PreviewID: "parent-preview",
		AdmitRequest: func(_ *http.Request, run publisher.PublishRunIdentity) error {
			admissions++
			if run.PublicURLID != parentID || run.Number != 1 {
				t.Error("alias lost entry-service admission identity")
			}
			return nil
		},
		ObserveResponse: func(*http.Response, publisher.PublishRunIdentity) error { responses++; return nil }}
	worker := projectAliasPublisher(state, services, selection, tunnel.ID(), base, resolvedVisitorAccess{access: controlv1.Restricted, prefixes: prefixes}, nil)
	if eligible, err := worker.Eligible(t.Context()); err != nil || eligible {
		t.Fatalf("unready alias eligible=%t err=%v", eligible, err)
	}
	if _, err := worker.Prepare(t.Context()); !errors.Is(err, clientstate.ErrAliasReceiverUnavailable) || requests != 0 {
		t.Fatalf("unready alias acquired remote state: requests=%d err=%v", requests, err)
	}
	if err := tunnel.SetReady(t.Context(), "https://web.member.example", 1); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		snapshot, err := worker.Prepare(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		cfg := snapshot.Config
		if cfg.PublisherID != identity.ClientId || !cfg.PreserveSavedURLTarget || cfg.Target != target || cfg.Purpose != controlv1.Alias || cfg.Feedback || cfg.PreviewID != "" || cfg.TargetOptions.ServerName != base.TargetOptions.ServerName || len(cfg.Mounts) != 1 || cfg.Mounts[0].Target != base.Mounts[0].Target {
			t.Fatalf("alias lost its local publication snapshot: %+v", cfg)
		}
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+route.CanonicalHostname+"/", nil)
		if err := cfg.AdmitRequest(request, publisher.PublishRunIdentity{}); err != nil {
			t.Fatal(err)
		}
		if err := cfg.ObserveResponse(&http.Response{}, publisher.PublishRunIdentity{}); err != nil {
			t.Fatal(err)
		}
		if _, err := cfg.Control.UpdatePublicURL(t.Context(), route.Id, controlv1.UpdatePublicURLRequest{Target: target}); !errors.Is(err, nativeauth.ErrScope) {
			t.Fatalf("alias runtime retained person mutation authority: %v", err)
		}
		if _, err := cfg.Control.CreatePublishRun(t.Context(), route.Id, newID(opaqueid.IdempotencyPrefix)); !errors.Is(err, controlclient.ErrUnavailable) {
			t.Fatalf("signed alias run: %v", err)
		}
	}
	if creations != 1 || enrollments != 1 || redemptions != 1 || runs != 2 || admissions != 2 || responses != 2 {
		t.Fatalf("alias lifecycle: create=%d enroll=%d redeem=%d runs=%d admit=%d responses=%d", creations, enrollments, redemptions, runs, admissions, responses)
	}
}
