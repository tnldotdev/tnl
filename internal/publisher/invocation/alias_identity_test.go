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

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/publisher"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	publicURL := controlv1.PublicURL{Id: newID(opaqueid.PublicURLPrefix), TeamId: "team", DomainId: "domain", MembershipId: &membership, CanonicalHostname: "review.member.example", ServiceProtocol: controlv1.Http, PublicUrlScope: controlv1.Member, Purpose: controlv1.Alias, LifecycleState: controlv1.Enabled, AccessMode: controlv1.Restricted, AllowedIpPrefixes: &prefixes}
	identity := authorityv1.PublisherEnrollmentResult{ClientId: newID(opaqueid.PublisherIdentityPrefix), KeyId: newID(opaqueid.PublisherIdentityKeyPrefix), GrantId: newID(opaqueid.PublisherGrantPrefix), TeamId: publicURL.TeamId, PublicUrlId: &publicURL.Id, Kind: authorityv1.SavedPublicUrl}
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
				page.PublicUrls = append(page.PublicUrls, publicURL)
			}
			value = page
		case "POST /v1/public-urls":
			var body controlv1.CreatePublicURLRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if token != "Bearer session" || body.Target != "" || body.Purpose != controlv1.Alias || body.PublicUrlScope != controlv1.Member || body.MembershipId == nil || *body.MembershipId != membership || body.CanonicalHostname != publicURL.CanonicalHostname {
				t.Errorf("alias reservation changed target, purpose, or ownership: %+v", body)
			}
			creations++
			status, value = http.StatusCreated, publicURL
		case "POST /v1/publisher-enrollments":
			var body controlv1.CreatePublisherEnrollmentRequest
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				return nil, err
			}
			if token != "Bearer session" || body.TeamId != publicURL.TeamId || body.PublicUrlId == nil || *body.PublicUrlId != publicURL.Id || body.DomainId != nil {
				t.Error("alias enrollment widened its grant")
			}
			enrollments++
			status, value = http.StatusCreated, controlv1.PublisherEnrollment{Id: enrollmentID, EnrollmentKey: enrollmentKey, ExpiresAt: time.Now().Add(time.Minute), PublicUrlId: &publicURL.Id, TeamId: publicURL.TeamId, Kind: "saved_public_url"}
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
			if _, err := publisherproof.Verify(body.ClientAssertion, identity.ClientId, identity.KeyId, identity.GrantId, server+"/v1/publisher-token", public, time.Now()); err != nil {
				return nil, err
			}
			if token != "" {
				t.Error("alias assertion exchange used person credentials")
			}
			value = authorityv1.PublisherTokenResponse{AccessToken: "alias-access", TokenType: "Bearer", ExpiresIn: 60, GrantId: identity.GrantId}
		case "POST /v1/public-urls/" + publicURL.Id + "/publish-runs":
			if token != "Bearer alias-access" {
				t.Error("alias run used the person session")
			}
			if _, err := publisherproof.VerifyRun(public, r.Header.Get("Publisher-Run-Proof"), publicURL.Id, r.Header.Get("Idempotency-Key")); err != nil {
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
	control, err := clientcontrol.New(server, &http.Client{Transport: transport}, "session")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server, &http.Client{Transport: transport}, "session")
	if err != nil {
		t.Fatal(err)
	}
	services := publisherServices{state: store, hostname: publicURL.CanonicalHostname, teamID: publicURL.TeamId, domainID: publicURL.DomainId, membershipID: membership, namespace: "member.example", publicURLScope: controlv1.Member, routes: control, authenticated: &auth.Client{ServerEndpoint: server, Control: control, Authority: authority}}
	scope := clientstate.AliasScope{Server: server, ProjectKey: project, TeamID: publicURL.TeamId, MembershipID: membership, Namespace: services.namespace, Name: "review"}
	selection, err := state.RegisterAlias(t.Context(), clientstate.AliasRegistration{Scope: scope, Hostname: publicURL.CanonicalHostname, Service: "web", TunnelID: tunnel.ID(), IntegrationGroup: group})
	if err != nil {
		t.Fatal(err)
	}
	admissions, responses := 0, 0
	base := publisher.Config{Target: target, TargetOptions: publisherproxy.TargetOptions{ServerName: "web.internal"}, Mounts: []publisherproxy.Mount{{Prefix: "/api", Target: "http://127.0.0.1:4000"}}, Feedback: true, PreviewID: "parent-preview",
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
		if cfg.PublisherIdentityID != identity.ClientId || !cfg.PreserveSavedPublicURLTarget || cfg.Target != target || cfg.Purpose != controlv1.Alias || cfg.Feedback || cfg.PreviewID != "" || cfg.TargetOptions.ServerName != base.TargetOptions.ServerName || len(cfg.Mounts) != 1 || cfg.Mounts[0].Target != base.Mounts[0].Target {
			t.Fatalf("alias lost its local publication snapshot: %+v", cfg)
		}
		request, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, "https://"+publicURL.CanonicalHostname+"/", nil)
		if err := cfg.AdmitRequest(request, publisher.PublishRunIdentity{}); err != nil {
			t.Fatal(err)
		}
		if err := cfg.ObserveResponse(&http.Response{}, publisher.PublishRunIdentity{}); err != nil {
			t.Fatal(err)
		}
		if _, ok := cfg.Control.(publisher.PublicURLManagementClient); ok {
			t.Fatal("alias runtime retained person mutation authority")
		}
		if _, err := cfg.Control.CreatePublishRun(t.Context(), publicURL.Id, newID(opaqueid.IdempotencyPrefix)); !errors.Is(err, clientcontrol.ErrUnavailable) {
			t.Fatalf("signed alias run: %v", err)
		}
	}
	if creations != 1 || enrollments != 1 || redemptions != 1 || runs != 2 || admissions != 2 || responses != 2 {
		t.Fatalf("alias lifecycle: create=%d enroll=%d redeem=%d runs=%d admit=%d responses=%d", creations, enrollments, redemptions, runs, admissions, responses)
	}
}
