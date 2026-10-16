package controlapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorization"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/controlstate"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/visitorcert"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"golang.org/x/crypto/ssh"
)

type sshVisitorURLStore struct {
	PublicURLStore
	auth     controlstate.PublishRunAuthentication
	protocol controlstate.PublicURLServiceProtocol
}

func (s *sshVisitorURLStore) PublishRunAuthentication(_ context.Context, _ string, _ uint64, _ credentials.PublishRunToken) (controlstate.PublishRunAuthentication, error) {
	return s.auth, nil
}

func (s *sshVisitorURLStore) GetPublicURLForAuthorization(_ context.Context, _ string) (controlstate.PublicURL, error) {
	return controlstate.PublicURL{ID: s.auth.PublicURLID, ServiceProtocol: s.protocol}, nil
}

type sshVisitorStore struct {
	VisitorStore
	identity, username string
	calls              int
}

type sshIdentityGrantStore struct {
	VisitorStore
	actor, identity string
	users           []string
}

func (s *sshIdentityGrantStore) CreateIdentityVisitorGrant(_ context.Context, urlID, actor, key, identity string, expires *time.Time, now time.Time, users ...string) (controlstate.VisitorGrant, error) {
	s.actor, s.identity, s.users = actor, identity, users
	return controlstate.VisitorGrant{ID: "grant", PublicURLID: urlID, Kind: "identity", IdentityID: identity, SSHUser: &users[0], CreatedAt: now, ExpiresAt: expires}, nil
}

func TestManagedSSHExplicitSelfGrantHTTPContract(t *testing.T) {
	state := &sshIdentityGrantStore{}
	h := &handler{visitorState: state, authorizer: &recordingAuthorizer{principal: testPublicURLReadPrincipal()}}
	server := httptest.NewTLSServer(controlv1.Handler(h))
	defer server.Close()
	client, err := controlclient.New(server.URL, server.Client(), "current-session")
	if err != nil {
		t.Fatal(err)
	}
	user := "deploy"
	grant, err := client.CreateIdentityVisitorGrant(t.Context(), "url", "self", controlv1.CreateIdentityVisitorGrantRequest{IdentityId: "identity_1", SshUser: &user})
	if err != nil || grant.IdentityId == nil || *grant.IdentityId != "identity_1" || grant.SshUser == nil || *grant.SshUser != user ||
		state.actor != "identity_1" || state.identity != "identity_1" || len(state.users) != 1 || state.users[0] != user {
		t.Fatalf("self grant = %+v, %v, state = %+v", grant, err, state)
	}
}

func (s *sshVisitorStore) SSHVisitorPermission(_ context.Context, _ controlstate.PublishRunAuthentication, identity, sourceIP, username string, now time.Time) (controlstate.VisitorPermission, error) {
	s.calls++
	s.identity, s.username = identity, username
	expires := now.Add(2 * time.Minute)
	return controlstate.VisitorPermission{IdentityID: identity, SSHUser: username, VisitAllowed: username == "" || username == "alice", ExpiresAt: &expires}, nil
}

func TestManagedSSHVisitorCertificateBoundary(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	urlID, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	otherURL, _ := opaqueid.New(opaqueid.PublicURLPrefix)
	identity, _ := opaqueid.New(opaqueid.IdentityPrefix)
	issuer, err := visitorcert.New(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	otherIssuer, err := visitorcert.New(bytes.Repeat([]byte{2}, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	expires := now.Add(time.Minute)
	certificate := func(issuer *visitorcert.Issuer, id string) *string {
		raw, err := issuer.Issue(csr, id, identity, expires, now)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(raw)
		encoded := base64.StdEncoding.EncodeToString(block.Bytes)
		return &encoded
	}
	valid := certificate(issuer, urlID)
	user := func(value string) *string { return &value }
	for _, test := range []struct {
		name, protocol string
		cert, username *string
		status, calls  int
	}{
		{"certificate mandatory on allowed IP", "ssh", nil, nil, 403, 0},
		{"wrong URL", "ssh", certificate(issuer, otherURL), nil, 403, 0},
		{"wrong issuer", "ssh", certificate(otherIssuer, urlID), nil, 403, 0},
		{"invalid certificate", "ssh", user("invalid"), nil, 403, 0},
		{"root forbidden", "ssh", valid, user("root"), 400, 0},
		{"empty account forbidden", "ssh", valid, user(""), 400, 0},
		{"wrong account", "ssh", valid, user("bob"), 403, 1},
		{"connection-level grant", "ssh", valid, nil, 200, 1},
		{"exact account", "ssh", valid, user("alice"), 200, 1},
		{"database rejects account", "postgres", valid, user("alice"), 400, 0},
	} {
		t.Run(test.name, func(t *testing.T) {
			state := &sshVisitorStore{}
			h := &handler{visitorState: state, visitorIssuer: issuer, store: &sshVisitorURLStore{
				auth: controlstate.PublishRunAuthentication{PublicURLID: urlID}, protocol: controlstate.PublicURLServiceProtocol(test.protocol),
			}}
			body, err := json.Marshal(controlv1.AuthorizeVisitorCertificateJSONRequestBody{PublishRunNumber: 1, SourceIp: "192.0.2.9", Certificate: test.cert, SshUser: test.username})
			if err != nil {
				t.Fatal(err)
			}
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer run-token")
			response := httptest.NewRecorder()
			h.AuthorizeVisitorCertificate(response, r, "run")
			if response.Code != test.status || state.calls != test.calls {
				t.Fatalf("decision = %d %s, state calls = %d", response.Code, response.Body.String(), state.calls)
			}
			if test.status != 200 {
				return
			}
			var decision struct {
				IdentityID  string    `json:"identity_id"`
				PublicURLID string    `json:"public_url_id"`
				SSHUser     string    `json:"ssh_user"`
				ValidUntil  time.Time `json:"valid_until"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &decision); err != nil {
				t.Fatal(err)
			}
			if decision.IdentityID != identity || decision.PublicURLID != urlID || !decision.ValidUntil.Equal(expires) ||
				decision.SSHUser != optionalFeedbackString(test.username) || state.identity != identity {
				t.Fatalf("decision = %+v, state = %+v", decision, state)
			}
		})
	}
}

func TestManagedSSHCreationRequiresRegisteredHostKey(t *testing.T) {
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{3}, ed25519.SeedSize))
	public, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	hostKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	for _, test := range []struct {
		name, protocol, access, target string
		key                            *string
		status                         int
	}{
		{"managed SSH", "ssh", "restricted", "", &hostKey, 201},
		{"required key", "ssh", "restricted", "", nil, 400},
		{"anonymous forbidden", "ssh", "anonymous", "", &hostKey, 400},
		{"forward target forbidden", "ssh", "restricted", "http://127.0.0.1:22", &hostKey, 400},
		{"HTTP forbids key", "http", "restricted", "http://127.0.0.1:3000", &hostKey, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			port := uint16(2222)
			store := &publicURLCreationStore{result: controlstate.PublicURL{SSHHostKey: hostKey, PublicPort: &port, ServiceProtocol: controlstate.PublicURLServiceSSH}}
			authorizer := &recordingAuthorizer{decision: authorization.Decision{IdentityID: "identity", TeamID: "team", DomainID: "domain", PublicURLMembershipID: "membership", CanonicalHostname: "ssh.example.test", PublicURLScope: authorization.PublicURLScopeMember, PolicyRevision: 1}}
			h := &handler{store: store, authorizer: authorizer}
			protocol := controlv1.PublicURLServiceProtocol(test.protocol)
			access := controlv1.VisitorAccessMode(test.access)
			body, _ := json.Marshal(controlv1.CreatePublicURLRequest{TeamId: "team", DomainId: "domain", CanonicalHostname: "ssh.example.test", PublicUrlScope: controlv1.Member, Purpose: controlv1.App, Target: test.target, ServiceProtocol: &protocol, AccessMode: &access, SshHostKey: test.key})
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewReader(body))
			r.Header.Set("Authorization", "Bearer access-token")
			response := httptest.NewRecorder()
			h.CreatePublicURL(response, r, controlv1.CreatePublicURLParams{})
			if response.Code != test.status {
				t.Fatalf("create = %d %s", response.Code, response.Body.String())
			}
			if test.status == 201 && (len(store.requests) != 1 || store.requests[0].SSHHostKey != hostKey || !strings.Contains(response.Body.String(), `"ssh_host_key"`)) {
				t.Fatalf("host key missing from creation or metadata: %+v %s", store.requests, response.Body.String())
			}
		})
	}
}
