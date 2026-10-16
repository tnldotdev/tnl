package controlclient

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestSSHVisitorDecisionRequiresScopedIdentityAccountAndDeadline(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	expires := now.Add(time.Minute)
	leaf := &x509.Certificate{Raw: []byte("certificate proof"), NotAfter: now.Add(2 * time.Minute)}
	tlsState := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
	scope := VisitorCertificateScope{PublishRunID: "run", PublicURLID: "url", PublishRunNumber: 3, PublishRunToken: "run-token", SourceIP: netip.MustParseAddr("::ffff:192.0.2.9")}
	for _, test := range []struct {
		name, username string
		decision       visitorCertificateDecision
		valid          bool
	}{
		{"connection-level", "", visitorCertificateDecision{IdentityID: "identity", PublicURLID: "url", ValidUntil: &expires}, true},
		{"exact account", "alice", visitorCertificateDecision{IdentityID: "identity", PublicURLID: "url", SSHUser: "alice", ValidUntil: &expires}, true},
		{"wrong URL", "alice", visitorCertificateDecision{IdentityID: "identity", PublicURLID: "other", SSHUser: "alice", ValidUntil: &expires}, false},
		{"missing identity", "alice", visitorCertificateDecision{PublicURLID: "url", SSHUser: "alice", ValidUntil: &expires}, false},
		{"wrong account", "alice", visitorCertificateDecision{IdentityID: "identity", PublicURLID: "url", SSHUser: "bob", ValidUntil: &expires}, false},
		{"missing account", "alice", visitorCertificateDecision{IdentityID: "identity", PublicURLID: "url", ValidUntil: &expires}, false},
		{"missing deadline", "alice", visitorCertificateDecision{IdentityID: "identity", PublicURLID: "url", SSHUser: "alice"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body controlv1.AuthorizeVisitorCertificateJSONRequestBody
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if r.URL.Path != "/v1/publish-runs/run/visitor-certificate" || r.Header.Get("Authorization") != "Bearer run-token" ||
					body.PublishRunNumber != 3 || body.SourceIp != "192.0.2.9" || body.Certificate == nil || *body.Certificate != base64.StdEncoding.EncodeToString(leaf.Raw) ||
					test.username == "" && body.SshUser != nil || test.username != "" && (body.SshUser == nil || *body.SshUser != test.username) {
					t.Errorf("unexpected decision request: %s %+v", r.URL, body)
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(test.decision)
			}))
			defer server.Close()
			client, err := New(server.URL, server.Client(), "")
			if err != nil {
				t.Fatal(err)
			}
			decision, err := client.AuthorizeSSHVisitor(t.Context(), scope, tlsState, test.username)
			if (err == nil) != test.valid {
				t.Fatalf("decision = %+v, error = %v", decision, err)
			}
			if test.valid && (decision.IdentityID != "identity" || decision.PublicURLID != "url" || decision.SSHUser != test.username || !decision.ValidUntil.Equal(expires)) {
				t.Fatalf("decision = %+v", decision)
			}
		})
	}
}

func TestSSHVisitorRejectsMissingTLSProofAndRootBeforeRequest(t *testing.T) {
	client, err := New("https://control.example.test", &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		t.Error("invalid SSH proof reached control")
		return nil, nil
	})}, "")
	if err != nil {
		t.Fatal(err)
	}
	scope := VisitorCertificateScope{PublishRunID: "run", PublicURLID: "url", PublishRunNumber: 1, PublishRunToken: "token", SourceIP: netip.MustParseAddr("192.0.2.9")}
	for _, test := range []struct {
		name, username string
		state          tls.ConnectionState
	}{
		{"missing certificate", "alice", tls.ConnectionState{HandshakeComplete: true}},
		{"missing handshake", "alice", tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}},
		{"root", "root", tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{{}}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := client.AuthorizeSSHVisitor(t.Context(), scope, test.state, test.username); err == nil {
				t.Fatal("invalid SSH proof accepted")
			}
		})
	}
}
