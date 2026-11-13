package connector

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/policy/visitorsubject"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
)

func connectorDeploymentCredential(t *testing.T, server string) auth.DeploymentCredential {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c := auth.DeploymentCredential{Version: 1, ControlURL: server, Team: "acme", PrivateKey: base64.RawURLEncoding.EncodeToString(key)}
	c.Approval = controlv1.DeploymentCredential{TeamId: "tm_" + strings.Repeat("a", 22), ProjectKey: "shop", ClientId: "pub_" + strings.Repeat("a", 22), KeyId: "pkey_" + strings.Repeat("a", 22), GrantId: "pgrant_" + strings.Repeat("a", 22), ExpiresAt: time.Now().Add(time.Hour)}
	c.Approval.Permissions.Connect = new(controlv1.DeploymentCredentialServiceProtocols{"db": "postgres", "web": "http", "cache": "tcp", "mysql": "mysql", "cluster": "kubernetes"})
	return c
}

func TestDeploymentContextNeedsNoProjectFilesAndFencesExactSelection(t *testing.T) {
	c := connectorDeploymentCredential(t, "https://control.example.test")
	token, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	r := connectorruntime.DeploymentRequest{Project: "acme/shop", Name: "production", Token: token}
	o := ContextOptions{Directory: t.TempDir(), Deployment: &r}
	p, first, err := connectionDeployment(o)
	if err != nil {
		t.Fatal(err)
	}
	if first.Deployment != "production" || first.Workload != "" || first.TeamID != c.Approval.TeamId || len(p.Config.Services) != 5 {
		t.Fatal("borrowed local/provider configuration")
	}
	if p.Deployment != first.Deployment || p.Config.Deployment != first.Deployment {
		t.Fatal("registered connection lost its selected deployment")
	}
	data, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), token) || strings.Contains(string(data), c.PrivateKey) {
		t.Fatal("context retained signing credential")
	}
	r.Name = "customer"
	_, sibling, err := connectionDeployment(o)
	if err != nil || first.ConfigDigest == sibling.ConfigDigest {
		t.Fatal("deployment selection shared an owner", err)
	}
	r.Name = "production"
	_, replacement, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c.PrivateKey = base64.RawURLEncoding.EncodeToString(replacement)
	r.Token, err = c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := connectionDeployment(o)
	if err != nil || first.ConfigDigest == wrongKey.ConfigDigest {
		t.Fatal("another signing key could adopt retained owner", err)
	}
	r.Project = "foreign/shop"
	if _, _, err := connectionDeployment(o); !errors.Is(err, connectorruntime.ErrInvalid) {
		t.Fatal("accepted foreign project", err)
	}
}

func TestDeploymentConnectorUsesRegisteredSourceAndCurrentRevocation(t *testing.T) {
	var credential auth.DeploymentCredential
	var denied atomic.Bool
	var exchanges atomic.Int64
	const service = "svc_aaaaaaaaaaaaaaaaaaaaaa"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/publisher-token" {
			exchanges.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "pta_private", "grant_id": credential.Approval.GrantId, "token_type": "Bearer", "expires_in": 300})
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("visitor request carried management bearer")
		}
		var body struct {
			Source controlv1.VisitorTokenSource `json:"source"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil {
			t.Error("invalid source request")
		}
		var source controlv1.VisitorTokenRegisteredKeySource
		if json.Unmarshal(body.Source, &source) != nil || source.Kind != "registered_key" || source.Credential != "pta_private" {
			t.Error("borrowed human or workload authority")
		}
		if denied.Load() {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"title":"revoked","status":401,"code":"unauthenticated"}`))
			return
		}
		_ = json.NewEncoder(w).Encode(controlv1.ServiceSelection{ServiceId: service, ServiceRunId: "srun_aaaaaaaaaaaaaaaaaaaaaa", RunNumber: 1, TrustRevision: 1, Protocol: "postgres", Endpoint: &controlv1.ServiceEndpoint{Hostname: "db.example.test", Port: 5432}, ExpiresAt: time.Now().Add(time.Minute), Subject: visitorsubject.Wire(credential.Subject())})
	}))
	defer server.Close()
	credential = connectorDeploymentCredential(t, server.URL)
	token, err := credential.Encode()
	if err != nil {
		t.Fatal(err)
	}
	d, err := newDeploymentConnection(connectorruntime.DeploymentRequest{Project: "acme/shop", Name: "production", Token: token}, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	control, err := d.controlFor("db", service)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := control.ConnectorSigner(t.Context(), "")
	if err != nil {
		t.Fatal(err)
	}
	if signer.Subject.Kind != tunnelv1.VisitorRegisteredKey || !ed25519.Verify(signer.PublicKey, []byte("proof"), signer.Sign([]byte("proof"))) {
		t.Fatal("wrong registered signer")
	}
	if _, err := control.ConnectorSigner(context.Background(), "person"); !errors.Is(err, connectorruntime.ErrUnauthorized) {
		t.Fatal("registered signer accepted a human identity")
	}
	for range 2 {
		if _, err := control.ResolveService(t.Context(), service); err != nil {
			t.Fatal(err)
		}
	}
	if exchanges.Load() != 1 {
		t.Fatal("signed token cache was not owner-bound")
	}
	denied.Store(true)
	if _, err := control.ResolveService(t.Context(), service); err == nil {
		t.Fatal("retained token bypassed current revocation")
	}
	if _, err := control.ResolveService(t.Context(), "svc_bbbbbbbbbbbbbbbbbbbbbb"); !errors.Is(err, connectorruntime.ErrUnauthorized) {
		t.Fatal("adapter selected another saved binding", err)
	}
}
