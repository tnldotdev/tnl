package control_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlapi "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationApplicationHTTPWebCryptoAgainstControl(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "application_sdk_http")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	now := time.Now().UTC()
	session, err := controltest.Session(t.Context(), d, "example.test", time.Hour, 24*time.Hour, now)
	if err != nil {
		t.Fatal(err)
	}
	member := session.Identity.Memberships[0]
	domains, err := d.ListTeamDomains(t.Context(), session.Identity.Identity.ID, member.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	u, err := d.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{TeamID: member.TeamID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "url", RequestDigest: sha256.Sum256([]byte("url")), CanonicalHostname: "app." + member.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewUnstartedServer(nil)
	origin := "https://" + server.Listener.Addr().String()
	handler, err := controlapi.NewHandler(controlapi.Config{DNSAutomation: true, ControlURL: origin}, controlapi.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := controlauthority.Register(handler, controlauthority.Config{ControlURL: origin}, d); err != nil {
		t.Fatal(err)
	}
	var proofs, permissions, ambient atomic.Int32
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/publisher-token" || r.URL.Path == "/v1/visitor-tokens" {
			if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
				ambient.Add(1)
			}
			if r.URL.Path == "/v1/publisher-token" {
				proofs.Add(1)
			} else {
				permissions.Add(1)
			}
		}
		handler.ServeHTTP(w, r)
	})
	server.StartTLS()
	t.Cleanup(server.Close)
	owner, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	registered, err := owner.RegisterApplication(t.Context(), "sdk-http", controlv1.RegisterApplicationRequest{TeamId: member.TeamID, Name: "sdk-http", Ownership: controlv1.RegisterApplicationMember, PublicKey: base64.RawURLEncoding.EncodeToString(public), Grants: []controlv1.ApplicationGrantInput{{Operation: controlv1.ApplicationVisit, PublicUrlId: &u.ID}, {Operation: controlv1.ApplicationPublish, PublicUrlId: &u.ID}}})
	if err != nil {
		t.Fatal(err)
	}
	file, err := credentialfile.NewApplication(origin, registered, private)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	credential := filepath.Join(root, "application.json")
	if err := credentialfile.Write(credential, file); err != nil {
		t.Fatal(err)
	}
	ca := filepath.Join(root, "control.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := d.RevokeControlSession(t.Context(), controlstate.ControlPrincipal{IdentityID: session.Identity.Identity.ID, SessionID: session.SessionID}, time.Now()); err != nil {
		t.Fatal(err)
	}
	_, source, _, _ := runtime.Caller(0)
	repo := filepath.Clean(filepath.Join(filepath.Dir(source), "../../../.."))
	check := func(mode string) {
		t.Helper()
		command := exec.CommandContext(t.Context(), "node", "packages/ts/test/fixtures/application-http-control.ts", credential, u.ID, "https://"+u.CanonicalHostname, mode)
		command.Dir = repo
		command.Env = append(os.Environ(), "NODE_EXTRA_CA_CERTS="+ca)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("SDK authority check %s: %v\n%s", mode, err, output)
		}
	}
	check("ready")
	if proofs.Load() != 2 || permissions.Load() != 2 || ambient.Load() != 0 {
		t.Fatal("SDK did not use one exact proof/visit exchange per independent scope", proofs.Load(), permissions.Load(), ambient.Load())
	}
	if err := d.RevokePublisherIdentity(t.Context(), member.TeamID, registered.ClientId, session.Identity.Identity.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	check("denied")
	if proofs.Load() != 4 || permissions.Load() != 2 || ambient.Load() != 0 {
		t.Fatal("revoked SDK authority retried or borrowed ambient authentication")
	}
}
