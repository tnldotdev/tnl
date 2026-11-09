package identity

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/client/credentialfile"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlapi "github.com/tnldotdev/tnl/internal/control/api/public"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type lostRegistrationReply struct {
	base  http.RoundTripper
	lost  atomic.Bool
	calls atomic.Int64
}

var errRegistrationReplyLost = errors.New("registration reply was lost")

func (r *lostRegistrationReply) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(request)
	if request.Method != http.MethodPost || request.URL.Path != "/v1/applications" {
		return response, err
	}
	r.calls.Add(1)
	if err == nil && response.StatusCode == http.StatusCreated && r.lost.CompareAndSwap(false, true) {
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		return nil, errRegistrationReplyLost
	}
	return response, err
}

func TestIntegrationApplicationCredentialSurvivesLostHTTPReplyAndSelectsEachGrant(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "application_credential_http")
	if err := controlstate.Migrate(t.Context(), databaseURL); err != nil {
		t.Fatal(err)
	}
	d, err := controlstate.Open(t.Context(), databaseURL, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "")
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
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
	url, err := d.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{TeamID: member.TeamID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "url", RequestDigest: sha256.Sum256([]byte("url")), CanonicalHostname: "app." + member.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := controlapi.NewHandler(controlapi.Config{DNSAutomation: true, ControlURL: "https://control.example.test"}, controlapi.DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	if _, err := controlauthority.Register(handler, controlauthority.Config{ControlURL: server.URL}, d); err != nil {
		t.Fatal(err)
	}
	transport := &lostRegistrationReply{base: server.Client().Transport}
	owner, err := clientcontrol.New(server.URL, &http.Client{Transport: transport}, session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	state, err := clientstate.OpenWithOptions(t.Context(), filepath.Join(root, "state"), clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	store, err := state.Server(t.Context(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "application.json")
	spec := RegistrationSpec{TeamID: member.TeamID, Name: "http-worker", Ownership: controlv1.RegisterApplicationMember, Grants: []controlv1.ApplicationGrantInput{{Operation: controlv1.ApplicationVisit, PublicUrlId: &url.ID}, {Operation: controlv1.ApplicationPublish, PublicUrlId: &url.ID}, {Operation: controlv1.ApplicationAllocate, DomainId: &domains[0].ID}}}
	if _, err := RegisterApplication(t.Context(), store, owner, output, spec); !errors.Is(err, errRegistrationReplyLost) {
		t.Fatal("lost HTTP response did not preserve its cause", err)
	}
	registered, err := RegisterApplication(t.Context(), store, owner, output, spec)
	if err != nil {
		t.Fatal(err)
	}
	if transport.calls.Load() != 2 {
		t.Fatal("registration replay did not make one exact retry")
	}
	file, err := credentialfile.Read(output)
	if err != nil || file.ClientID != registered.ClientId {
		t.Fatal("registration did not export its captured identity", err)
	}
	private, err := file.Validate()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	visitor, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, grant := range file.Grants {
		resource := url.ID
		if grant.Operation == controlv1.ApplicationAllocate {
			resource = domains[0].ID
		}
		selected, err := file.Select(grant.Operation, resource)
		if err != nil || selected.ID != grant.ID {
			t.Fatal("file selected another capability", err)
		}
		access, err := authority.ExchangePublisherAssertion(t.Context(), file.ClientID, selected.ID, file.KeyID, private)
		if err != nil {
			t.Fatal("exported private key did not match its registered grants", err)
		}
		if grant.Operation == controlv1.ApplicationVisit {
			source, err := json.Marshal(controlv1.VisitorTokenApplicationSource{Kind: controlv1.VisitorTokenApplication, Credential: access})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := visitor.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: url.ID}, Source: source}); err != nil {
				t.Fatal("portable visit grant required a personal session", err)
			}
		} else if grant.Operation == controlv1.ApplicationPublish {
			if saved, err := visitor.PublisherPublicURL(t.Context(), access); err != nil || saved.Id != url.ID {
				t.Fatal("portable publication grant changed its scope", err)
			}
		}
	}
	listed, err := owner.ListPublisherIdentities(t.Context(), member.TeamID, "")
	if err != nil || len(listed.Identities) != 1 || len(listed.Identities[0].Grants) != 3 {
		t.Fatal("lost reply created another remote identity or duplicate grants", err)
	}
}
