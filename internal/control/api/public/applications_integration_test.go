package public

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	controlauthority "github.com/tnldotdev/tnl/internal/control/api/authority"
	controlstate "github.com/tnldotdev/tnl/internal/control/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/controltest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationApplicationRegistrationHTTP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	databaseURL := testutil.NewDisposablePostgresDatabaseURL(t, "application_registration_http")
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
	url, err := d.CreatePublicURL(t.Context(), controlstate.CreatePublicURLRequest{TeamID: member.TeamID, DomainID: domains[0].ID, MembershipID: member.ID, ActingIdentityID: session.Identity.Identity.ID, IdempotencyKey: "url", RequestDigest: sha256.Sum256([]byte("url")), CanonicalHostname: "app." + member.ManagedLabel + ".example.test", Target: "http://127.0.0.1:3000", PublicURLScope: controlstate.PublicURLScopeMember, Purpose: controlstate.PublicURLPurposeApp, DNSState: controlstate.PublicURLDNSUnmanaged}, now)
	if err != nil {
		t.Fatal(err)
	}
	control, err := NewHandler(Config{DNSAutomation: true, ControlURL: "https://control.example.test"}, DatabaseStores(d), d, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewTLSServer(control)
	t.Cleanup(server.Close)
	if _, err := controlauthority.Register(control, controlauthority.Config{ControlURL: server.URL}, d); err != nil {
		t.Fatal(err)
	}
	owner, err := clientcontrol.New(server.URL, server.Client(), session.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	client, err := clientcontrol.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), "")
	if err != nil {
		t.Fatal(err)
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body := controlv1.RegisterApplicationRequest{TeamId: member.TeamID, Name: "server-app", Ownership: controlv1.RegisterApplicationMember, PublicKey: base64.RawURLEncoding.EncodeToString(public), Grants: []controlv1.ApplicationGrantInput{
		{Operation: controlv1.ApplicationVisit, PublicUrlId: &url.ID},
		{Operation: controlv1.ApplicationPublish, PublicUrlId: &url.ID},
		{Operation: controlv1.ApplicationAllocate, DomainId: &domains[0].ID},
	}}
	registered, err := owner.RegisterApplication(t.Context(), "same-application", body)
	if err != nil {
		t.Fatal(err)
	}
	if len(registered.Grants) != 3 || registered.ClientId == "" || registered.KeyId == "" {
		t.Fatal("registration did not return one key and its exact grants")
	}
	retry, err := owner.RegisterApplication(t.Context(), "same-application", body)
	if err != nil || !reflect.DeepEqual(retry, registered) {
		t.Fatal("registration reply could not be recovered", err)
	}
	changed := body
	changed.Name = "different"
	if _, err := owner.RegisterApplication(t.Context(), "same-application", changed); !errors.Is(err, clientcontrol.ErrStatusConflict) {
		t.Fatal("registration retry widened its captured request", err)
	}
	for index, grant := range registered.Grants {
		if grant.Operation != body.Grants[index].Operation {
			t.Fatal("HTTP response dropped the explicit operation")
		}
		access, err := authority.ExchangePublisherAssertion(t.Context(), registered.ClientId, grant.Id, registered.KeyId, private)
		if err != nil {
			t.Fatal("registered key could not exchange for its exact grant", err)
		}
		if grant.Operation == controlv1.ApplicationVisit {
			source, err := json.Marshal(controlv1.VisitorTokenApplicationSource{Kind: controlv1.VisitorTokenApplication, Credential: access})
			if err != nil {
				t.Fatal(err)
			}
			permission, err := client.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: url.ID}, Source: source})
			if err != nil || permission.VisitorToken == "" {
				t.Fatal("explicit application visit exchange failed without a personal session", err)
			}
			source, err = json.Marshal(controlv1.VisitorTokenApplicationSource{Kind: controlv1.VisitorTokenApplication, Credential: "pta_" + strings.Repeat("A", 43)})
			if err != nil {
				t.Fatal(err)
			}
			_, err = owner.IssueVisitorToken(t.Context(), controlv1.VisitorTokenRequest{Resource: controlv1.VisitorResourceScope{Kind: "public_url", Id: url.ID}, Source: source})
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.ServerDenied {
				t.Fatal("invalid application source fell back to the owner's session", err)
			}
			if _, err := client.PublisherPublicURL(t.Context(), access); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
				t.Fatal("visit capability authorized the publisher API", err)
			}
			visitor, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken(access))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := visitor.RegisterApplication(t.Context(), "forbidden", body); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
				t.Fatal("application visit access became management authority", err)
			}
		} else if grant.Operation == controlv1.ApplicationPublish {
			read, err := client.PublisherPublicURL(t.Context(), access)
			if err != nil || read.Id != url.ID {
				t.Fatal("explicit publish grant lost its resource", err)
			}
		}
	}
	listed, err := owner.ListPublisherIdentities(t.Context(), member.TeamID, "")
	if err != nil || len(listed.Identities) != 1 || len(listed.Identities[0].Grants) != 3 || listed.Identities[0].Kind != "application" {
		t.Fatal("identity inventory lost application operations", err)
	}
}
