package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestPublisherListKeepsGrantsWithTheirPublisherIDs(t *testing.T) {
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	identities := []controlv1.PublisherIdentity{
		{Name: "worker", Id: "pub_a", Grants: []controlv1.PublisherGrant{{Id: "grant_a", Namespace: new("dev.example"), ExpiresAt: &now}}},
		{Name: "worker", Id: "pub_b", RevokedAt: &now, Grants: []controlv1.PublisherGrant{{Id: "grant_b", ServiceId: new("svc_db")}}},
	}
	var out bytes.Buffer
	if err := writeResult(&out, publisherListTables(identities, now)...); err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	for _, line := range strings.Split(out.String(), "\n") {
		rows[strings.Join(strings.Fields(line), " ")] = true
	}
	for _, want := range []string{"worker enrolled pub_a", "worker revoked pub_b", "pub_a grant_a dev.example expired", "pub_b grant_b svc_db publisher revoked"} {
		if !rows[want] {
			t.Fatalf("missing row %q in:\n%s", want, &out)
		}
	}
}

func TestPortablePublisherCommandFlags(t *testing.T) {
	for _, tc := range []struct {
		args    []string
		command string
	}{
		{[]string{"publisher", "setup", "--namespace"}, "publisher setup"},
		{[]string{"publisher", "setup", "--url", "https://app.example.test"}, "publisher setup"},
		{[]string{"publisher", "provision", "--namespace", "--output-file", "/tmp/publisher.json"}, "publisher provision"},
		{[]string{"publisher", "provision", "--url", "https://app.example.test", "--output-file", "/tmp/publisher.json"}, "publisher provision"},
		{[]string{"publisher", "grant", "add", "pub_0123456789abcdefghijkl", "--url", "https://app.example.test"}, "publisher grant add <publisher-identity-id>"},
		{[]string{"publish", "3000", "--publisher-credential-file", "/tmp/publisher.json"}, "publish <service-or-target>"},
	} {
		var flags cli
		parser := commandForTest(&flags, io.Discard)
		parsed, err := parser(tc.args)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if command := commandID(parsed); command != tc.command {
			t.Fatalf("%v: command %s, want %s", tc.args, command, tc.command)
		}
		if tc.command == "publish <service-or-target>" && flags.Publish.PublisherCredentialFile != "/tmp/publisher.json" {
			t.Fatal("file flag was lost")
		}
	}
}

func TestPublisherGrantRejectsRetiredPublicURLIDFlag(t *testing.T) {
	var flags cli
	parser := commandForTest(&flags, io.Discard)
	if _, err := parser([]string{"publisher", "grant", "add", "pub_0123456789abcdefghijkl", "--public-url-id", "url_0123456789abcdefghijkl"}); err == nil {
		t.Fatal("retired public URL grant option was accepted")
	}
}

func TestPublisherAddressSelectsExactManagedServiceWithoutVisitorAuthority(t *testing.T) {
	const team = "tm_0123456789abcdefghijkl"
	const id = "svc_0123456789abcdefghijkl"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer manager" {
			t.Error("publisher enrollment scope did not use the control session")
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.Method + " " + r.URL.Path {
		case "GET /v1/teams/" + team:
			_ = json.NewEncoder(w).Encode(authorityv1.Team{Id: team})
		case "GET /v1/services":
			if r.URL.Query().Get("team_id") != team {
				t.Error("address selection lost its team")
			}
			_ = json.NewEncoder(w).Encode(controlv1.ServicePage{Services: []controlv1.ServiceSummary{
				{Id: id, TeamId: team, Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, Endpoint: &controlv1.ServiceEndpoint{Hostname: "app.example.test", Port: 443, Public: true}},
			}})
		case "GET /v1/services/" + id:
			_ = json.NewEncoder(w).Encode(controlv1.Service{Id: id, TeamId: team, Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1})
		default:
			t.Errorf("publisher selection used visitor or retired URL authority: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()
	control, err := clientcontrol.New(server.URL, server.Client(), credentials.AccessToken("manager"))
	if err != nil {
		t.Fatal(err)
	}
	authority, err := clientauthority.New(server.URL, server.Client(), credentials.AccessToken("manager"))
	if err != nil {
		t.Fatal(err)
	}
	session := clientteam.NewSession(nil, nil, &auth.Client{Control: control, Authority: authority},
		authorityv1.IdentityContext{Memberships: []authorityv1.Membership{{TeamId: team}}}, clientteam.Options{SelectedTeam: team})
	current, err := session.Current(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, selector := range []string{id, "app.example.test", "https://app.example.test"} {
		service, domain, err := publisherCLIGrantScope(t.Context(), session, current, selector, "", false, "")
		if err != nil || service == nil || *service != id || domain != nil {
			t.Fatalf("publisher address %q did not resolve one service: %v", selector, err)
		}
	}
	for _, selector := range []string{"url_0123456789abcdefghijkl", "https://app.example.test/path"} {
		if _, _, err := publisherCLIGrantScope(t.Context(), session, current, selector, "", false, ""); err == nil {
			t.Fatalf("retired or invalid selector %q was accepted", selector)
		}
	}
	if _, _, err := publisherCLIGrantScope(t.Context(), session, current, id, id, false, ""); err == nil {
		t.Fatal("two exact selectors were accepted")
	}
}

func TestPublisherProvisionRejectsServiceWithoutDeploymentBeforeState(t *testing.T) {
	for _, scope := range [][]string{
		nil, {"--namespace"}, {"--url", "url_selected"}, {"--service-id", "svc_selected"}, {"--domain", "example.test"},
	} {
		t.Run(strings.Join(scope, " "), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusInternalServerError)
			}))
			defer server.Close()
			root := t.TempDir()
			state, file := filepath.Join(root, "state"), filepath.Join(root, "publisher.json")
			args := []string{"--no-config", "publisher", "provision", "--service", "db", "--service", "api", "--output-file", file, "--state-dir", state, "--server", server.URL}
			args = append(args, scope...)
			var output, diagnostics bytes.Buffer
			err := run(t.Context(), args, &output, &diagnostics)
			if reason, ok := failure.ReasonOf(err); !ok || reason != failure.InvalidTunnelFlags || !strings.Contains(err.Error(), "--service requires --deployment") {
				t.Fatal("service selection reached standalone provisioning", err)
			}
			if requests != 0 || output.Len() != 0 || diagnostics.Len() != 0 {
				t.Fatal("invalid selection reached authentication or control")
			}
			for _, path := range []string{state, file} {
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("invalid selection opened state or wrote a credential", err)
				}
			}
		})
	}
}
