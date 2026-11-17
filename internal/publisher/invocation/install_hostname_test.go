package invocation

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/setup"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestInstallHTTPNormalizesExactPublicURLBeforeReservation(t *testing.T) {
	for _, address := range []string{
		"install.member.example", "https://install.member.example",
		"http://install.member.example", "https://install.member.example/",
		"https://install.member.example:443", "https://install.member.example/path",
		"https://install.member.example?query", "https://install.member.example#fragment",
	} {
		t.Run(address, func(t *testing.T) {
			f := newServiceSetupFixture(t, "install.member.example")
			local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
			defer local.Close()
			posts, identities, teams, domains := 0, 0, 0, 0
			domain := *f.saved.DomainId
			f.services.authenticated.Discovery.ManagedUrlMode = "generated"
			f.before = func(r *http.Request) (*http.Response, bool) {
				switch r.Method + " " + r.URL.Path {
				case "GET /v1/identity":
					identities++
					return serviceTestResponse(r, 200, authorityv1.IdentityContext{PersonalTeamId: f.saved.TeamId, Memberships: []authorityv1.Membership{{TeamId: f.saved.TeamId, Role: "owner", MemberSlug: "member", ManagedLabel: "member"}}}), true
				case "GET /v1/teams/" + f.saved.TeamId:
					teams++
					return serviceTestResponse(r, 200, authorityv1.Team{Id: f.saved.TeamId, DefaultDomainId: domain}), true
				case "GET /v1/teams/" + f.saved.TeamId + "/domains":
					domains++
					return serviceTestResponse(r, 200, authorityv1.DomainPage{Domains: []authorityv1.Domain{{Id: domain, CanonicalDomain: "example", Kind: authorityv1.Managed, State: authorityv1.DomainStateReady}}}), true
				case "POST /v1/services":
					posts++
					var body controlv1.CreateServiceRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					if body.Placement == nil || body.Placement.Hostname == nil || *body.Placement.Hostname != "install.member.example" {
						t.Error("reservation did not receive the normalized hostname", body.Placement)
					}
					// stop before enrollment, supervisor operations, or sudo.
					return serviceTestResponse(r, 400, controlv1.Problem{Code: controlv1.InvalidRequest, Status: 400}), true
				}
				return nil, false
			}
			flags := InstallationOptions{PublicOptions: PublicOptions{
				Target: local.URL, PublicURL: address, SelectedTeam: f.saved.TeamId, ServerURL: f.services.authenticated.ServerEndpoint, StateDir: filepath.Join(t.TempDir(), "client"),
				Authenticate: func(context.Context, *clientstate.Database, string, string) (*auth.Client, error) {
					return f.services.authenticated, nil
				},
			}}
			err := InstallHTTP(t.Context(), flags, setup.Presentation{})
			if identities != 1 || teams != 1 || domains != 1 {
				t.Fatal("fixture did not complete authenticated environment selection", err)
			}
			valid := address == "install.member.example" || address == "https://install.member.example"
			var problem *clientcontrol.ProblemError
			if valid {
				if posts != 1 || !errors.As(err, &problem) {
					t.Fatal("valid address did not reach the deliberate reservation stop", posts, err)
				}
			} else if posts != 0 || err == nil {
				t.Fatal("invalid exact public URL reached reservation", posts, err)
			} else if reason, _ := failure.ReasonOf(err); reason != failure.InvalidTunnelFlags {
				t.Fatal("invalid exact public URL lost its flag diagnostic", reason, err)
			}
		})
	}
}
