package invocation

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/client/project/resolve"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestForegroundIntegrationsRetainAuthenticatedSelection(t *testing.T) {
	for _, scenario := range []string{"no_oauth_control", "generated_without_dns_automation", "environment_token_explicit_server", "flag_token_no_saved_session", "team_override", "conflicting_environment", "shutdown_failure", "shutdown_cancellation"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("TNL_ACCESS_TOKEN", "")
			t.Setenv("TNL_SERVER", "")
			f := newForegroundFixture(t)
			if scenario == "generated_without_dns_automation" {
				f.saved.Endpoint.Hostname, f.services.hostname = "app.member.quiet-heron.example", "app.member.quiet-heron.example"
			}
			f.saved.EndpointRevision = 1
			shutdown := scenario == "shutdown_failure" || scenario == "shutdown_cancellation"
			shutdownProblem := errors.New("integration shutdown request failed")
			integrationEntered := make(chan struct{})
			markIntegrationEntered := sync.OnceFunc(func() { close(integrationEntered) })
			var oauthHostname string
			before := f.before
			f.before = func(r *http.Request) (*http.Response, bool) {
				if r.Method == http.MethodPost && r.URL.Path == "/v1/services/"+f.saved.Id+"/runs" {
					if r.Header.Get("Authorization") != "Bearer service-access" {
						t.Error("run preparation lost exact signed publisher authority")
					}
					f.runs++
					if shutdown {
						select {
						case <-integrationEntered:
						case <-r.Context().Done():
							t.Error("integration worker did not enter preparation before parent publication")
						}
					}
					// stop at the run boundary: attachment requires no relay or
					// certificate topology to prove credential/team propagation.
					return serviceTestResponse(r, 400, controlv1.Problem{Code: "invalid_request", Status: 400, Detail: "selected foreground run reached"}), true
				}
				return before(r)
			}
			// foreground publication reopens state using normal platform protection.
			database, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "state"))
			if err != nil {
				t.Fatal(err)
			}
			defer database.Close()
			store, err := database.Server(t.Context(), f.services.authenticated.ServerEndpoint)
			if err != nil {
				t.Fatal(err)
			}
			f.state, f.services.state = database, store
			access, _, _, err := credentials.NewAccessToken()
			if err != nil {
				t.Fatal(err)
			}
			secret := access.String()
			selectedTeam, otherTeam := f.saved.TeamId, serviceTestID(t, opaqueid.TeamPrefix)
			domain := authorityv1.Domain{Id: *f.saved.DomainId, CanonicalDomain: "example", Kind: "managed", State: "ready"}
			person := serviceTestID(t, opaqueid.IdentityPrefix)
			identity := authorityv1.IdentityContext{Identity: authorityv1.Identity{Id: person}, PersonalTeamId: otherTeam,
				Memberships: []authorityv1.Membership{
					{Id: serviceTestID(t, opaqueid.MembershipPrefix), IdentityId: person, TeamId: selectedTeam, TeamKind: "organization", TeamDisplayName: "selected", Role: "owner", ManagedLabel: "member", MemberSlug: "member", Active: new(true), PolicyRevision: 1},
					{Id: serviceTestID(t, opaqueid.MembershipPrefix), IdentityId: person, TeamId: otherTeam, TeamKind: "personal", TeamDisplayName: "other", Role: "owner", ManagedLabel: "other", MemberSlug: "other", Active: new(true), PolicyRevision: 1},
				}}
			discovery := controlv1.ControlDiscovery{ManagedDomain: "example", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{controlv1.Oidc},
					Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example", LoginFlow: controlv1.DeviceCode}}}
			var teamReads []string
			identities, originalAuth, serviceReads := 0, 0, 0
			transport := serviceSetupTransport(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == "GET" && (r.URL.Path == "/v1/discovery" || r.URL.Path == "/.well-known/tnl"):
					return serviceTestResponse(r, 200, discovery), nil
				case r.Method == "GET" && r.URL.Path == "/v1/identity":
					if r.Header.Get("Authorization") != "Bearer "+secret {
						t.Error("identity request lost selected foreground credential")
					}
					identities++
					return serviceTestResponse(r, 200, identity), nil
				case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/v1/teams/"):
					parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v1/teams/"), "/")
					id := parts[0]
					if r.Header.Get("Authorization") != "Bearer "+secret {
						t.Error("team selection lost selected foreground credential")
					}
					if len(parts) > 1 && parts[1] == "domains" {
						return serviceTestResponse(r, 200, authorityv1.DomainPage{Domains: []authorityv1.Domain{domain}}), nil
					}
					teamReads = append(teamReads, id)
					return serviceTestResponse(r, 200, authorityv1.Team{Id: id, DisplayName: "selected",
						Kind: authorityv1.Organization, ManagedLabel: "quiet-heron", DefaultDomainId: domain.Id, PolicyRevision: 1}), nil
				}
				if shutdown && r.Method == http.MethodPost && r.URL.Path == "/v1/services" {
					data, err := io.ReadAll(r.Body)
					if err != nil {
						return nil, err
					}
					var body controlv1.CreateServiceRequest
					if err := json.Unmarshal(data, &body); err != nil {
						return nil, err
					}
					if body.Placement != nil && body.Placement.Hostname != nil && *body.Placement.Hostname == oauthHostname {
						markIntegrationEntered()
						<-r.Context().Done()
						if scenario == "shutdown_failure" {
							return nil, errors.Join(r.Context().Err(), shutdownProblem)
						}
						return nil, r.Context().Err()
					}
					r.Body = io.NopCloser(bytes.NewReader(data))
				}
				copy := r.Clone(r.Context())
				if copy.Header.Get("Authorization") == "Bearer "+secret {
					originalAuth++
					copy.Header.Set("Authorization", "Bearer session")
				}
				// the shared fixture verifies real enrollment and signed assertions.
				// these proof exchanges do not use the optional management bearer.
				if copy.URL.Path == "/v1/publisher-enrollments/redeem" || copy.URL.Path == "/v1/publisher-token" {
					copy.Header.Del("Authorization")
				}
				if copy.URL.Path == "/v1/publisher/services/"+f.saved.Id {
					serviceReads++
				}
				return f.serve(copy)
			})
			previous := http.DefaultTransport
			http.DefaultTransport = transport
			defer func() { http.DefaultTransport = previous }()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
			defer target.Close()
			project := clientproject.Project{Root: t.TempDir(), Config: config.TNL{OAuth: scenario != "no_oauth_control"}}
			project.Worktree, err = clientproject.ResolveWorktree(t.Context(), project.Root)
			if err != nil {
				t.Fatal(err)
			}
			project.Root = project.Worktree.Root
			if scenario == "team_override" {
				project.Config.Team = &otherTeam
				refresh, _, _, err := credentials.NewRefreshToken()
				if err != nil {
					t.Fatal(err)
				}
				if err := store.SaveControlSession(t.Context(), clientstate.ControlSession{SessionID: serviceTestID(t, opaqueid.ControlSessionPrefix),
					AccessToken: secret, RefreshToken: refresh.String(), AccessExpiresAt: time.Now().Add(time.Hour), RefreshExpiresAt: time.Now().Add(24 * time.Hour)}); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "environment_token_explicit_server" {
				t.Setenv("TNL_ACCESS_TOKEN", secret)
			}
			if scenario == "conflicting_environment" {
				t.Setenv("TNL_ACCESS_TOKEN", "another-credential")
				t.Setenv("TNL_SERVER", "https://other.example")
			}
			origin, err := resolve.IntegrationOrigin(t.Context(), database, project, f.services.authenticated.ServerEndpoint, "member.quiet-heron.example", "oauth")
			if err != nil {
				t.Fatal(err)
			}
			oauthHostname = origin.Hostname
			// another elected local publisher already owns the callback service.
			// attachment still resolves the original scope but starts no remote work.
			if !shutdown {
				lock, err := store.LockHostname("companion:" + origin.Hostname)
				if err != nil {
					t.Fatal(err)
				}
				defer lock.Close()
			}
			var original *auth.Client
			flags := PublicOptions{Target: target.URL, StateDir: database.Root(), ServerURL: f.services.authenticated.ServerEndpoint,
				AccessToken: secret, SelectedTeam: selectedTeam, PublicURL: "https://" + f.saved.Endpoint.Hostname, Project: project, ProjectRoot: project.Root,
				Authenticate: func(ctx context.Context, state *clientstate.Database, server, token string) (*auth.Client, error) {
					if token != secret {
						t.Fatal("foreground entry omitted its explicit credential")
					}
					var err error
					original, err = auth.Authenticate(ctx, auth.Config{ServerEndpoint: server, State: state, AccessToken: token, HTTPClient: &http.Client{Transport: transport}})
					return original, err
				}}
			if scenario == "generated_without_dns_automation" {
				flags.PublicURL, flags.FallbackName = "", "app"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
			defer cancel()
			err = PublishHTTP(ctx, flags, &Presentation{})
			if original == nil || f.creates != 1 || f.enrollments != 1 || f.redemptions != 1 || originalAuth == 0 {
				t.Fatal("did not traverse foreground authentication and signed service setup", err, f.creates, f.enrollments, f.redemptions, originalAuth)
			}
			if err == nil || f.runs != 1 {
				t.Fatal("foreground integrations did not reach signed run preparation", err, f.runs)
			}
			if scenario == "shutdown_failure" && !errors.Is(err, shutdownProblem) {
				t.Fatal("enclosing foreground publication lost its integration shutdown failure", err)
			}
			if scenario == "shutdown_cancellation" && errors.Is(err, context.Canceled) {
				t.Fatal("expected integration cancellation contaminated the enclosing result", err)
			}
			wantReads := 1
			if project.Config.OAuth {
				wantReads = 3
				if serviceReads == 0 {
					t.Fatal("integration attachment skipped exact publisher service validation")
				}
			}
			if identities != wantReads || len(teamReads) != wantReads {
				t.Fatal("unexpected authentication or team selection", identities, teamReads)
			}
			for _, team := range teamReads {
				if team != selectedTeam {
					t.Fatal("integration replaced the selected foreground team", teamReads)
				}
			}
		})
	}
}
