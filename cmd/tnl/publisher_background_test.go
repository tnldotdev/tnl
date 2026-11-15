package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	clientteam "github.com/tnldotdev/tnl/internal/client/team"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
	publisheridentity "github.com/tnldotdev/tnl/internal/publisher/identity"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	"github.com/tnldotdev/tnl/internal/publisher/invocation"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type backgroundAuthority struct {
	identity    authorityv1.PublisherEnrollmentResult
	public      ed25519.PublicKey
	redemptions int
}

const backgroundTeamID = "tm_0123456789abcdefghijkl"

func (a *backgroundAuthority) RedeemPublisherEnrollment(_ context.Context, _ string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	a.redemptions++
	a.public = append(ed25519.PublicKey(nil), public...)
	return a.identity, nil
}
func (a *backgroundAuthority) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != a.identity.ClientId || grant != a.identity.GrantId || key != a.identity.KeyId || !private.Public().(ed25519.PublicKey).Equal(a.public) {
		return "", publisheridentity.ErrScope
	}
	return "access-secret", nil
}

type backgroundControl struct {
	publisheridentity.ServiceControl
	service controlv1.Service
	server  string
}

func (c *backgroundControl) ControlURL() string {
	if c.server != "" {
		return c.server
	}
	return "https://control.example"
}

func backgroundClients(c *backgroundControl) installedjobs.PublisherClients {
	return installedjobs.PublisherClients{NativeControl: publisheridentity.NativeControl{Services: c}}
}

func (c *backgroundControl) GetPublisherService(_ context.Context, id, access string) (controlv1.Service, error) {
	if id != c.service.Id || access != "access-secret" {
		return controlv1.Service{}, publisheridentity.ErrScope
	}
	return c.service, nil
}

func backgroundFixture(t *testing.T) (*installedjobs.Registry, *backgroundAuthority, *backgroundControl, enrolledPublishSelection) {
	t.Helper()
	owner := os.Geteuid()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := installedjobs.Open(t.Context(), installedjobs.OpenOptions{Root: filepath.Join(parent, "system"), TestOwnerUID: &owner})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	id := func(prefix string) string {
		result, err := opaqueid.New(prefix)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	service := id(opaqueid.ServicePrefix)
	a := &backgroundAuthority{identity: authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), TeamId: backgroundTeamID, Kind: "service", ServiceId: &service}}
	c := &backgroundControl{service: controlv1.Service{Id: service, TeamId: backgroundTeamID, Name: "web", Enabled: true, Protocol: controlv1.ServiceProtocolHTTP, TrustRevision: 1,
		Endpoint: &controlv1.ServiceEndpoint{Hostname: "web.example", Port: 443, Public: true}}}
	return r, a, c, enrolledPublishSelection{EnrollmentKey: id(opaqueid.PublisherEnrollmentPrefix) + ".enrollment-secret"}
}

func TestBackgroundInstallsEnrolledHTTPJobWithLocalTarget(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	flags := publishCommand{Target: target.URL}
	flags.ServerURL = "https://control.example"
	bg := backgroundPublishFlags{Install: true, ServiceName: "database"}
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(c), a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, bg, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("installed jobs: %+v, %v", jobs, err)
	}
	job := jobs[0]
	if job.ID != installedjobs.ServiceJobKey(flags.ServerURL, c.service.Id) || job.Name != "database" || job.Protocol != config.ProtocolHTTP || job.Target != flags.Target || job.Trust != nil || job.PublisherIdentityID != a.identity.ClientId {
		t.Fatalf("private target settings: %+v", job)
	}
	if a.redemptions != 1 {
		t.Fatal("enrollment was not redeemed once")
	}
	if err := r.Stop(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	if err := r.Start(t.Context(), job.ID); err != nil {
		t.Fatal(err)
	}
	profile, err := r.Profile(t.Context(), flags.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := profile.PublisherIdentity(t.Context(), a.identity.ClientId); err != nil || !found {
		t.Fatalf("stop revoked/removed identity: %v", err)
	}
}

func TestAppWorkflowInstallLoadsExplicitPublisherFromClientState(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	state, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "operator"))
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	profile, err := state.Server(t.Context(), "https://control.example")
	if err != nil {
		t.Fatal(err)
	}
	_, identity, err := publisheridentity.EnrollNative(t.Context(), profile, publisheridentity.NativeControl{Services: c}, a, selection.EnrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	flags := publishCommand{Target: target.URL, remoteFlags: remoteFlags{ServerURL: "https://control.example", StateDir: state.Root()}}
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(c), a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, enrolledPublishSelection{PublisherIdentityID: identity.ClientId}, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal("explicit publisher was looked up in staging instead of client state", err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].PublisherIdentityID != identity.ClientId || a.redemptions != 1 {
		t.Fatalf("installed wrong identity: %+v %v", jobs, err)
	}
	credential, err := r.Credential(t.Context(), jobs[0])
	if err != nil || credential.PublisherIdentityID != identity.ClientId {
		t.Fatal("exact credential was not imported", err)
	}
}

func TestBackgroundImportsPortableFileWithoutRedeemingEnrollment(t *testing.T) {
	r, a, c, _ := backgroundFixture(t)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a.public = private.Public().(ed25519.PublicKey)
	f, err := credentialfile.New("https://control.example", a.identity, private)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "publisher.json")
	if err := credentialfile.Write(path, f); err != nil {
		t.Fatal(err)
	}
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer target.Close()
	flags := publishCommand{Target: target.URL}
	flags.ServerURL = f.ControlURL
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(c), a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, enrolledPublishSelection{PublisherCredentialFile: path}, backgroundPublishFlags{Install: true, ServiceName: "database"}, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].PublisherIdentityID != a.identity.ClientId || a.redemptions != 0 {
		t.Fatalf("import did not reuse the saved identity: jobs=%v, redemptions=%d, err=%v", jobs, a.redemptions, err)
	}
}

func TestBackgroundRejectsNamespaceEphemeralAndImplicitServer(t *testing.T) {
	for _, kind := range []string{"namespace", "ephemeral", "implicit server", "policy", "open"} {
		t.Run(kind, func(t *testing.T) {
			r, a, c, selection := backgroundFixture(t)
			flags := publishCommand{Target: "3000"}
			flags.ServerURL = "https://control.example"
			switch kind {
			case "namespace":
				a.identity.Kind, a.identity.ServiceId = "namespace", nil
				namespace, domain := "member.example", func() string { v, _ := opaqueid.New(opaqueid.DomainPrefix); return v }()
				a.identity.Namespace, a.identity.DomainId = &namespace, &domain
			case "ephemeral":
				c.service.Ephemeral = true
			case "implicit server":
				flags.ServerURL = ""
			case "policy":
				flags.Anonymous = true
			case "open":
				flags.Open = true
			}
			clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
				return backgroundClients(c), a, nil
			}
			err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true, ServiceName: "one"}, strings.NewReader(""), clients, nil)
			if err == nil {
				t.Fatal("invalid background scope installed")
			}
			jobs, err := r.List(t.Context())
			if err != nil || len(jobs) != 0 {
				t.Fatalf("partial job installed: %+v, %v", jobs, err)
			}
		})
	}
}

func TestInstallPreflightLeavesEnrollmentAndStateUntouched(t *testing.T) {
	selection := enrolledPublishSelection{EnrollmentKey: "pen_0123456789abcdefghijkl.enrollment-secret"}
	requests := make(chan string, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case requests <- r.Method + " " + r.URL.Path:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = io.WriteString(w, `{"code":"unavailable","detail":"target preflight must run first"}`)
	}))
	defer server.Close()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root, clientRoot := filepath.Join(parent, "not-installed"), filepath.Join(parent, "no-client-state")
	ca := filepath.Join(parent, "control.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	flags := publishCommand{Target: unavailableInstalledTarget(t), Protocol: "http", TargetTLS: new(true),
		remoteFlags: remoteFlags{ServerURL: server.URL, StateDir: clientRoot}}
	err = runEnrolledBackgroundPublish(t.Context(), flags, selection, backgroundPublishFlags{Install: true, SystemStateDir: root, ServerCAFile: ca}, io.Discard, strings.NewReader(""), installedjobs.ExecutorFunc(func(context.Context, installedjobs.Command) error {
		t.Fatal("missing service reached the manager")
		return nil
	}))
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.TargetUnavailable {
		t.Errorf("unavailable target used the wrong failure reason: %v", err)
	}
	select {
	case request := <-requests:
		t.Errorf("unavailable target contacted control before preflight: %s", request)
	default:
	}
	for _, path := range []string{clientRoot, root} {
		if _, statErr := os.Lstat(path); !errors.Is(statErr, os.ErrNotExist) {
			t.Errorf("preflight created state at %s: %v", path, statErr)
		}
	}
}

func configuredInstallFixture(t *testing.T) (projectConfiguration, publishCommand) {
	t.Helper()
	access, _, _, err := credentials.NewAccessToken()
	if err != nil {
		t.Fatal(err)
	}
	current := configuredInstallTeam()
	authority := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/discovery" && r.Header.Get("Authorization") != "Bearer "+access.String() {
			t.Error("configured selection lost its actual operator authentication")
		}
		switch r.URL.Path {
		case "/v1/discovery":
			_ = json.NewEncoder(w).Encode(controlv1.ControlDiscovery{ManagedDomain: "example", ManagedUrlMode: "generated",
				Authentication: controlv1.AuthenticationFacts{Methods: []controlv1.AuthenticationFactsMethods{"oidc"}, Oidc: &controlv1.OIDCAuthenticationFacts{Issuer: "https://identity.example.test", LoginFlow: "device_code"}}})
		case "/v1/identity":
			_ = json.NewEncoder(w).Encode(authorityv1.IdentityContext{PersonalTeamId: backgroundTeamID,
				Memberships: []authorityv1.Membership{current.Membership()}})
		case "/v1/teams/" + backgroundTeamID:
			_ = json.NewEncoder(w).Encode(current.Team())
		case "/v1/teams/" + backgroundTeamID + "/domains":
			_ = json.NewEncoder(w).Encode(authorityv1.DomainPage{Domains: current.Domains()})
		default:
			t.Errorf("configured selection mutated or used another authority: %s %s", r.Method, r.URL)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(authority.Close)
	original := http.DefaultTransport
	http.DefaultTransport = authority.Client().Transport
	t.Cleanup(func() { http.DefaultTransport = original })
	t.Setenv("TNL_SERVER", authority.URL)
	t.Setenv("TNL_ACCESS_TOKEN", access.String())
	listener := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(listener.Close)
	server, target, name, hostname := authority.URL, config.Target(listener.URL), "orders", "orders.example"
	protocol := "http"
	root := t.TempDir()
	project := projectConfiguration{Project: clientproject.Project{Root: root, Worktree: namedTestWorktree(root, "shop"), Config: config.TNL{
		Server: &server, Services: config.Services{
			"orders": {Protocol: &protocol, Public: new(true), Hostname: &hostname, Target: &config.ServiceTarget{Type: "address", Address: &target}, HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}}},
			"api":    {Target: &config.ServiceTarget{Type: "app"}},
		},
	}}}
	flags := publishCommand{Target: name, remoteFlags: remoteFlags{StateDir: filepath.Join(t.TempDir(), "operator")}}
	if err := project.applyInstalledService(&flags); err != nil {
		t.Fatal(err)
	}
	return project, flags
}

func configuredInstallTeam() clientteam.Context {
	return clientteam.NewContext(
		authorityv1.Team{Id: backgroundTeamID, DisplayName: "install-team", DefaultDomainId: "dom_0123456789abcdefghijkl"},
		authorityv1.Membership{TeamId: backgroundTeamID, Role: "owner", ManagedLabel: "member", MemberSlug: "member"},
		[]authorityv1.Domain{{Id: "dom_0123456789abcdefghijkl", CanonicalDomain: "example", Kind: "custom", State: "ready"}}, "",
	)
}

func backgroundScopeService(scope invocation.InstallScope, id string) controlv1.Service {
	return controlv1.Service{Id: id, TeamId: scope.TeamID, DomainId: &scope.DomainID, Name: scope.Service, Enabled: true, Protocol: controlv1.ServiceProtocol(scope.Protocol), TrustRevision: 1,
		Source:   &controlv1.LocalServiceSource{ProjectKey: scope.ProjectKey, SourceFingerprint: scope.SourceFingerprint, WorktreeKey: scope.WorktreeKey, Service: scope.Service},
		Endpoint: &controlv1.ServiceEndpoint{Hostname: scope.Hostname, Port: 443, Public: true}}
}

func bindConfiguredBackgroundService(t *testing.T, c *backgroundControl, flags publishCommand) invocation.InstallScope {
	t.Helper()
	scope, err := invocation.ConfiguredInstallScopeForTeam(flags.project.Project, flags.Service, invocation.FromTeamContext(configuredInstallTeam()))
	if err != nil {
		t.Fatal(err)
	}
	c.service, c.server = backgroundScopeService(scope, c.service.Id), flags.ServerURL
	return scope
}

func TestConfiguredInstallUsesOnlySelectedStableService(t *testing.T) {
	project, flags := configuredInstallFixture(t)
	if flags.Service != "orders" || flags.ServiceName != "orders" || flags.ServerURL != *project.Config.Server || flags.Target != string(*project.Config.Services["orders"].Target.Address) || flags.Protocol != "http" || flags.projectRoot != project.Root {
		t.Fatalf("wrong configured service: %+v", flags)
	}
	scope, err := invocation.ResolveConfiguredInstallScope(t.Context(), backgroundOptions(flags), nil)
	if err != nil || scope.Hostname != "orders.example" || scope.TeamID != backgroundTeamID || scope.DomainID != configuredInstallTeam().Team().DefaultDomainId {
		t.Fatalf("configured service did not bind its exact hostname, team, and domain: %+v %v", scope, err)
	}
	serviceID := "svc_0123456789abcdefghijkl"
	identity := authorityv1.PublisherEnrollmentResult{TeamId: scope.TeamID, Kind: authorityv1.Service, ServiceId: &serviceID}
	for _, hostname := range []string{"orders.other-team.example", "orders.other-domain.example", "orders.example.other-checkout"} {
		other := backgroundScopeService(scope, serviceID)
		other.Endpoint.Hostname = hostname
		if scope.Matches(other, identity) {
			t.Fatalf("same prefix on a different endpoint was selected: %s", hostname)
		}
	}
	if !scope.Matches(backgroundScopeService(scope, serviceID), identity) {
		t.Fatal("configured service did not match its exact saved grant")
	}
	staleID := "svc_abcdefghijkl0123456789"
	identity.ServiceId = &staleID
	if scope.Matches(backgroundScopeService(scope, serviceID), identity) {
		t.Fatal("mismatched grant selected the configured service")
	}
	renamed := publishCommand{Target: "orders", backgroundPublishFlags: backgroundPublishFlags{ServiceName: "different"}}
	if err := project.applyInstalledService(&renamed); err == nil {
		t.Fatal("configured service name could be hidden behind a different CLI name")
	}
	missing := publishCommand{Target: "api"}
	if err := project.applyInstalledService(&missing); err == nil {
		t.Fatal("app-reported target was silently installed without a stable address")
	} else if reason, ok := failure.Of(err); !ok || reason.Reason() != failure.InstalledTargetMissing {
		t.Fatalf("app-reported target has no authored fixed-target diagnostic: %v", err)
	}
	err = backgroundSelection(flags, enrolledPublishSelection{}, backgroundPublishFlags{System: true})
	if reason, ok := failure.Of(err); !ok || reason.Reason() != failure.InstalledPublisherSelectionMissing {
		t.Fatalf("system install fell back to a user project grant: %v", err)
	}
}

func TestConfiguredInstallPersistsReadinessWithExactGrant(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	bindConfiguredBackgroundService(t, c, flags)
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(c), a, nil
	}
	var id string
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{ServiceName: flags.ServiceName, System: true}, strings.NewReader(""), clients, &id); err != nil {
		t.Fatal(err)
	}
	job, err := r.ResolveJob(t.Context(), id)
	if err != nil || job.ReadinessPath != "/health" || job.PublisherIdentityID != a.identity.ClientId || job.GrantID != a.identity.GrantId || job.Revision != 1 {
		t.Fatal("configured readiness or exact grant was lost", err)
	}
	service := flags.project.Config.Services[flags.Service]
	service.HTTP = &config.HTTPService{Readiness: &config.Readiness{Path: "/ready"}}
	flags.project.Config.Services[flags.Service] = service
	selection = enrolledPublishSelection{PublisherIdentityID: job.PublisherIdentityID}
	staged, err := r.Profile(t.Context(), flags.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	identity, private, err := invocation.SigningIdentity(t.Context(), staged, job.PublisherIdentityID)
	if err != nil {
		t.Fatal(err)
	}
	operator, err := clientstate.Open(t.Context(), filepath.Join(t.TempDir(), "operator"))
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Close()
	flags.StateDir = operator.Root()
	profile, err := operator.Server(t.Context(), flags.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	document, err := json.Marshal(identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := profile.ImportPublisherIdentity(t.Context(), clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: document, SigningKey: private}); err != nil {
		t.Fatal(err)
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{ServiceName: flags.ServiceName, System: true}, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	updated, err := r.ResolveJob(t.Context(), id)
	if err != nil || updated.ReadinessPath != "/ready" || updated.Revision != job.Revision+1 || updated.GrantID != job.GrantID || a.redemptions != 1 {
		t.Fatal("readiness update lost its job revision or changed the grant", err)
	}
}

func TestConfiguredInstallSelectsSavedExactGrantWithoutEnrollment(t *testing.T) {
	r, a, c, _ := backgroundFixture(t)
	project, flags := configuredInstallFixture(t)
	profile, err := r.Profile(t.Context(), flags.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	scope := bindConfiguredBackgroundService(t, c, flags)
	store := func(identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) {
		document, err := json.Marshal(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := profile.ImportPublisherIdentity(t.Context(), clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: document, SigningKey: private}); err != nil {
			t.Fatal(err)
		}
		if err := profile.SelectPublisherIdentity(t.Context(), "project", "project-publisher:service:"+*identity.ServiceId, identity.ClientId); err != nil {
			t.Fatal(err)
		}
	}
	_, unrelatedKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := a.identity
	unrelated.ClientId, err = opaqueid.New(opaqueid.PublisherIdentityPrefix)
	if err != nil {
		t.Fatal(err)
	}
	unrelatedService, err := opaqueid.New(opaqueid.ServicePrefix)
	if err != nil {
		t.Fatal(err)
	}
	unrelated.ServiceId = &unrelatedService
	store(unrelated, unrelatedKey)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a.public = private.Public().(ed25519.PublicKey)
	store(a.identity, private)
	native, selected, key, savedService, err := invocation.SelectConfiguredPublisherCandidates(t.Context(), flags.ServerURL, profile, []string{unrelatedService, c.service.Id}, scope, publisheridentity.NativeControl{Services: c}, a)
	if err != nil || native == nil || selected.ClientId != a.identity.ClientId || savedService.Id != c.service.Id || !key.Public().(ed25519.PublicKey).Equal(a.public) || a.redemptions != 0 {
		t.Fatalf("selected wrong scoped grant or redeemed enrollment: %+v %v", selected, err)
	}
	if _, _, _, _, err := invocation.SelectConfiguredPublisherCandidates(t.Context(), flags.ServerURL, profile, []string{unrelatedService}, scope, publisheridentity.NativeControl{Services: c}, a); err == nil {
		t.Fatal("missing matching grant fell back to a different service")
	} else if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.InstalledPublisherSelectionMissing {
		t.Fatalf("missing selection has no authored next step: %v", err)
	}
	if !scope.Matches(savedService, selected) || project.Root != flags.projectRoot {
		t.Fatal("saved service does not match project")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("read-only grant selection installed a job: %+v %v", jobs, err)
	}
}

func TestConfiguredWorktreeSourceBindsTeamDomainAndGrant(t *testing.T) {
	root := t.TempDir()
	worktree := namedTestWorktree(root, "shop")
	protocol := "http"
	project := projectConfiguration{Project: clientproject.Project{Root: root, Worktree: worktree, Config: config.TNL{
		Services: config.Services{"orders": {Protocol: &protocol}},
	}}}
	current := clientteam.NewContext(
		authorityv1.Team{Id: "team_selected", DefaultDomainId: "domain_selected"},
		authorityv1.Membership{
			TeamId: "team_selected", Role: authorityv1.TeamRoleMember, ManagedLabel: "ecstatic-penguin", MemberSlug: "chase",
		},
		[]authorityv1.Domain{{Id: "domain_selected", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady}}, "",
	)
	scope, err := invocation.ConfiguredInstallScopeForTeam(project.Project, "orders", invocation.FromTeamContext(current))
	if err != nil {
		t.Fatal(err)
	}
	source := project.LocalPublicationIdentity()
	if scope.Hostname != "" || scope.TeamID != current.Team().Id || scope.DomainID != current.Domains()[0].Id ||
		scope.ProjectKey != source.Key || scope.SourceFingerprint != source.Fingerprint || scope.WorktreeKey != project.LocalWorktreeKey() {
		t.Fatalf("selection reconstructed an endpoint or lost its source binding: %+v", scope)
	}
	serviceID := "svc_0123456789abcdefghijkl"
	identity := authorityv1.PublisherEnrollmentResult{TeamId: current.Team().Id, Kind: authorityv1.Service, ServiceId: &serviceID}
	item := backgroundScopeService(scope, serviceID)
	item.Endpoint.Hostname = "assigned-by-control.ecstatic-penguin.tnl.dev"
	if !scope.Matches(item, identity) {
		t.Fatal("saved service with matching source, team, domain and grant was rejected")
	}
	for name, mutate := range map[string]func(*controlv1.Service, *authorityv1.PublisherEnrollmentResult){
		"other team": func(service *controlv1.Service, grant *authorityv1.PublisherEnrollmentResult) {
			service.TeamId, grant.TeamId = "team_other", "team_other"
		},
		"other domain": func(service *controlv1.Service, _ *authorityv1.PublisherEnrollmentResult) {
			service.DomainId = new("domain_other")
		},
		"old grant": func(_ *controlv1.Service, grant *authorityv1.PublisherEnrollmentResult) {
			grant.ServiceId = new("svc_abcdefghijkl0123456789")
		},
		"missing source": func(service *controlv1.Service, _ *authorityv1.PublisherEnrollmentResult) {
			service.Source = nil
		},
		"other project": func(service *controlv1.Service, _ *authorityv1.PublisherEnrollmentResult) {
			service.Source.ProjectKey += "-other"
		},
		"other fingerprint": func(service *controlv1.Service, _ *authorityv1.PublisherEnrollmentResult) {
			service.Source.SourceFingerprint = strings.Repeat("a", 64)
		},
		"other worktree": func(service *controlv1.Service, _ *authorityv1.PublisherEnrollmentResult) {
			service.Source.WorktreeKey = strings.Repeat("b", 64)
		},
		"other service": func(service *controlv1.Service, _ *authorityv1.PublisherEnrollmentResult) {
			service.Source.Service = "api"
		},
		"other protocol": func(service *controlv1.Service, _ *authorityv1.PublisherEnrollmentResult) {
			service.Protocol = controlv1.Tcp
		},
	} {
		t.Run(name, func(t *testing.T) {
			otherService, otherGrant := backgroundScopeService(scope, serviceID), identity
			otherService.Endpoint.Hostname = item.Endpoint.Hostname
			mutate(&otherService, &otherGrant)
			if scope.Matches(otherService, otherGrant) {
				t.Fatal("saved service outside selected source scope was accepted")
			}
		})
	}
	other := project
	other.Root = filepath.Join(root, "other-checkout")
	other.Worktree = namedTestWorktree(other.Root, "shop")
	otherScope, err := invocation.ConfiguredInstallScopeForTeam(other.Project, "orders", invocation.FromTeamContext(current))
	if err != nil || otherScope.WorktreeKey == scope.WorktreeKey || otherScope.Matches(item, identity) {
		t.Fatalf("another checkout selected this worktree's service: %+v %v", otherScope, err)
	}
}

func TestConfiguredInstallPreflightDoesNotOpenProjectOrServiceState(t *testing.T) {
	_, flags := configuredInstallFixture(t)
	target := config.Target(unavailableInstalledTarget(t))
	service := flags.project.Config.Services[flags.Service]
	service.Target.Address = &target
	service.Target.TLS = &config.TargetTLS{}
	flags.project.Config.Services[flags.Service] = service
	flags.Target = string(target)
	// macOS exposes its temporary directory through a /var symlink; installed
	// state rejects symlinked ancestors before it reaches target preflight.
	userParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	serviceParent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	flags.StateDir = filepath.Join(userParent, "no-user-state")
	serviceRoot := filepath.Join(serviceParent, "no-service")
	err = runEnrolledBackgroundPublish(t.Context(), flags, enrolledPublishSelection{}, backgroundPublishFlags{Install: true, SystemStateDir: serviceRoot}, io.Discard, strings.NewReader(""), installedjobs.ExecutorFunc(func(context.Context, installedjobs.Command) error {
		t.Fatal("missing supervisor reached the manager")
		return nil
	}))
	if reason, ok := failure.ReasonOf(err); !ok || reason != failure.TargetUnavailable {
		t.Fatalf("configured install skipped target preflight: %v", err)
	}
	for _, path := range []string{flags.StateDir, serviceRoot} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preflight mutated state at %s: %v", path, err)
		}
	}
}

func unavailableInstalledTarget(t *testing.T) string {
	t.Helper()
	// use an unbound ephemeral port, not an available listener with invalid tls:
	// refusal is target_unavailable; failed verification has its own diagnostic.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return "https://" + address
}

func TestInstalledConfiguredServiceRejectsStaleSavedTrust(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	bindConfiguredBackgroundService(t, c, flags)
	trust, err := captureServiceTargetTrust(t.Context(), publishCommand{Target: flags.Target, TargetTLSName: "old.internal"}, controlv1.ServiceProtocolHTTP, flags.Target)
	if err != nil {
		t.Fatal(err)
	}
	c.service.TargetTls = publisheridentity.ServiceTargetTLS(trust)
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(c), a, nil
	}
	err = installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil)
	if err == nil {
		t.Fatal("outdated saved HTTP target trust installed")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("stale target installed job: %+v %v", jobs, err)
	}
}

func TestExplicitPublisherCannotInstallAnotherServiceEndpoint(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	bindConfiguredBackgroundService(t, c, flags)
	c.service.Endpoint.Hostname = "orders.other-domain.example"
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(c), a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err == nil {
		t.Fatal("explicit enrollment installed a same-prefix endpoint from another domain")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("wrong-domain grant installed a job: %+v %v", jobs, err)
	}
}

func TestConfiguredInstallSnapshotsTargetTrust(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	flags.Target = server.URL
	service := flags.project.Config.Services[flags.Service]
	service.Target.Address = new(config.Target(server.URL))
	service.Target.TLS = &config.TargetTLS{CA: new(string(certificate)), Hostname: new(server.Certificate().DNSNames[0])}
	flags.project.Config.Services[flags.Service] = service
	bindConfiguredBackgroundService(t, c, flags)
	trust, err := captureServiceTargetTrust(t.Context(), flags, controlv1.ServiceProtocolHTTP, flags.Target)
	if err != nil {
		t.Fatal(err)
	}
	c.service.TargetTls = publisheridentity.ServiceTargetTLS(trust)
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		return backgroundClients(c), a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	service.Target.TLS.CA = new("changed configuration")
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].Trust == nil || !bytes.Equal(jobs[0].Trust.PEM, certificate) || jobs[0].Trust.Hostname != server.Certificate().DNSNames[0] {
		t.Fatalf("installed trust followed mutable project configuration: %+v %v", jobs, err)
	}
	encoded, err := json.Marshal(jobs[0])
	if err != nil || bytes.Contains(encoded, []byte(`"target_ca_pem"`)) || bytes.Contains(encoded, []byte(`"target_tls_name"`)) {
		t.Fatal("installed trust retained a second trust representation", err)
	}
}

func TestInvalidConfiguredCARejectsBeforeEnrollment(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	service := flags.project.Config.Services[flags.Service]
	service.Target.TLS = &config.TargetTLS{CA: new("not a CA certificate")}
	flags.project.Config.Services[flags.Service] = service
	clients := func(installedjobs.Job) (installedjobs.PublisherClients, publisheridentity.EnrollmentAuthority, error) {
		t.Fatal("invalid trust reached the control API")
		return backgroundClients(c), a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err == nil {
		t.Fatal("invalid trust accepted")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 || a.redemptions != 0 {
		t.Fatalf("invalid CA mutated publisher state: %+v redemptions=%d %v", jobs, a.redemptions, err)
	}
}
