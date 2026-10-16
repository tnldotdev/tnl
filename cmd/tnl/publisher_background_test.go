package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisheridentity/credentialfile"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type backgroundAuthority struct {
	identity    authorityv1.PublisherEnrollmentResult
	public      ed25519.PublicKey
	redemptions int
}

func (a *backgroundAuthority) RedeemPublisherEnrollment(_ context.Context, _ string, public ed25519.PublicKey) (authorityv1.PublisherEnrollmentResult, error) {
	a.redemptions++
	a.public = append(ed25519.PublicKey(nil), public...)
	return a.identity, nil
}
func (a *backgroundAuthority) ExchangePublisherAssertion(_ context.Context, client, grant, key string, private ed25519.PrivateKey) (string, error) {
	if client != a.identity.ClientId || grant != a.identity.GrantId || key != a.identity.KeyId || !private.Public().(ed25519.PublicKey).Equal(a.public) {
		return "", nativeauth.ErrScope
	}
	return "access-secret", nil
}

type backgroundControl struct {
	nativeauth.NativeControl
	publicURL controlv1.PublicURL
}

func (c *backgroundControl) PublisherPublicURL(context.Context, string) (controlv1.PublicURL, error) {
	return c.publicURL, nil
}

func backgroundFixture(t *testing.T) (*publisherjob.Registry, *backgroundAuthority, *backgroundControl, enrolledPublishSelection) {
	t.Helper()
	owner := os.Geteuid()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	r, err := publisherjob.Open(t.Context(), publisherjob.OpenOptions{Root: filepath.Join(parent, "system"), TestOwnerUID: &owner})
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
	url := id(opaqueid.PublicURLPrefix)
	a := &backgroundAuthority{identity: authorityv1.PublisherEnrollmentResult{ClientId: id(opaqueid.PublisherIdentityPrefix), KeyId: id(opaqueid.PublisherIdentityKeyPrefix), GrantId: id(opaqueid.PublisherGrantPrefix), TeamId: "team", Kind: "saved_url", PublicUrlId: &url}}
	c := &backgroundControl{publicURL: controlv1.PublicURL{Id: url, TeamId: "team", CanonicalHostname: "db.example", LifecycleState: controlv1.Enabled, Purpose: controlv1.App, ServiceProtocol: "postgres"}}
	return r, a, c, enrolledPublishSelection{EnrollmentKey: id(opaqueid.PublisherEnrollmentPrefix) + ".enrollment-secret"}
}

func TestBackgroundInstallsEnrolledTCPJobWithLocalTarget(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	flags := publishCommand{Target: "127.0.0.1:5432", TargetTLS: true, TargetTLSName: "db.internal"}
	flags.ServerURL = "https://control.example"
	bg := backgroundPublishFlags{Install: true, ServiceName: "database"}
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return c, a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, bg, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("installed jobs: %+v, %v", jobs, err)
	}
	job := jobs[0]
	if job.ID != publisherjob.PublicURLJobKey(flags.ServerURL, c.publicURL.Id) || job.Name != "database" || job.Protocol != "postgres" || job.Target != flags.Target || !job.TargetTLS || job.TargetTLSName != "db.internal" || job.PublisherID != a.identity.ClientId {
		t.Fatalf("private target settings: %+v", job)
	}
	if c.publicURL.Target != "" {
		t.Fatal("private database target was sent to control")
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
	if _, found, err := profile.PublisherSigningIdentity(t.Context(), "publisher:"+a.identity.ClientId); err != nil || !found {
		t.Fatalf("stop revoked/removed identity: %v", err)
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
	flags := publishCommand{Target: "127.0.0.1:5432"}
	flags.ServerURL = f.ControlURL
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return c, a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, enrolledPublishSelection{PublisherFile: path}, backgroundPublishFlags{Install: true, ServiceName: "database"}, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || jobs[0].PublisherID != a.identity.ClientId || a.redemptions != 0 {
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
				a.identity.Kind, a.identity.PublicUrlId = "namespace", nil
				namespace, domain := "member.example", func() string { v, _ := opaqueid.New(opaqueid.DomainPrefix); return v }()
				a.identity.Namespace, a.identity.DomainId = &namespace, &domain
			case "ephemeral":
				c.publicURL.Ephemeral = true
			case "implicit server":
				flags.ServerURL = ""
			case "policy":
				flags.Anonymous = true
			case "open":
				flags.Open = true
			}
			clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
				return c, a, nil
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
	_, a, _, selection := backgroundFixture(t)
	root := filepath.Join(t.TempDir(), "not-installed")
	flags := publishCommand{Target: "127.0.0.1:5432"}
	flags.ServerURL = "https://control.example"
	err := runEnrolledBackgroundPublish(t.Context(), flags, selection, backgroundPublishFlags{Install: true, SystemStateDir: root}, io.Discard, strings.NewReader(""), publisherjob.ExecutorFunc(func(context.Context, publisherjob.Command) error {
		t.Fatal("missing service reached the manager")
		return nil
	}))
	if err == nil || a.redemptions != 0 {
		t.Fatalf("preflight: err=%v redemptions=%d", err, a.redemptions)
	}
	if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.ServiceNotInstalled {
		t.Fatalf("missing service used the wrong failure reason: %v", err)
	}
	if _, statErr := os.Lstat(root); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("preflight created state: %v", statErr)
	}
}

func configuredInstallFixture(t *testing.T) (projectConfiguration, publishCommand) {
	t.Helper()
	server, target, name, hostname := "https://control.example", config.Target("127.0.0.1:5432"), "orders", "https://orders.example"
	protocol := "postgres"
	project := projectConfiguration{Project: projectconfig.Project{Root: t.TempDir(), Config: config.TNL{
		Server: &server, Services: config.Services{
			"orders": {Protocol: &protocol, Tunnel: &config.Tunnel{PublicURL: &hostname}, Target: &config.ServiceTarget{Type: "address", Address: &target}},
			"api":    {Target: &config.ServiceTarget{Type: "app"}},
		},
	}}}
	flags := publishCommand{Target: name}
	if err := project.applyInstalledService(&flags); err != nil {
		t.Fatal(err)
	}
	return project, flags
}

func TestConfiguredInstallUsesOnlySelectedStableService(t *testing.T) {
	project, flags := configuredInstallFixture(t)
	if flags.Service != "orders" || flags.ServiceName != "orders" || flags.ServerURL != "https://control.example" || flags.Target != "127.0.0.1:5432" || flags.Protocol != "postgres" || flags.projectRoot != project.Root {
		t.Fatalf("wrong configured service: %+v", flags)
	}
	scope, err := resolveConfiguredInstallScope(t.Context(), flags, nil)
	if err != nil || scope.hostname != "orders.example" || scope.teamID != "" {
		t.Fatalf("explicit configured public URL did not select an exact hostname: %+v %v", scope, err)
	}
	urlID := "url_selected"
	identity := authorityv1.PublisherEnrollmentResult{TeamId: "team_selected", PublicUrlId: &urlID}
	for _, hostname := range []string{"orders.other-team.example", "orders.other-domain.example", "orders.example.other-checkout"} {
		if scope.matches(controlv1.PublicURL{Id: urlID, CanonicalHostname: hostname, TeamId: identity.TeamId}, identity) {
			t.Fatalf("same prefix on a different URL was selected: %s", hostname)
		}
	}
	if !scope.matches(controlv1.PublicURL{Id: urlID, CanonicalHostname: "orders.example", TeamId: identity.TeamId}, identity) {
		t.Fatal("explicit public URL did not match its exact saved grant")
	}
	staleID := "url_previous"
	identity.PublicUrlId = &staleID
	if scope.matches(controlv1.PublicURL{Id: urlID, CanonicalHostname: "orders.example", TeamId: identity.TeamId}, identity) {
		t.Fatal("mismatched grant selected the configured public URL")
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

func TestConfiguredInstallSelectsSavedExactGrantWithoutEnrollment(t *testing.T) {
	r, a, c, _ := backgroundFixture(t)
	project, flags := configuredInstallFixture(t)
	profile, err := r.Profile(t.Context(), flags.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	c.publicURL.CanonicalHostname = "orders.example"
	scope, err := resolveConfiguredInstallScope(t.Context(), flags, nil)
	if err != nil {
		t.Fatal(err)
	}
	store := func(identity authorityv1.PublisherEnrollmentResult, private ed25519.PrivateKey) {
		document, err := json.Marshal(identity)
		if err != nil {
			t.Fatal(err)
		}
		if err := profile.ImportPublisherIdentity(t.Context(), clientstate.PublisherIdentity{ID: identity.ClientId, PublicDocument: document, SigningKey: private}); err != nil {
			t.Fatal(err)
		}
		if err := profile.SelectPublisherIdentity(t.Context(), "project", projectPublisherScope(flags.ServerURL, *identity.PublicUrlId), identity.ClientId); err != nil {
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
	unrelatedURL, err := opaqueid.New(opaqueid.PublicURLPrefix)
	if err != nil {
		t.Fatal(err)
	}
	unrelated.PublicUrlId = &unrelatedURL
	store(unrelated, unrelatedKey)
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a.public = private.Public().(ed25519.PublicKey)
	store(a.identity, private)
	native, selected, key, route, err := selectConfiguredPublisherCandidates(t.Context(), flags.ServerURL, profile, []string{unrelatedURL, c.publicURL.Id}, scope, c, a)
	if err != nil || native == nil || selected.ClientId != a.identity.ClientId || route.Id != c.publicURL.Id || !key.Public().(ed25519.PublicKey).Equal(a.public) || a.redemptions != 0 {
		t.Fatalf("selected wrong scoped grant or redeemed enrollment: %+v %v", selected, err)
	}
	if _, _, _, _, err := selectConfiguredPublisherCandidates(t.Context(), flags.ServerURL, profile, []string{unrelatedURL}, scope, c, a); err == nil {
		t.Fatal("missing matching grant fell back to a different service")
	} else if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.InstalledPublisherSelectionMissing {
		t.Fatalf("missing selection has no authored next step: %v", err)
	}
	if !scope.matches(route, selected) || project.Root != flags.projectRoot {
		t.Fatal("saved URL does not match project")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("read-only grant selection installed a job: %+v %v", jobs, err)
	}
}

func TestConfiguredWorktreeHostnameBindsTeamDomainAndGrant(t *testing.T) {
	root := t.TempDir()
	worktree := namedTestWorktree(root, "shop")
	protocol := "postgres"
	project := projectConfiguration{Project: projectconfig.Project{Root: root, Worktree: worktree, Config: config.TNL{
		Services: config.Services{"orders": {Protocol: &protocol}},
	}}}
	current := teamContext{
		team: authorityv1.Team{Id: "team_selected", DefaultDomainId: "domain_selected"},
		membership: authorityv1.Membership{
			TeamId: "team_selected", Role: authorityv1.TeamRoleMember, ManagedLabel: "ecstatic-penguin", MemberSlug: "chase",
		},
		domains: []authorityv1.Domain{{Id: "domain_selected", Kind: authorityv1.Managed, CanonicalDomain: "tnl.dev", State: authorityv1.DomainStateReady}},
	}
	scope, err := configuredInstallScopeForTeam(project, "orders", current)
	if err != nil {
		t.Fatal(err)
	}
	want := projectconfig.ServiceWorktreeLabel("orders", worktree) + ".ecstatic-penguin.tnl.dev"
	if scope.hostname != want || scope.teamID != current.team.Id || scope.domainID != current.domains[0].Id {
		t.Fatalf("wrong advertised worktree URL: %+v, want %s", scope, want)
	}
	urlID := "url_selected"
	identity := authorityv1.PublisherEnrollmentResult{TeamId: current.team.Id, PublicUrlId: &urlID}
	item := controlv1.PublicURL{Id: urlID, CanonicalHostname: want, TeamId: current.team.Id, DomainId: current.domains[0].Id}
	if !scope.matches(item, identity) {
		t.Fatal("saved URL with matching team, domain and grant was rejected")
	}
	for name, mutate := range map[string]func(*controlv1.PublicURL, *authorityv1.PublisherEnrollmentResult){
		"other team": func(url *controlv1.PublicURL, grant *authorityv1.PublisherEnrollmentResult) {
			url.TeamId, grant.TeamId = "team_other", "team_other"
		},
		"other domain": func(url *controlv1.PublicURL, _ *authorityv1.PublisherEnrollmentResult) {
			url.DomainId = "domain_other"
		},
		"old grant": func(_ *controlv1.PublicURL, grant *authorityv1.PublisherEnrollmentResult) {
			old := "url_previous"
			grant.PublicUrlId = &old
		},
	} {
		t.Run(name, func(t *testing.T) {
			otherURL, otherGrant := item, identity
			mutate(&otherURL, &otherGrant)
			if scope.matches(otherURL, otherGrant) {
				t.Fatal("saved URL outside selected service scope was accepted")
			}
		})
	}
	other := project
	other.Worktree = namedTestWorktree(filepath.Join(root, "other-checkout"), "shop")
	otherScope, err := configuredInstallScopeForTeam(other, "orders", current)
	if err != nil || otherScope.hostname == want || otherScope.matches(item, identity) {
		t.Fatalf("another checkout selected this worktree's URL: %+v %v", otherScope, err)
	}
}

func TestConfiguredInstallPreflightDoesNotOpenProjectOrServiceState(t *testing.T) {
	_, flags := configuredInstallFixture(t)
	flags.StateDir = filepath.Join(t.TempDir(), "no-user-state")
	serviceRoot := filepath.Join(t.TempDir(), "no-service")
	err := runEnrolledBackgroundPublish(t.Context(), flags, enrolledPublishSelection{}, backgroundPublishFlags{Install: true, SystemStateDir: serviceRoot}, io.Discard, strings.NewReader(""), publisherjob.ExecutorFunc(func(context.Context, publisherjob.Command) error {
		t.Fatal("missing supervisor reached the manager")
		return nil
	}))
	if reason, ok := failure.Of(err); !ok || reason.Reason() != failure.ServiceNotInstalled {
		t.Fatalf("configured install skipped supervisor preflight: %v", err)
	}
	for _, path := range []string{flags.StateDir, serviceRoot} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("preflight mutated state at %s: %v", path, err)
		}
	}
}

func TestInstalledConfiguredServiceRejectsStaleSavedTarget(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	flags.Protocol, flags.Target = "http", "3000"
	c.publicURL.ServiceProtocol = controlv1.Http
	c.publicURL.CanonicalHostname = "orders.example"
	c.publicURL.Target = "http://127.0.0.1:5000"
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return c, a, nil
	}
	err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil)
	if err == nil {
		t.Fatal("outdated saved HTTP target installed")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("stale target installed job: %+v %v", jobs, err)
	}
}

func TestExplicitPublisherCannotInstallAnotherServiceURL(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	c.publicURL.CanonicalHostname = "orders.other-domain.example"
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return c, a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err == nil {
		t.Fatal("explicit enrollment installed a same-prefix URL from another domain")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 {
		t.Fatalf("wrong-domain grant installed a job: %+v %v", jobs, err)
	}
}

func TestConfiguredInstallSnapshotsTargetTrust(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	project, flags := configuredInstallFixture(t)
	caPath := filepath.Join(project.Root, "target.pem")
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(caPath, certificate, 0o600); err != nil {
		t.Fatal(err)
	}
	flags.TargetCAFile, flags.TargetTLS, flags.TargetTLSName = "target.pem", true, "db.internal"
	c.publicURL.CanonicalHostname = "orders.example"
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		return c, a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(caPath, []byte("changed file"), 0o600); err != nil {
		t.Fatal(err)
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 1 || !bytes.Equal(jobs[0].TargetCAPEM, certificate) || jobs[0].TargetTLSName != "db.internal" {
		t.Fatalf("installed trust followed a mutable project file: %+v %v", jobs, err)
	}
}

func TestInvalidConfiguredCARejectsBeforeEnrollment(t *testing.T) {
	r, a, c, selection := backgroundFixture(t)
	_, flags := configuredInstallFixture(t)
	path := filepath.Join(flags.projectRoot, "invalid.pem")
	if err := os.WriteFile(path, []byte("not a CA certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	flags.TargetCAFile = path
	clients := func(publisherjob.Job) (nativeauth.NativeControl, nativeauth.EnrollmentAuthority, error) {
		t.Fatal("invalid trust reached the control API")
		return c, a, nil
	}
	if err := installBackgroundJob(t.Context(), r, flags, selection, backgroundPublishFlags{Install: true}, strings.NewReader(""), clients, nil); err == nil {
		t.Fatal("invalid trust accepted")
	}
	jobs, err := r.List(t.Context())
	if err != nil || len(jobs) != 0 || a.redemptions != 0 {
		t.Fatalf("invalid CA mutated publisher state: %+v redemptions=%d %v", jobs, a.redemptions, err)
	}
}
