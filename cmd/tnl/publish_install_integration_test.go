package main

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/authorityclient"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/failure"
	nativeauth "github.com/tnldotdev/tnl/internal/publisheridentity/native"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/pkg/api/authorityv1"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var publisherInstallContainer = flag.Bool("tnl-publisher-install-container", false, "allow supervisor fixtures only inside disposable Ubuntu")
var publisherInstallNetwork = flag.String("tnl-publisher-install-network", "", "disposable PostgreSQL network namespace for Compose")
var publisherInstallImage = flag.String("tnl-publisher-install-image", "", "disposable Ubuntu image for the init reboot fixture")
var publisherInstallInspect = flag.Bool("tnl-publisher-install-inspect", false, "inspect the Compose fixture's original scoped state")
var publisherInstallServer = flag.String("tnl-publisher-install-server", "", "fixture control URL")
var publisherInstallTarget = flag.String("tnl-publisher-install-target", "", "fixture HTTP target")
var publisherInstallURL = flag.String("tnl-publisher-install-url", "", "fixture exact public URL ID")
var publisherInstallTeam = flag.String("tnl-publisher-install-team", "", "fixture exact team ID")

func TestIntegrationPublisherInstallLifecycle(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if !*publisherInstallContainer {
		t.Skip("use task go:test:integration:publisher-install")
	}
	init, err := os.ReadFile("/proc/1/comm")
	if runtime.GOOS != "linux" || os.Geteuid() != 0 || err != nil || strings.TrimSpace(string(init)) != "systemd" || *publisherInstallNetwork == "" {
		t.Fatal("publisher installation requires the disposable Ubuntu/systemd fixture")
	}
	if _, err := os.Stat("/.dockerenv"); err != nil {
		t.Fatal("refusing host supervisor access")
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "operator")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "installation fixture", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	key, err := randomIdempotencyKey()
	if err != nil {
		t.Fatal(err)
	}
	team, err := session.authenticated.Authority.CreateTeam(t.Context(), authorityv1.CreateTeamRequest{DisplayName: "studio"}, key)
	if err != nil {
		t.Fatal(err)
	}
	services, err := preparePublisherServices(t.Context(), session.database, f.url, "", "opencode", "", "studio", false, session.authenticated)
	if err != nil {
		t.Fatal(err)
	}
	// systemd children use the real OS trust store inside this disposable image.
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw})
	if err := os.WriteFile("/usr/local/share/ca-certificates/tnl-install-fixture.crt", ca, 0o644); err != nil {
		t.Fatal(err)
	}
	installFixtureCommand(t, "update-ca-certificates")
	hosts, err := os.OpenFile("/etc/hosts", os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = fmt.Fprintln(hosts, "127.0.0.1 "+services.hostname)
	if err != nil {
		t.Fatal(err)
	}
	if err := hosts.Close(); err != nil {
		t.Fatal(err)
	}
	// preserve visitor DNS/443/TLS while the existing small topology selects an
	// ephemeral ingress port. this listener is in the fixture's network namespace.
	public, err := net.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = public.Close() })
	go func() {
		for {
			visitor, err := public.Accept()
			if err != nil {
				return
			}
			go func() {
				defer visitor.Close()
				ingress, err := net.Dial("tcp", f.publicAddress)
				if err != nil {
					return
				}
				defer ingress.Close()
				done := make(chan struct{})
				go func() { _, _ = io.Copy(ingress, visitor); close(done) }()
				_, _ = io.Copy(visitor, ingress)
				_ = visitor.Close()
				<-done
			}()
		}
	}()
	var probes atomic.Int64
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Tnl-Readiness-Probe") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("readiness forwarded credentials to the app")
		}
		probes.Add(1)
		_, _ = io.WriteString(w, "opencode fixture")
	}))
	_ = target.Listener.Close()
	target.Listener, err = net.Listen("tcp", "127.0.0.1:4096")
	if err != nil {
		t.Fatal(err)
	}
	target.Start()
	defer target.Close()
	binDir := "/opt/tnl-publisher-install-fixture"
	if err := os.Mkdir(binDir, 0o755); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(binDir, "tnl")
	build := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", binary, "./cmd/tnl")
	build.Dir = "../.."
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build fixture CLI: %v\n%s", err, output)
	}
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"} {
		data, err := os.ReadFile(filepath.Join("../..", name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(binDir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"--no-config", "--no-telemetry", "publish", target.URL, "--name", "opencode", "--team", "studio", "--install", "--system", "--server", f.url, "--state-dir", person}
	output := installFixtureCommand(t, binary, args...)
	if !strings.Contains(output, "https://opencode.") || !strings.Contains(output, "ready") || probes.Load() == 0 {
		t.Fatal("setup returned before verified public readiness", output)
	}
	root := publisherjob.DefaultRoot("linux")
	registry, err := publisherjob.Open(t.Context(), publisherjob.OpenOptions{Root: root})
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()
	job, err := registry.ResolveJob(t.Context(), "opencode")
	if err != nil {
		t.Fatal(err)
	}
	if job.Status.PublicURL != "https://"+services.hostname {
		t.Fatal("installation printed a different public URL")
	}
	firstRun, publisherID, urlID := job.Status.PublishRunNumber, job.PublisherID, job.PublicURLID
	checkSeparation := func() {
		t.Helper()
		profile, err := registry.Profile(t.Context(), f.url)
		if err != nil {
			t.Fatal(err)
		}
		if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
			t.Fatal("installed publisher contains a human session", err)
		}
		for _, path := range []string{root, filepath.Join(root, "bin"), filepath.Join(root, "bin", "tnl-notices")} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0o700 {
				t.Fatal("publisher directory is not private", path, err)
			}
		}
	}
	checkSeparation()
	credential, err := registry.Credential(t.Context(), job)
	if err != nil {
		t.Fatal(err)
	}
	// interrupt after the desired job/key commit, before supervisor installation.
	err = registerPublication(t.Context(), publisherjob.ServiceOptions{Root: root, BinarySource: filepath.Join(binDir, "missing")}, publicationInstallation{Job: job, Credential: credential}, io.Discard,
		publisherjob.ExecutorFunc(func(context.Context, publisherjob.Command) error {
			t.Fatal("interrupted installer reached systemd")
			return nil
		}))
	if err == nil {
		t.Fatal("interrupted installation unexpectedly succeeded")
	}
	// retry as a non-root operator. only this exact root helper is sudo-allowed;
	// the private payload must survive stdin without exposing secrets in argv.
	installFixtureCommand(t, "useradd", "--create-home", "--uid", "1001", "installer")
	sudoers := "installer ALL=(root) NOPASSWD: " + binary + " --no-telemetry service register --system --system-state-dir " + root + " --private-result\n"
	if err := os.WriteFile("/etc/sudoers.d/tnl-install-fixture", []byte(sudoers), 0o440); err != nil {
		t.Fatal(err)
	}
	installFixtureCommand(t, "chown", "-R", "1001:1001", filepath.Dir(person))
	installFixtureCommand(t, "runuser", append([]string{"-u", "installer", "--", binary}, args...)...)
	installFixtureCommand(t, "chown", "-R", "0:0", filepath.Dir(person))
	job, err = registry.ResolveJob(t.Context(), "opencode")
	if err != nil || job.PublisherID != publisherID || job.PublicURLID != urlID || job.Status.PublishRunNumber <= firstRun {
		t.Fatal("setup retry replaced the identity or URL", err)
	}
	// enter through the real parser as the unprivileged operator. the configured
	// target must survive serialization, sudo, logout, restart and init reboot.
	installFixtureCommand(t, "chown", "-R", "1001:1001", filepath.Dir(person))
	job = installConfiguredHealthTarget(t, registry, job, binDir, binary, person)
	installFixtureCommand(t, "chown", "-R", "0:0", filepath.Dir(person))
	firstRun = job.Status.PublishRunNumber
	installFixtureCommand(t, binary, "auth", "logout", "--server", f.url, "--state-dir", person)
	installFixtureCommand(t, "systemctl", "is-enabled", publisherjob.SystemdUnit)
	installFixtureCommand(t, "systemctl", "daemon-reexec")
	installFixtureCommand(t, "systemctl", "restart", publisherjob.SystemdUnit)
	workflowWait(t, 30*time.Second, func() bool {
		job, err = registry.ResolveJob(t.Context(), "opencode")
		return err == nil && job.Status.State == "ready" && job.Status.PublishRunNumber > firstRun
	})
	if job.PublicURLID != urlID || job.PublisherID != publisherID {
		t.Fatal("logout/restart changed publication ownership")
	}
	checkSeparation()
	installFixtureCommand(t, "systemctl", "stop", publisherjob.SystemdUnit)
	t.Cleanup(func() { _ = exec.Command("systemctl", "stop", publisherjob.SystemdUnit).Run() })
	// keep control/ingress/relay alive in this runner while a separate installed
	// machine reboots through its real init. only the exact credential crosses.
	machine := "tnl-installed-" + fmt.Sprint(time.Now().UnixNano())
	installFixtureCommand(t, "docker", "run", "--detach", "--name", machine, "--privileged", "--cgroupns=private", "--network=container:"+*publisherInstallNetwork, "--tmpfs", "/run", "--tmpfs", "/run/lock", *publisherInstallImage)
	t.Cleanup(func() {
		if t.Failed() {
			for _, args := range [][]string{{"logs", machine}, {"exec", machine, "systemctl", "status", publisherjob.SystemdUnit, "--no-pager"}, {"exec", machine, binary, "service", "status", "opencode", "--system"}} {
				output, _ := exec.Command("docker", args...).CombinedOutput()
				t.Log(string(output))
			}
			f.logRuns(t)
		}
		_ = exec.Command("docker", "rm", "--force", machine).Run()
	})
	installFixtureCommand(t, "docker", "exec", machine, "mkdir", "-p", binDir)
	installFixtureCommand(t, "docker", "cp", binDir+"/.", machine+":"+binDir)
	installFixtureCommand(t, "docker", "cp", "/usr/local/share/ca-certificates/tnl-install-fixture.crt", machine+":/usr/local/share/ca-certificates/tnl-install-fixture.crt")
	installFixtureCommand(t, "docker", "exec", machine, "update-ca-certificates")
	payload, err := json.Marshal(publicationInstallation{Job: job, Credential: credential})
	if err != nil {
		t.Fatal(err)
	}
	register := exec.CommandContext(t.Context(), "docker", "exec", "-i", machine, binary, "--no-telemetry", "service", "register", "--system")
	register.Stdin = bytes.NewReader(payload)
	if output, err := register.CombinedOutput(); err != nil {
		t.Fatalf("register reboot fixture: %v\n%s", err, output)
	}
	// control's current run number is observed across a complete container boot,
	// not inferred from local desired state or an old readiness observation.
	beforeBoot, err := session.authenticated.Control.GetPublicURL(t.Context(), urlID)
	if err == nil {
		t.Fatal("logged-out human session still has control access")
	}
	// the publisher can still read its exact URL without that human session.
	control, authority, err := publisherjob.Clients(job)
	if err != nil {
		t.Fatal(err)
	}
	identity, signing, err := credential.Validate()
	if err != nil {
		t.Fatal(err)
	}
	scoped, err := nativeauth.NewNative(control, authority, identity, signing)
	if err != nil {
		t.Fatal(err)
	}
	beforeBoot, err = scoped.SavedURL(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	installFixtureCommand(t, "docker", "restart", "--timeout", "60", machine)
	// Docker rewrites the shared /etc/hosts file on container boot. restore this
	// fixture's stand-in for public DNS before checking the restarted publisher.
	dns := exec.CommandContext(t.Context(), "docker", "exec", "-i", machine, "tee", "-a", "/etc/hosts")
	dns.Stdin = strings.NewReader("127.0.0.1 " + services.hostname + "\n")
	if output, err := dns.CombinedOutput(); err != nil {
		t.Fatalf("restore fixture DNS: %v\n%s", err, output)
	}
	workflowWait(t, 75*time.Second, func() bool {
		command := exec.CommandContext(t.Context(), "docker", "exec", machine, binary, "service", "status", "opencode", "--system")
		output, err := command.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "ready") {
			return false
		}
		afterBoot, err := scoped.SavedURL(t.Context())
		return err == nil && afterBoot.Id == urlID && afterBoot.NextPublishRunNumber > beforeBoot.NextPublishRunNumber
	})
	status := installFixtureCommand(t, "docker", "exec", machine, binary, "auth", "status", "--server", f.url, "--state-dir", root, "--output=json")
	var auth struct {
		Status string `json:"status"`
		Source string `json:"source"`
	}
	if json.Unmarshal([]byte(status), &auth) != nil || auth.Status != "unauthenticated" || auth.Source != "none" {
		t.Fatal("rebooted publisher contains human credentials")
	}
	installFixtureCommand(t, "docker", "exec", machine, "systemctl", "stop", publisherjob.SystemdUnit)
	staleOwner, err := scoped.RemoteRuntime(f.url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := staleOwner.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	replacementOwner, err := scoped.RemoteRuntime(f.url)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replacementOwner.Renew(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err := staleOwner.Renew(t.Context()); err == nil {
		t.Fatal("old publisher epoch reclaimed its replacement")
	} else if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.ServerConflict {
		t.Fatal("stale runtime lost its owned fence diagnostic", err)
	}
	scoped.WithRuntime(staleOwner)
	if _, err := scoped.CreatePublishRun(t.Context(), urlID, "stale-epoch-proof"); err == nil {
		t.Fatal("stale publisher epoch created another public URL run")
	} else if classified, ok := failure.Of(err); !ok || classified.Reason() != failure.ServerConflict {
		t.Fatal("stale run creation lost its fence diagnostic", err)
	}
	if err := replacementOwner.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	f.loginPerson(t, person)
	current, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "enrollment fixture", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer current.Close()
	route, err := current.authenticated.Control.GetPublicURL(t.Context(), urlID)
	if err != nil || route.AccessMode != controlv1.Restricted || route.Target != "" {
		t.Fatal("setup relaxed access or stored the private target", err)
	}
	// fresh Compose identity is issued by the operator. it receives exactly one
	// saved URL grant, and never receives the operator's session.
	enrollment := func() string {
		t.Helper()
		e, err := current.authenticated.Control.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{TeamId: team.Id, PublicUrlId: &urlID, Name: "opencode", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled})
		if err != nil {
			t.Fatal(err)
		}
		return e.EnrollmentKey
	}
	image := "tnl-install-fixture:" + fmt.Sprint(time.Now().UnixNano())
	buildPublisherFixtureImage(t, image, binary, ca)
	t.Cleanup(func() { _ = exec.Command("docker", "image", "rm", "--force", image).Run() })
	project := "tnl-install-" + fmt.Sprint(time.Now().UnixNano())
	override := filepath.Join(t.TempDir(), "compose.yaml")
	// this local source-built fixture has no published registry digest. only its
	// explicit test override omits deployment-image validation; the reference
	// always passes its required immutable TNL_IMAGE to the native publisher.
	if err := os.WriteFile(override, []byte("services:\n  publisher:\n    network_mode: container:"+*publisherInstallNetwork+"\n    environment:\n      TNL_IMAGE: \"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := enrollment()
	consumedSecret := secret
	environmentFile := filepath.Join(t.TempDir(), ".env")
	compose := func(allowFailure bool, extra ...string) string {
		t.Helper()
		data := "TNL_IMAGE=" + image + "\nTNL_SERVER=" + f.url + "\nTNL_TARGET=" + target.URL + "\nTNL_ENROLL_KEY=" + secret + "\n"
		if err := os.WriteFile(environmentFile, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(t.Context(), "docker", append([]string{"compose", "--env-file", environmentFile, "--project-name", project, "--file", "../../deploy/compose-publisher/compose.yaml", "--file", override}, extra...)...)
		output, err := command.CombinedOutput()
		if err != nil && !allowFailure {
			t.Fatalf("Compose fixture: %v\n%s", err, output)
		}
		return string(output)
	}
	t.Cleanup(func() {
		if t.Failed() {
			t.Log(compose(true, "logs", "--no-color", "publisher"))
		}
		compose(true, "down", "--volumes", "--remove-orphans")
	})
	compose(false, "up", "--detach")
	ready := func() {
		t.Helper()
		workflowWait(t, 30*time.Second, func() bool { return strings.Contains(compose(false, "logs", "--no-color", "publisher"), "ready") })
	}
	ready()
	before, err := current.authenticated.Control.GetPublicURL(t.Context(), urlID)
	if err != nil {
		t.Fatal(err)
	}
	compose(false, "exec", "-T", "publisher", "/fixture/inspect.test", "-test.run=^TestIntegrationPublisherInstallIdentity$", "-test.v", "-tnl-test-tier=integration", "-tnl-publisher-install-inspect", "-tnl-publisher-install-server="+f.url, "-tnl-publisher-install-target="+target.URL, "-tnl-publisher-install-url="+urlID, "-tnl-publisher-install-team="+team.Id)
	secret = ""
	compose(false, "up", "--detach", "--force-recreate")
	ready()
	after, err := current.authenticated.Control.GetPublicURL(t.Context(), urlID)
	if err != nil || after.NextPublishRunNumber <= before.NextPublishRunNumber {
		t.Fatal("retained Compose identity did not start a new run", err)
	}
	// an anonymous application GET remains denied while proof-bound readiness
	// succeeds, and the state volume contains no control session.
	visitor := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := visitor.Get("https://" + services.hostname + "/")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode == http.StatusOK {
		t.Fatal("restricted publication admitted an anonymous application request")
	}
	compose(false, "down", "--volumes")
	secret = "" // an empty volume cannot initiate interactive login.
	compose(false, "up", "--detach")
	workflowWait(t, 15*time.Second, func() bool {
		return strings.Contains(compose(false, "logs", "--no-color", "publisher"), "TNL_CLIENT_PUBLISHER_ENROLLMENT_REQUIRED")
	})
	compose(false, "down", "--volumes")
	secret = consumedSecret
	compose(false, "up", "--detach")
	workflowWait(t, 15*time.Second, func() bool {
		return strings.Contains(compose(false, "logs", "--no-color", "publisher"), "TNL_CLIENT_PUBLISHER_ENROLLMENT_REQUIRED")
	})
	compose(false, "down", "--volumes")
	// a consumed key must not resurrect the lost private key.
	// the first enrollment ID is retained separately from container state.
	// capture it from the operator's exact URL identities for explicit revocation.
	identities, err := current.authenticated.Control.ListPublisherIdentities(t.Context(), team.Id, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, identity := range identities.Identities {
		if identity.Id != publisherID {
			if err := current.authenticated.Control.RevokePublisherIdentity(t.Context(), team.Id, identity.Id); err != nil {
				t.Fatal(err)
			}
		}
	}
	secret = enrollment()
	compose(false, "up", "--detach")
	ready()
	recovered, err := current.authenticated.Control.GetPublicURL(t.Context(), urlID)
	if err != nil || recovered.Id != route.Id || recovered.CanonicalHostname != route.CanonicalHostname || recovered.AccessMode != controlv1.Restricted || recovered.NextPublishRunNumber <= after.NextPublishRunNumber {
		t.Fatal("fresh enrollment failed to recover the saved publication", err)
	}
	t.Log("real Ubuntu sudo setup/interrupted retry, operator logout, complete init reboot, retained Compose restart, missing-state/consumed-key failures, and fresh scoped enrollment preserved the restricted URL without human management access")
}

func installConfiguredHealthTarget(t *testing.T, registry *publisherjob.Registry, old publisherjob.Job, binDir, binary, person string) publisherjob.Job {
	t.Helper()
	var probes atomic.Int64
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Tnl-Readiness-Probe") != "" || r.Header.Get("Cookie") != "" {
			t.Error("readiness credential reached target")
		}
		probes.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(target.Close)
	projectRoot := filepath.Join(binDir, "project")
	if err := os.Mkdir(projectRoot, 0o755); err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(projectRoot, "target-ca.pem")
	ca := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: target.Certificate().Raw})
	if err := os.WriteFile(caFile, ca, 0o644); err != nil {
		t.Fatal(err)
	}
	address := config.Target(target.URL)
	document := config.Document{Version: new(1), TNL: &config.TNL{Server: &old.Server, Team: new("studio"), Services: config.Services{
		"opencode": {Tunnel: &config.Tunnel{PublicURL: &old.Status.PublicURL}, Target: &config.ServiceTarget{Type: "address", Address: &address, TLS: &config.TargetTLS{CAFile: new("target-ca.pem"), ServerName: new("example.com")}}, HTTP: &config.HTTPService{Readiness: &config.Readiness{Path: "/health"}}},
	}}}
	data, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	configuration := filepath.Join(projectRoot, "tnl.json")
	if err := os.WriteFile(configuration, data, 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{"-u", "installer", "--", binary, "--no-telemetry", "--config", configuration, "publish", "opencode", "--install", "--system", "--state-dir", person}
	output := installFixtureCommand(t, "runuser", args...)
	if !strings.Contains(output, "ready") || strings.Contains(output, "sign in") {
		t.Fatal("configured CLI installation failed or exposed credentials", output)
	}
	job, err := registry.ResolveJob(t.Context(), old.ID)
	if err != nil || job.ReadinessPath != "/health" || job.Revision <= old.Revision || job.GrantID != old.GrantID || job.PublisherID != old.PublisherID || job.Target != target.URL || job.TargetTLSName != "example.com" || !bytes.Equal(job.TargetCAPEM, ca) {
		t.Fatal("configured CLI installation lost target settings or exact grant", err)
	}
	// retry the real setup command after its first committed reply. it must reuse
	// the identity and exact URL while retaining the evaluated target snapshot.
	installFixtureCommand(t, "runuser", args...)
	retried, err := registry.ResolveJob(t.Context(), old.ID)
	if err != nil || retried.PublisherID != job.PublisherID || retried.GrantID != job.GrantID || retried.PublicURLID != job.PublicURLID || retried.Status.PublishRunNumber <= job.Status.PublishRunNumber {
		t.Fatal("configured CLI retry changed identity or failed to restart", err)
	}
	// supervisor restarts and the reboot machine have no project or CA file.
	if err := os.RemoveAll(projectRoot); err != nil {
		t.Fatal(err)
	}
	job = retried
	if job.Status.State != "ready" || probes.Load() == 0 {
		t.Fatal("installed /health target did not become ready", err)
	}
	logs := installFixtureCommand(t, "journalctl", "--unit", publisherjob.SystemdUnit, "--no-pager")
	if strings.Contains(logs, "PRIVATE KEY") {
		t.Fatal("supervisor logged private credentials")
	}
	response, err := http.Get(job.Status.PublicURL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode < 400 {
		t.Fatal("readiness allowed an anonymous visitor")
	}
	return job
}

func TestIntegrationPublisherInstallIdentity(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if !*publisherInstallInspect {
		t.Skip("Compose state inspection helper")
	}
	publisherState, err := clientstate.OpenWithOptions(t.Context(), "/var/lib/tnl/publisher", clientstate.OpenOptions{Protection: clientstate.ProtectionFile})
	if err != nil {
		t.Fatal(err)
	}
	defer publisherState.Close()
	profile, err := publisherState.Server(t.Context(), *publisherInstallServer)
	if err != nil {
		t.Fatal(err)
	}
	if _, found, err := profile.ControlSession(t.Context()); err != nil || found {
		t.Fatal("Compose received a person session", err)
	}
	selected, found, err := profile.SelectedPublisherIdentity(t.Context(), "job", retainedPublicationScope(*publisherInstallTarget))
	if err != nil || !found {
		t.Fatal("Compose did not retain its exact identity", err)
	}
	control, err := controlclient.New(*publisherInstallServer, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	authority, err := authorityclient.New(*publisherInstallServer, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	native, identity, err := nativeauth.LoadNative(t.Context(), profile, control, authority, selected.ID)
	if err != nil || identity.Kind != authorityv1.SavedUrl || identity.PublicUrlId == nil || *identity.PublicUrlId != *publisherInstallURL || identity.TeamId != *publisherInstallTeam {
		t.Fatal("Compose identity is not scoped to the exact URL", err)
	}
	access, err := native.Access(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	management, err := controlclient.New(*publisherInstallServer, nil, credentials.AccessToken(access))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := management.ListPublicURLs(t.Context(), *publisherInstallTeam); err == nil {
		t.Fatal("publisher identity acquired human management access")
	}
}

func installFixtureCommand(t *testing.T, program string, args ...string) string {
	t.Helper()
	command := exec.CommandContext(t.Context(), program, args...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture %s: %v\n%s", filepath.Base(program), err, output)
	}
	return string(output)
}

func buildPublisherFixtureImage(t *testing.T, image, binary string, ca []byte) {
	t.Helper()
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	var context bytes.Buffer
	archive := tar.NewWriter(&context)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	inspector, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{
		"Dockerfile": []byte("FROM ubuntu:24.04@sha256:68ee22004a9109b44973313b02ff7b1de250f1de0f5ecb628d73f579aaff33ac\nCOPY tnl /usr/local/bin/tnl\nCOPY inspect.test ca.crt /fixture/\nCOPY LICENSE NOTICE THIRD_PARTY_LICENSES.txt /licenses/tnl/\nENV SSL_CERT_FILE=/fixture/ca.crt\nENTRYPOINT [\"/usr/local/bin/tnl\"]\n"),
		"tnl":        data, "ca.crt": ca,
		"inspect.test": inspector,
	}
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD_PARTY_LICENSES.txt"} {
		files[name], err = os.ReadFile(filepath.Join(filepath.Dir(binary), name))
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range files {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(content))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "docker", "build", "--tag", image, "-")
	command.Stdin = &context
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build Compose fixture: %v\n%s", err, output)
	}
}
