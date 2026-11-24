package daemon

import (
	"bufio"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	publisherapp "github.com/tnldotdev/tnl/internal/publisher/app"
	publisherlocal "github.com/tnldotdev/tnl/internal/publisher/local"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/testutil"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var nativePublisherRelayChild = flag.String("tnl-native-publisher-relay-child", "", "private native publisher test topology descriptor")

type nativePublisherRelayTopology struct {
	ControlURL string `json:"control_url"`
	ControlTCP string `json:"control_tcp"`
	RootsPEM   string `json:"roots_pem"`
}

// the SDK spawns the native owner in its own process. only fixture TLS roots
// and the control dial address differ from the built CLI handoff.
func TestNativePublisherRelayChild(t *testing.T) {
	if *nativePublisherRelayChild == "" {
		t.Skip("only started by the native relay fixture")
	}
	data, err := os.ReadFile(*nativePublisherRelayChild)
	var topology nativePublisherRelayTopology
	if err != nil || json.Unmarshal(data, &topology) != nil {
		os.Exit(1)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(topology.RootsPEM)) {
		os.Exit(1)
	}
	origin, err := url.Parse(topology.ControlURL)
	if err != nil {
		os.Exit(1)
	}
	dial := net.Dialer{Timeout: 5 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address == net.JoinHostPort(origin.Hostname(), "443") {
				address = topology.ControlTCP
			}
			return dial.DialContext(ctx, network, address)
		},
	}
	http.DefaultTransport = transport
	values := map[string]string{}
	args := flag.Args()
	for i := 3; i+1 < len(args); i += 2 {
		values[args[i]] = args[i+1]
	}
	err = publisherlocal.ServeSDKPublisher(t.Context(), publisherlocal.Options{
		Directory: ".", StateDir: os.Getenv("TNL_STATE_DIR"),
		AttachPublication: func(_ context.Context, _ publisherapp.Service, config *publisherservice.RunConfig) error {
			config.TransportTLS = transport.TLSClientConfig.Clone()
			config.DrainTime = time.Second
			return nil
		},
	}, values["--instance"], values["--control-url"], os.Stdin, os.Stdout)
	if err != nil {
		_, _ = io.WriteString(os.Stderr, err.Error()+"\n")
		os.Exit(1)
	}
	os.Exit(0)
}

func TestIntegrationNativePublisherRelayTraffic(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if len(flag.Args()) != 0 {
		t.Fatal("unexpected native relay test arguments")
	}
	testutil.UseClientKeychain(t)
	f, _, _, _, _ := wasmFixtureRelays(t)
	ingress := startSeparatedPrivateIngress(t, f, 0, "wss", nil)
	visitorTransport := &http.Transport{
		TLSClientConfig:   f.visitorRoots.Clone(),
		DialContext:       workloadPublicEndpointDialer(t, ingress.ingresses[0].server, 443),
		DisableKeepAlives: true,
	}
	t.Cleanup(visitorTransport.CloseIdleConnections)
	visitor := &http.Client{Transport: visitorTransport, Timeout: 5 * time.Second}
	const project, deployment = "native-publisher-relay", "production"
	mode, protocol := controlv1.Anonymous, controlv1.ServiceProtocolHTTP
	configuration := controlv1.ProjectConfiguration{
		Settings: &controlv1.DeploymentSettings{},
		Services: map[string]controlv1.ProjectServiceConfiguration{
			"web":      {Target: "app", Protocol: &protocol, Public: new(true), Http: &controlv1.ProjectServiceHTTP{Access: &controlv1.ProjectHTTPAccess{Mode: &mode}}},
			"internal": {Target: "app", Protocol: &protocol, Public: new(false)},
		},
	}
	apply := func(revision int64) controlv1.AppliedProjectConfiguration {
		t.Helper()
		request := controlv1.ApplyProjectConfigurationRequest{
			TeamId: f.identity.teamID, Deployment: deployment, Configuration: configuration,
			ServiceDeclarations: controlv1.ProjectServiceDeclarations{"web": protocol, "internal": protocol}, ExpectedRevision: revision,
		}
		if revision == 0 {
			request.Source = &testProjectSource
		}
		applied, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), project, request)
		if err != nil || applied.Deployments == nil || len(*applied.Deployments) != 1 {
			t.Fatal("apply native publisher fixture", err)
		}
		return applied
	}
	first := apply(0)
	binding := configuration.Services["web"]
	binding.PublisherAliasParent = new((*first.Deployments)[0].Namespace)
	configuration.Services["web"] = binding
	applied := apply(first.Revision)
	var internalID string
	for _, service := range applied.Services {
		if service.Service == "internal" && service.ServiceId != nil {
			internalID = *service.ServiceId
		}
	}
	privateService, err := f.identity.routes.GetService(t.Context(), internalID)
	if err != nil || privateService.Endpoint == nil || privateService.Endpoint.Public {
		t.Fatal("private HTTP fixture did not realize a connector-only service", err)
	}
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	control, err := connectorstream.NewControl(f.identity.routes, f.identity.state, person.Identity.Id)
	if err != nil {
		t.Fatal(err)
	}

	directory, repo := t.TempDir(), integrationRepositoryRoot(t)
	topology := filepath.Join(directory, "relay.json")
	raw, err := json.Marshal(nativePublisherRelayTopology{
		ControlURL: f.controlConfig.ControlOrigin(), ControlTCP: f.publicControlAddress,
		RootsPEM: string(f.certificateAuthority.certificatePEM),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(topology, raw, 0600); err != nil {
		t.Fatal(err)
	}
	testBinary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
	shim := filepath.Join(directory, "tnl")
	script := "#!/bin/sh\nexec " + quote(testBinary) + " -test.run='^TestNativePublisherRelayChild$' -tnl-native-publisher-relay-child=" + quote(topology) + " -- \"$@\"\n"
	if err := os.WriteFile(shim, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	installPublicationSDKs(t, repo, directory, shim)
	type evidence struct {
		Identity          string `json:"identity"`
		URL               string `json:"url"`
		ExactURL          string `json:"publisher_url"`
		CertificateSHA256 string `json:"certificate_sha256"`
	}
	type active struct {
		evidence
		run  int64
		stop func()
	}
	enrollment := func(service, instance string) string {
		t.Helper()
		approval, err := f.identity.routes.CreateDeploymentPublisherEnrollment(t.Context(), f.identity.teamID, project, deployment, instance,
			controlv1.CreateDeploymentPublisherEnrollmentRequest{Services: []string{service}, MaxMembers: new(1), ExpiresIn: new(600)})
		if err != nil {
			t.Fatal(err)
		}
		return approval.EnrollmentKey
	}
	start := func(sdk, service, instance, key string) active {
		t.Helper()
		args := []string{f.controlConfig.ControlOrigin(), sdk, instance, service}
		var command *exec.Cmd
		if sdk == "python" {
			command = exec.Command("uv", append([]string{"run", "--frozen", "--project", filepath.Join(repo, "packages/py"), "python", filepath.Join(directory, "enrolled-publisher-traffic.py")}, args...)...)
		} else {
			command = exec.Command(sdk, append([]string{filepath.Join(directory, "enrolled-publisher-traffic.ts")}, args...)...)
		}
		command.Dir = directory
		command.Env = append(os.Environ(), "TNL_STATE_DIR="+filepath.Join(directory, "state"), "TNL_NO_TELEMETRY=1", "PYTHONPATH="+filepath.Join(directory, "python"))
		stdin, err := command.StdinPipe()
		if err != nil {
			t.Fatal(err)
		}
		stdout, err := command.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		var stderr synchronizedBuffer
		command.Stderr = &stderr
		isolate := isolateIntegrationCommand(t, command)
		owned, err := startOwnedCommand(command, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			defer isolate()
			_ = stdin.Close()
			_ = owned.shutdown(4*time.Second, 3*time.Second)
		})
		if _, err := io.WriteString(stdin, key+"\n"); err != nil {
			t.Fatal(err)
		}
		line := make(chan string, 1)
		go func() {
			reader := bufio.NewScanner(stdout)
			if reader.Scan() {
				line <- reader.Text()
			} else {
				line <- ""
			}
		}()
		var facts evidence
		select {
		case raw := <-line:
			if err := json.Unmarshal([]byte(raw), &facts); err != nil || facts.Identity == "" || len(facts.CertificateSHA256) != 64 {
				t.Fatalf("%s did not report publication readiness: %v (%s)", sdk, err, stderr.String())
			}
		case <-time.After(90 * time.Second):
			t.Fatalf("%s publisher did not become ready: %s", sdk, stderr.String())
		}
		var run int64
		if service == "web" {
			if !strings.HasPrefix(facts.URL, "https://") || !strings.HasPrefix(facts.ExactURL, "https://p-") {
				t.Fatal("public publication did not return its pool and exact addresses")
			}
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT run.run_number FROM control.service_endpoints ep JOIN control.service_runs run ON ep.service_run_id=run.id WHERE ep.hostname=$1 AND run.publisher_identity_id=$2 AND run.closed_at IS NULL`,
				strings.TrimPrefix(facts.ExactURL, "https://"), facts.Identity).Scan(&run); err != nil {
				t.Fatal("published address did not identify the actual current run", err)
			}
		} else {
			if facts.URL != "" || facts.ExactURL != "" {
				t.Fatal("connector-only publication returned an address")
			}
			var publicCount int
			if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FROM control.service_endpoints WHERE service_id=$1 AND public`, internalID).Scan(&publicCount); err != nil || publicCount != 0 {
				t.Fatal("connector-only publication installed public routing", err, publicCount)
			}
		}
		return active{facts, run, func() {
			t.Helper()
			_ = stdin.Close()
			select {
			case <-owned.done:
				if err := owned.result(); err != nil {
					t.Fatalf("%s owner did not join: %v (%s)", sdk, err, stderr.String())
				}
			case <-time.After(20 * time.Second):
				t.Fatalf("%s publisher did not stop: %s", sdk, stderr.String())
			}
		}}
	}
	assertCertificate := func(response *http.Response, want string) {
		t.Helper()
		if response.TLS == nil || len(response.TLS.PeerCertificates) == 0 {
			t.Fatal("visitor did not receive a service certificate")
		}
		fingerprint := sha256.Sum256(response.TLS.PeerCertificates[0].Raw)
		if hex.EncodeToString(fingerprint[:]) != want {
			t.Fatal("exported leaf was not the certificate that served the visitor")
		}
	}
	visit := func(address, want, certificate string) {
		t.Helper()
		privateWait(t, 15*time.Second, func(ctx context.Context) (bool, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
			if err != nil {
				return false, err
			}
			resp, err := visitor.Do(req)
			if err != nil {
				return want == "", nil
			}
			body, err := io.ReadAll(io.LimitReader(resp.Body, 2048))
			err = errors.Join(err, resp.Body.Close())
			if want == "" {
				return resp.StatusCode != http.StatusOK, err
			}
			if resp.StatusCode == http.StatusOK && string(body) != want {
				t.Fatalf("%s reached a different publisher (got %q, want %q)", address, body, want)
			}
			if resp.StatusCode == http.StatusOK {
				assertCertificate(resp, certificate)
			}
			return resp.StatusCode == http.StatusOK && string(body) == want, err
		})
	}
	sibling := start("node", "web", "sibling", enrollment("web", "sibling"))
	defer sibling.stop()
	for index, sdk := range []string{"node", "bun", "python"} {
		instance := sdk + "-" + strconv.Itoa(index)
		current := start(sdk, "web", instance, enrollment("web", instance))
		t.Logf("%s: verify initial and reopened traffic on one exact address", sdk)
		visit(current.ExactURL, instance+":initial", current.CertificateSHA256)
		current.stop()
		visit(current.ExactURL, "", "")
		visit(sibling.ExactURL, "sibling:initial", sibling.CertificateSHA256)
		reopened := start(sdk, "web", instance, "")
		if reopened.evidence != current.evidence || reopened.run <= current.run {
			t.Fatal("reopening did not retain identity/address or advance the serving run", reopened.run, current.run)
		}
		visit(reopened.ExactURL, instance+":reopened", reopened.CertificateSHA256)
		reopened.stop()

		name := sdk + "-private"
		owner := start(sdk, "internal", name, enrollment("internal", name))
		_, wss := f.connectors()
		listener, stop := startRuntimeConnector(t, f, privateService, connectorstream.Config{
			Control: control, IdentityID: person.Identity.Id, RelayQUIC: privateDisabledConnector(), RelayWebSocket: wss,
		}, revokedConnectorOwnerStop)
		roots := f.visitorRoots.Clone()
		roots.ServerName = privateService.Endpoint.Hostname
		transport := &http.Transport{
			TLSClientConfig: roots,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, listener.Addr().String())
			},
		}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
		response, err := client.Get("https://" + privateService.Endpoint.Hostname)
		if err != nil {
			t.Fatal("connector-only publisher did not serve a private request", err)
		}
		body, err := io.ReadAll(io.LimitReader(response.Body, 2048))
		err = errors.Join(err, response.Body.Close())
		transport.CloseIdleConnections()
		stop()
		owner.stop()
		if err != nil || response.StatusCode != http.StatusOK || string(body) != name+":initial" {
			t.Fatalf("%s private publisher returned status %d, body %q (%v)", sdk, response.StatusCode, body, err)
		}
		assertCertificate(response, owner.CertificateSHA256)
	}
}
