package tnldruntime

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/clientauth"
	"github.com/tnldotdev/tnl/internal/clientstate"
	"github.com/tnldotdev/tnl/internal/muxsession"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/publisherauth"
	"github.com/tnldotdev/tnl/internal/remoteprobe"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestIntegrationEditorDeviceAndEngineerPublicPath(t *testing.T) {
	fixture := newStandalonePublishFixture(t, "engineer-device")
	release := make(chan struct{})
	var releaseOnce sync.Once
	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })
	started := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stream" {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, "first\n")
			w.(http.Flusher).Flush()
			started <- struct{}{}
			select {
			case <-release:
				_, _ = io.WriteString(w, "second\n")
			case <-r.Context().Done():
			}
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	cleanupIntegrationHTTPServer(t, target, fixture.owner)
	quic, tcp := fixture.connectors()
	configured := fixture.identity.publisherConfig(target.URL, quic, tcp)
	configured.AllowedIPPrefixes = []string{"192.0.2.7/32"}
	vendor := startOwnedIntegrationPublisher(t, fixture.owner, configured, fixture.diagnostics)
	reserved := fixture.waitReady(t, vendor)
	stopIntegrationPublisher(t, vendor)

	controlHTTP, _ := newIntegrationHTTPSClient(t, fixture.pebble.roots, fixture.publicAddress, false, fixture.owner)
	urlID := reserved.PublicURLID
	deviceConfig := restartEnrolledIntegrationDevice(t, fixture.owner, fixture.identity, controlHTTP, urlID,
		target.URL, controlv1.Http, quic, tcp)
	handle := startOwnedIntegrationPublisher(t, fixture.owner, deviceConfig, fixture.diagnostics)
	ready := fixture.waitReady(t, handle)
	selected := remoteprobe.Selection{Address: ready.PublicURL, HTTPTransport: fixture.visitor.transport}
	waitForEngineerReachability(t, selected, false)
	entry, err := fixture.identity.routes.AddOperatorIP(t.Context(), urlID, "127.0.0.1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	waitForEngineerReachability(t, selected, true)
	request, err := http.NewRequestWithContext(t.Context(), http.MethodGet, ready.PublicURL+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := fixture.visitor.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	reader := bufio.NewReader(response.Body)
	if line, err := reader.ReadString('\n'); err != nil || line != "first\n" {
		t.Fatalf("existing visitor stream = %q, %v", line, err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("engineer stream did not reach the device")
	}
	if err := fixture.identity.routes.RemoveOperatorIP(t.Context(), urlID, entry.Id); err != nil {
		t.Fatal(err)
	}
	waitForEngineerReachability(t, selected, false)
	releaseOnce.Do(func() { close(release) })
	if line, err := reader.ReadString('\n'); err != nil || line != "second\n" {
		t.Fatalf("revocation interrupted an established visitor: %q, %v", line, err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	stopIntegrationPublisher(t, handle)
}

func TestDNSIntegrationEnrolledSSHDeviceAndEngineerIPHandoff(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierDNS)
	if runtime.GOOS == "darwin" {
		t.Skip("automatic DNS integration requires binding privileged port 53")
	}
	if integrationDNSSubprocess(t) {
		return
	}
	publicAddress := unusedTCPAddress(t)
	_, port, err := net.SplitHostPort(publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	dnsFixture := newIntegrationRoute53(t, "server", "split.integration.test")
	fixture := newSplitPublishFixtureWithOptions(t, "engineer-ssh", splitPublishOptions{
		dns:          dnsFixture,
		proxyIngress: true,
		configureProcess: func(cfg *tnldconfig.Config) {
			if cfg.Role == tnldconfig.RoleControl {
				cfg.TCPPorts = port
			}
		},
	})
	stopProxy := startIntegrationPublicProxyWithDestination(t, fixture.ingressConfig.IngressListen,
		netip.MustParseAddrPort(publicAddress), publicAddress)
	defer stopProxy()
	sshd, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sshd.Close() })
	go func() {
		for {
			connection, err := sshd.Accept()
			if err != nil {
				return
			}
			go func() {
				defer connection.Close()
				_, _ = io.WriteString(connection, "SSH-2.0-device-fixture\r\n")
				_, _ = io.Copy(connection, connection)
			}()
		}
	}()
	quic, tcp := fixture.connectors()
	target := sshd.Addr().String()
	configured := fixture.identity.publisherConfig(target, quic, tcp)
	configured.ServiceProtocol = controlv1.Ssh
	configured.AllowedIPPrefixes = []string{"192.0.2.7/32"}
	diagnostics := func() string { return integrationPublisherDiagnostics(fixture.inspect, fixture.pebble.logPath) }
	vendor := startOwnedIntegrationPublisher(t, fixture.owner, configured, diagnostics)
	reserved := waitForPublisherReady(t, vendor)
	stopIntegrationPublisher(t, vendor)
	deviceConfig := restartEnrolledIntegrationDevice(t, fixture.owner, fixture.identity, fixture.controlHTTP,
		reserved.PublicURLID, target, controlv1.Ssh, quic, tcp)
	device := startOwnedIntegrationPublisher(t, fixture.owner, deviceConfig, diagnostics)
	ready := waitForPublisherReady(t, device)
	if ready.PublicURLID != reserved.PublicURLID {
		t.Fatal("enrolled device published a different saved public URL")
	}
	waitForReadyPublisherConnections(t, fixture.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, fixture.inspect, 1)
	selected := remoteprobe.Selection{Address: publicAddress, Protocol: "ssh"}
	waitForEngineerReachability(t, selected, false)
	entry, err := fixture.identity.routes.AddOperatorIP(t.Context(), ready.PublicURLID, "127.0.0.1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	waitForEngineerReachability(t, selected, true)
	connection, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(t.Context(), "tcp", publicAddress)
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(20 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(connection)
	if line, err := reader.ReadString('\n'); err != nil || line != "SSH-2.0-device-fixture\r\n" {
		t.Fatalf("engineer SSH banner = %q, %v", line, err)
	}
	if _, err := io.WriteString(connection, "before\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "before\n" {
		t.Fatalf("engineer stream before revocation = %q, %v", line, err)
	}
	if err := fixture.identity.routes.RemoveOperatorIP(t.Context(), ready.PublicURLID, entry.Id); err != nil {
		t.Fatal(err)
	}
	waitForEngineerReachability(t, selected, false)
	if _, err := io.WriteString(connection, "after\n"); err != nil {
		t.Fatal(err)
	}
	if line, err := reader.ReadString('\n'); err != nil || line != "after\n" {
		t.Fatalf("operator IP revocation interrupted existing SSH stream: %q, %v", line, err)
	}
	if err := connection.Close(); err != nil {
		t.Fatal(err)
	}
	stopIntegrationPublisher(t, device)
}

func restartEnrolledIntegrationDevice(t *testing.T, topology *runtimeTopology, identity *integrationPublishingIdentity,
	controlHTTP *http.Client, publicURLID, target string, protocol controlv1.PublicURLServiceProtocol,
	quic, tcp muxsession.Connector) publisher.Config {
	t.Helper()
	enrollment, err := identity.routes.CreatePublisherEnrollment(t.Context(), controlv1.CreatePublisherEnrollmentRequest{
		TeamId: controlv1.TeamID(identity.teamID), PublicUrlId: &publicURLID,
		Name: "device", Kind: controlv1.CreatePublisherEnrollmentRequestKindInstalled,
	})
	if err != nil {
		t.Fatal(err)
	}
	auth, err := clientauth.PublisherClients(t.Context(), identity.controlOrigin, controlHTTP)
	if err != nil {
		t.Fatal(err)
	}
	device, err := publisherauth.Redeem(t.Context(), auth.PublisherControl, auth.PublisherAuthority, enrollment.EnrollmentKey)
	if err != nil {
		t.Fatal(err)
	}
	installed, err := device.InstalledIdentity()
	if err != nil {
		t.Fatal(err)
	}
	private, err := json.Marshal(installed)
	if err != nil {
		t.Fatal(err)
	}
	serviceRoot := filepath.Join(t.TempDir(), "device-service")
	service, err := clientstate.OpenService(t.Context(), serviceRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.SavePublisherJob(t.Context(), clientstate.PublisherJob{
		PublicURLID: publicURLID, Server: identity.controlOrigin, Target: target,
		Protocol: string(protocol), Identity: private,
	}); err != nil {
		t.Fatal(err)
	}
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	service, err = clientstate.OpenService(t.Context(), serviceRoot)
	if err != nil {
		t.Fatal(err)
	}
	topology.cleanupResource(t, func() { _ = service.Close() })
	jobs, err := service.PublisherJobs(t.Context())
	if err != nil || len(jobs) != 1 {
		t.Fatalf("device jobs after restart = %d, %v", len(jobs), err)
	}
	var restoredIdentity publisherauth.InstalledIdentity
	if err := json.Unmarshal(jobs[0].Identity, &restoredIdentity); err != nil {
		t.Fatal(err)
	}
	restarted, err := publisherauth.Restore(auth.PublisherControl, auth.PublisherAuthority, restoredIdentity)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := service.Server(t.Context(), identity.controlOrigin)
	if err != nil {
		t.Fatal(err)
	}
	deviceConfig := identity.publisherConfig(target, quic, tcp)
	deviceConfig.Control = &publisherauth.RunControl{Client: auth.PublisherControl, Owner: restarted}
	deviceConfig.State = profile
	deviceConfig.ServiceProtocol = protocol
	deviceConfig.AllowedIPPrefixes = []string{"192.0.2.7/32"}
	deviceConfig.PreserveSavedURLSettings = true
	return deviceConfig
}

func waitForEngineerReachability(t *testing.T, selected remoteprobe.Selection, reachable bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		result, err := remoteprobe.Probe(t.Context(), selected)
		if err != nil {
			t.Fatal(err)
		}
		if result.Reachable == reachable {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("engineer public path reachable = %t, want %t; reason = %s", result.Reachable, reachable, result.Reason)
		}
		select {
		case <-t.Context().Done():
			t.Fatal(t.Context().Err())
		case <-time.After(100 * time.Millisecond):
		}
	}
}
