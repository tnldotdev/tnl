package daemon

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// replacement sessions use different visitor connections. crossing the old
// deadline cannot transfer its authorization to, or close, the new subject.
func TestIntegrationWorkloadHTTPReplacementKeepsSubjectsSeparate(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f, issuer := newWorkloadTransportFixture(t, nil)
	process := startSeparatedPrivateIngress(t, f, 0, "tls-tcp", nil)
	startSeparatedPrivateIngress(t, f, 1, "tls-tcp", nil)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			if _, err := io.WriteString(w, "tick\n"); err != nil {
				return
			}
			if err := http.NewResponseController(w).Flush(); err != nil {
				return
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(50 * time.Millisecond):
			}
		}
	}))
	t.Cleanup(target.Close)
	environment := createServiceRuntimeEnvironment(t, f, "workload", controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{"api": {Protocol: controlv1.ServiceProtocolHTTP}}}, controlv1.CreateEnvironmentRequest{Name: "public", Public: new(true), Targets: controlv1.EnvironmentTargets{"api": {Address: &target.URL}}})
	startEnvironmentPublishers(t, f, environment, "tls-tcp")
	machine := registerRuntimeWorkload(t, f, "replacement", "")
	permissions := map[string]string{
		"old": runtimeWorkloadPermission(t, f, machine, environment, 8),
		"new": runtimeWorkloadPermission(t, f, machine, environment, 120),
	}
	open := func(name, execution string) (*http.Response, string, time.Time) {
		t.Helper()
		claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
		claims["check_run_id"], claims["jti"] = execution, execution
		job, prepared := prepareRuntimeWorkload(t, f, environment, permissions[name], issuer.Sign(t, claims))
		session, service := prepared.Session, prepared.Services["api"]
		certificate, err := job.ClientTLSCertificate(t.Context(), service.ServiceId)
		if err != nil {
			t.Fatal(err)
		}
		verification := f.visitorRoots.Clone()
		verification.ServerName = service.Endpoint.Hostname
		verification.Certificates = []tls.Certificate{certificate}
		transport := &http.Transport{TLSClientConfig: verification, DialContext: workloadPublicEndpointDialer(t, process.ingresses[0].publicServices, service.Endpoint.Port)}
		t.Cleanup(transport.CloseIdleConnections)
		request, err := http.NewRequestWithContext(t.Context(), "GET", "https://"+net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port))+"/stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		var response *http.Response
		privateWait(t, 5*time.Second, func(context.Context) (bool, error) {
			response, err = (&http.Client{Transport: transport}).Do(request)
			if err != nil {
				return false, err
			}
			if response.StatusCode == http.StatusOK {
				return true, nil
			}
			response.Body.Close()
			return false, nil
		})
		t.Cleanup(func() { _ = response.Body.Close() })
		return response, session.Id, *session.ExpiresAt
	}
	old, oldID, expires := open("old", "401")
	current, currentID, _ := open("new", "402")
	if oldID == currentID {
		t.Fatal("replacement reused its parent session")
	}
	oldDone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, old.Body); close(oldDone) }()
	select {
	case <-oldDone:
		t.Fatal("replacement revoked the still-current old subject")
	default:
	}
	reader := bufio.NewReader(current.Body)
	for time.Now().Before(expires.Add(time.Second)) {
		if line, err := reader.ReadString('\n'); err != nil || line != "tick\n" {
			t.Fatal("new subject inherited old deadline", err)
		}
	}
	select {
	case <-oldDone:
	case <-time.After(time.Second):
		t.Fatal("old subject survived fixed expiry")
	}
}
