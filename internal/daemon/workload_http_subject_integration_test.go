package daemon

import (
	"bufio"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/connector/workload"
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
	group, protocol := "public", controlv1.ServiceProtocolHTTP
	policy := controlv1.ProjectWorkload{Provider: controlv1.WorkloadGitHub, Github: &controlv1.ProjectWorkloadGitHub{Repository: "example/repository", RepositoryId: "12345", RepositoryOwnerId: "6789", WorkflowRef: "example/repository/.github/workflows/test.yml@refs/heads/main", Ref: "refs/heads/main", Events: []string{"push"}}, Services: []string{"api"}, MaxDurationSeconds: 120}
	short := policy
	short.MaxDurationSeconds = 8
	policies := map[string]controlv1.ProjectWorkload{"old": short, "new": policy}
	_, err := f.identity.routes.ApplyProjectConfiguration(t.Context(), "workload", controlv1.ApplyProjectConfigurationRequest{TeamId: f.identity.teamID, SourceFingerprint: strings.Repeat("a", 64), Configuration: controlv1.ProjectConfiguration{Workloads: &policies, PublisherGroups: map[string]controlv1.ProjectPublisherGroup{group: {Public: new(true)}}, Services: map[string]controlv1.ProjectServiceConfiguration{"api": {PublisherGroup: &group, Protocol: &protocol, Target: target.URL}}, Webhooks: map[string]controlv1.ProjectWebhook{}}})
	if err != nil {
		t.Fatal(err)
	}
	startWorkloadPublishers(t, f, group, "tls-tcp")
	open := func(name, execution string) (*http.Response, string, time.Time) {
		t.Helper()
		job, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
		if err != nil {
			t.Fatal(err)
		}
		claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
		claims["check_run_id"], claims["jti"] = execution, execution
		session, err := job.Exchange(t.Context(), f.identity.teamID, "workload", strings.Repeat("a", 64), name, issuer.Sign(t, claims), []string{"api"})
		if err != nil {
			t.Fatal(err)
		}
		inventory, err := job.ListServices(t.Context())
		if err != nil || len(inventory.Services) != 1 {
			t.Fatal("inventory", err)
		}
		service := inventory.Services[0]
		certificate, err := job.ClientTLSCertificate(t.Context(), service.Id)
		if err != nil {
			t.Fatal(err)
		}
		verification := f.visitorRoots.Clone()
		verification.ServerName = service.Endpoint.Hostname
		verification.Certificates = []tls.Certificate{certificate}
		transport := &http.Transport{TLSClientConfig: verification, DialContext: workloadDirectDialer(t, process.ingresses[0].private, service.Endpoint.Port)}
		t.Cleanup(transport.CloseIdleConnections)
		request, err := http.NewRequestWithContext(t.Context(), "GET", "https://"+net.JoinHostPort(service.Endpoint.Hostname, strconv.Itoa(service.Endpoint.Port))+"/stream", nil)
		if err != nil {
			t.Fatal(err)
		}
		var response *http.Response
		for deadline := time.Now().Add(5 * time.Second); ; {
			response, err = (&http.Client{Transport: transport}).Do(request.Clone(t.Context()))
			if err != nil {
				t.Fatal("open stream", err)
			}
			if response.StatusCode == 200 {
				break
			}
			status := response.StatusCode
			_ = response.Body.Close()
			if (status != 403 && status != 503) || !time.Now().Before(deadline) {
				t.Fatal("prepared workload permission did not admit a new stream", status)
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Cleanup(func() { _ = response.Body.Close() })
		return response, session.Id, session.ExpiresAt
	}
	old, oldID, expires := open("old", "401")
	current, currentID, _ := open("new", "402")
	oldDone := make(chan struct{})
	go func() { _, _ = io.Copy(io.Discard, old.Body); close(oldDone) }()
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
	var oldConnections, newConnections, mixed int
	if err := f.inspect.QueryRowContext(t.Context(), `SELECT count(*) FILTER(WHERE workload_session_id=$1),count(*) FILTER(WHERE workload_session_id=$2),count(*) FILTER(WHERE workload_session_id=$2 AND certificate_digest IN(SELECT certificate_digest FROM control.workload_client_certificates WHERE workload_session_id=$1)) FROM control.visitor_certificate_facts`, oldID, currentID).Scan(&oldConnections, &newConnections, &mixed); err != nil || oldConnections != 1 || newConnections != 1 || mixed != 0 {
		t.Fatal("replacement transferred a visitor/certificate binding", err)
	}
}
