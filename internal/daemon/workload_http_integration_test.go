package daemon

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/testutil/githubtest"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestIntegrationWorkloadHTTPPublicTLS(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	f, issuer := newWorkloadTransportFixture(t, nil)
	process := startSeparatedPrivateIngress(t, f, 0, "tls-tcp", nil)
	startSeparatedPrivateIngress(t, f, 1, "tls-tcp", nil)
	var requests, once atomic.Int32
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Header.Get("Authorization") != "Bearer application-owned" {
			t.Error("target lost application authorization or received workload secret")
		}
		if r.TLS == nil {
			t.Error("private target lost independent TLS")
		}
		if r.URL.Path == "/upgrade" {
			conn, buffer, err := http.NewResponseController(w).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: workload-test\r\n\r\n")
			if err := buffer.Flush(); err != nil {
				return
			}
			_, _ = io.Copy(conn, buffer)
			return
		}
		if r.URL.Path == "/stream" {
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
		}
		if r.URL.Path == "/once" {
			once.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			conn, _, err := http.NewResponseController(w).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		_, _ = io.Copy(w, r.Body)
	}))
	targetCA := newTestCertificateAuthority(t)
	const targetHostname = "workload.private.integration.test"
	target.TLS = serviceRuntimeTLS(t, targetCA, targetHostname)
	target.StartTLS()
	t.Cleanup(target.Close)
	targetTrust := serviceHTTPTestTargetTrust(targetHostname, string(targetCA.certificatePEM))
	targetTLS := controlv1.EnvironmentTargetTLS{Hostname: &targetTrust.Hostname, CaPem: targetTrust.CaPem, Digest: &targetTrust.Digest}
	public := createServiceRuntimeEnvironment(t, f, "workload", controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{
		"api": {Protocol: controlv1.ServiceProtocolHTTP}, "other": {Protocol: controlv1.ServiceProtocolHTTP},
	}}, controlv1.CreateEnvironmentRequest{Name: "public", Public: new(true), Targets: controlv1.EnvironmentTargets{
		"api": {Address: &target.URL, Tls: &targetTLS}, "other": {Address: &target.URL, Tls: &targetTLS},
	}})
	private := createServiceRuntimeEnvironment(t, f, "workload", controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{
		"private": {Protocol: controlv1.ServiceProtocolHTTP},
	}}, controlv1.CreateEnvironmentRequest{Name: "private", Targets: controlv1.EnvironmentTargets{"private": {Address: &target.URL, Tls: &targetTLS}}})
	startEnvironmentPublishers(t, f, public, "tls-tcp")
	// register both identities before issuing sessions: registration is itself a
	// revocation boundary for previously issued matching OIDC subjects.
	machine := registerRuntimeWorkload(t, f, "http", "")
	providerMachine := registerRuntimeWorkload(t, f, "provider", "provider")
	permissions := map[string]string{}
	for _, name := range []string{"test", "narrow", "short"} {
		duration := 120
		if name == "short" {
			duration = 8
		}
		permissions[name] = runtimeWorkloadPermission(t, f, machine, public, duration)
	}
	permissions["provider"] = runtimeWorkloadPermission(t, f, providerMachine, public, 120)
	newJob := func(name, execution string) *workload.Client {
		t.Helper()
		claims := githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())
		claims["check_run_id"], claims["jti"] = execution, execution
		if name == "provider" {
			claims["sub"] = providerMachine.Trust.Claims["sub"]
			claims["environment"] = providerMachine.Trust.Claims["environment"]
		}
		job, _ := prepareRuntimeWorkload(t, f, public, permissions[name], issuer.Sign(t, claims))
		return job
	}
	job := newJob("test", "301")
	prepared, err := job.Preparation()
	if err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	endpoints := map[string]controlv1.ServiceEndpoint{}
	for name, s := range prepared.Services {
		ids[name], endpoints[name] = s.ServiceId, s.Endpoint
	}
	if _, err := job.ClientTLSCertificate(t.Context(), private.Services[0].ServiceId); err == nil {
		t.Fatal("public environment visitor reached connector-only sibling")
	} else if problem := new(clientcontrol.ProblemError); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
		t.Fatal("out-of-scope HTTP certificate request did not reach an authorization denial", err)
	}
	privateProbe, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := privateProbe.Prepare(t.Context(), runtimeEnvironmentReference(f, private), permissions["test"], issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())), runtimeEnvironmentProtocols(private)); err == nil {
		t.Fatal("public environment permission selected connector-only sibling")
	} else if problem := new(clientauthority.ProblemError); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
		t.Fatal("sibling environment request did not reach an authority denial", err)
	}
	endpoint := func(name string) string {
		e := endpoints[name]
		return "https://" + net.JoinHostPort(e.Hostname, strconv.Itoa(e.Port))
	}
	newClient := func(name string, job *workload.Client) *http.Client {
		t.Helper()
		verification := f.visitorRoots.Clone()
		verification.ServerName = endpoints[name].Hostname
		verification.Certificates = nil
		if job != nil {
			certificate, err := job.ClientTLSCertificate(t.Context(), ids[name])
			if err != nil {
				t.Fatal(err)
			}
			verification.Certificates = append(verification.Certificates, certificate)
		}
		tr := &http.Transport{TLSClientConfig: verification, DialContext: workloadPublicEndpointDialer(t, process.ingresses[0].publicServices, endpoints[name].Port)}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	client := newClient("api", job)
	awaitServiceHTTPStatus(t, client, endpoint("api"), "Authorization", "Bearer application-owned", 200)
	request := func(client *http.Client, endpoint, path string, payload []byte, status int) *http.Response {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), "POST", endpoint+path, bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Authorization", "Bearer application-owned")
		response, err := client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		if response.StatusCode != status {
			response.Body.Close()
			t.Fatalf("HTTP status %d, want %d", response.StatusCode, status)
		}
		return response
	}
	// server-authenticated TLS with no local connector or client certificate;
	// no credential reaches an HTTP denial rather than failing TLS negotiation.
	before := requests.Load()
	response := request(newClient("api", nil), endpoint("api"), "/", nil, 403)
	response.Body.Close()
	if requests.Load() != before {
		t.Fatal("denied request reached target")
	}
	// the same credential permits several complete byte-preserving calls.
	payload := bytes.Repeat([]byte("\x00workload\xff\n"), 32<<10)
	for range 2 {
		response = request(client, endpoint("api"), "/echo", payload, 200)
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || !bytes.Equal(body, payload) {
			t.Fatal("forwarded bytes changed", err)
		}
	}
	response = request(newClient("api", job), endpoint("api"), "/echo", payload, 200)
	_, _ = io.Copy(io.Discard, response.Body)
	response.Body.Close()
	session, _ := job.Session()
	httpAsHuman, err := clientcontrol.New(f.controlConfig.ControlOrigin(), f.publicHTTP, credentials.AccessToken(session.Credential))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := httpAsHuman.GetEnvironment(t.Context(), f.identity.teamID, "workload", public.Id); !errors.Is(err, clientcontrol.ErrUnauthenticated) {
		t.Fatal("HTTP credential gained management rights", err)
	}
	// an application response loss cannot cause arbitrary POST-body replay.
	response = request(newClient("api", job), endpoint("api"), "/once", payload, 502)
	response.Body.Close()
	if once.Load() != 1 {
		t.Fatal("application body was retried")
	}
	openStream := func(job *workload.Client) <-chan error {
		t.Helper()
		streamClient := newClient("api", job)
		awaitServiceHTTPStatus(t, streamClient, endpoint("api"), "Authorization", "Bearer application-owned", 200)
		streamClient.Timeout = 0
		response := request(streamClient, endpoint("api"), "/stream", nil, 200)
		t.Cleanup(func() { _ = response.Body.Close() })
		done := make(chan error, 1)
		go func() { _, err := io.Copy(io.Discard, response.Body); done <- err }()
		return done
	}
	shortJob := newJob("short", "303")
	shortSession, _ := shortJob.Session()
	shortDone := openStream(shortJob)
	select {
	case <-shortDone:
	case <-time.After(time.Until(*shortSession.ExpiresAt) + time.Second):
		t.Fatal("fixed-expiry HTTP stream stayed open")
	}
	if wait := time.Until(*shortSession.ExpiresAt); wait > 0 {
		time.Sleep(wait + 25*time.Millisecond)
	}
	if _, err := shortJob.ClientTLSCertificate(t.Context(), ids["api"]); err == nil {
		t.Fatal("failed expiry extended certificate")
	}
	revoked := openStream(job)
	upgradeJob := newJob("test", "306")
	upgradeRequest, err := http.NewRequestWithContext(t.Context(), "GET", endpoint("api")+"/upgrade", nil)
	if err != nil {
		t.Fatal(err)
	}
	upgradeRequest.Header.Set("Authorization", "Bearer application-owned")
	upgradeRequest.Header.Set("Connection", "Upgrade")
	upgradeRequest.Header.Set("Upgrade", "workload-test")
	upgradeClient := newClient("api", upgradeJob)
	awaitServiceHTTPStatus(t, upgradeClient, endpoint("api"), "Authorization", "Bearer application-owned", 200)
	upgradeClient.Timeout = 0
	upgradeResponse, err := upgradeClient.Do(upgradeRequest)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upgradeResponse.Body.Close() })
	upgraded, ok := upgradeResponse.Body.(io.ReadWriteCloser)
	if upgradeResponse.StatusCode != 101 || !ok {
		t.Fatal("workload upgrade was not forwarded")
	}
	if _, err := upgraded.Write([]byte("upgrade bytes\n")); err != nil {
		t.Fatal(err)
	}
	upgradedBytes := make([]byte, len("upgrade bytes\n"))
	if _, err := io.ReadFull(upgraded, upgradedBytes); err != nil || string(upgradedBytes) != "upgrade bytes\n" {
		t.Fatal("upgrade bytes changed", err)
	}
	upgradeDone := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, upgraded); upgradeDone <- err }()
	narrowJob, providerJob := newJob("narrow", "304"), newJob("provider", "305")
	narrowed, provider := openStream(narrowJob), openStream(providerJob)
	if err := job.Revoke(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := upgradeJob.Revoke(t.Context()); err != nil {
		t.Fatal(err)
	}
	// permissions are immutable. replace a broad grant with a separately scoped
	// one, then revoke the original; old streams cannot adopt the replacement.
	replacement := runtimeWorkloadPermission(t, f, machine, public, 120, "other")
	person, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := f.database.RevokeEnvironmentVisitorPermission(t.Context(), f.identity.teamID, permissions["narrow"], person.Identity.Id, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := f.database.RevokeMachineIdentity(t.Context(), f.identity.teamID, providerMachine.ID, person.Identity.Id, time.Now()); err != nil {
		t.Fatal(err)
	}
	narrowProbe, err := workload.New(f.controlConfig.ControlOrigin(), f.publicHTTP)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := narrowProbe.Prepare(t.Context(), runtimeEnvironmentReference(f, public), replacement, issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())), map[string]string{"api": "http"}); err == nil {
		t.Fatal("narrow replacement restored removed service permission")
	} else if problem := new(clientauthority.ProblemError); !errors.As(err, &problem) || problem.Status != http.StatusForbidden {
		t.Fatal("removed-service request did not reach an authority denial", err)
	}
	if _, err := narrowProbe.Prepare(t.Context(), runtimeEnvironmentReference(f, public), replacement, issuer.Sign(t, githubtest.Claims(f.controlConfig.ControlOrigin(), time.Now())), map[string]string{"other": "http"}); err != nil {
		t.Fatal("narrow replacement lost its independently allowed service", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for _, done := range []<-chan error{revoked, narrowed, provider, upgradeDone} {
		select {
		case <-done:
		case <-time.After(time.Until(deadline)):
			t.Fatal("revoked HTTP stream exceeded 30-second authorization bound")
		}
	}
	response = request(client, endpoint("api"), "/", nil, 403)
	response.Body.Close()
	response = request(newClient("other", narrowProbe), endpoint("other"), "/", nil, 200)
	response.Body.Close()
}
