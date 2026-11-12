package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// real PostgreSQL, control, relays, CLI publishers/connectors, managed visitor
// TLS and application bytes complement the routine lease-replacement fixture.
func TestIntegrationCLIEnvironmentPublisherMultipleServicesKeepRuntimeLease(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "environment publisher siblings", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	team, control := session.Identity().PersonalTeamId, session.Authenticated().Control
	definition := controlv1.ServiceDefinition{Services: map[string]controlv1.ServiceDefinitionService{}}
	targets := controlv1.EnvironmentTargets{}
	for _, name := range []string{"api", "web"} {
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, name+" application bytes") }))
		defer target.Close()
		definition.Services[name] = controlv1.ServiceDefinitionService{Protocol: controlv1.ServiceProtocol("http")}
		targets[name] = controlv1.EnvironmentTarget{Address: &target.URL, Http: &controlv1.EnvironmentServiceHTTP{Access: &controlv1.ProjectPublicAccess{Mode: new(controlv1.Restricted)}}}
	}
	project := "publisher-siblings"
	revision, err := control.CreateServiceDefinition(t.Context(), project, controlv1.CreateServiceDefinitionRequest{TeamId: team, SourceFingerprint: strings.Repeat("a", 64), Definition: definition})
	if err != nil {
		t.Fatal(err)
	}
	key, err := randomIdempotencyKey()
	if err != nil {
		t.Fatal(err)
	}
	environment, err := control.CreateEnvironment(t.Context(), project, controlv1.CreateEnvironmentRequest{TeamId: team, SourceFingerprint: revision.SourceFingerprint, Name: "production", IdempotencyKey: key, DefinitionRevision: &revision.Revision, Targets: targets})
	if err != nil {
		t.Fatal(err)
	}
	identity := filepath.Join(t.TempDir(), "publisher.json")
	cliCall(t, t.Context(), []string{"--no-config", "publisher", "provision", "--server", f.url, "--team", team, "--project-key", project, "--environment", environment.Id, "--services", "api,web", "--instance", "replica-1", "--output-file", identity, "--state-dir", person})
	publisherCtx, stopPublisher := context.WithCancel(t.Context())
	publisherReady, publisherJoined := f.command(t, publisherCtx, stopPublisher, []string{"--no-config", "publisher", "serve", "--environment", environment.Id, "--project-key", project, "--instance", "replica-1", "--identity-file", identity, "--state-dir", f.state(t, "publisher"), "--identity-dir", filepath.Join(t.TempDir(), "identities")})
	select {
	case <-publisherReady:
	case <-time.After(30 * time.Second):
		t.Fatal("both environment service publications did not become ready")
	}
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(t.Context())
	type visitor struct {
		name, address string
		client        *http.Client
		cancel        context.CancelFunc
		joined        <-chan struct{}
	}
	var visitors []visitor
	for _, assigned := range environment.Services {
		service, err := control.GetService(t.Context(), assigned.ServiceId)
		if err != nil || service.Endpoint == nil {
			t.Fatal("missing saved service endpoint", err)
		}
		listener := workflowListen(t)
		address := listener.Addr().String()
		_ = listener.Close()
		ctx, cancel := context.WithCancel(t.Context())
		ready, joined := f.command(t, ctx, cancel, []string{"--no-config", "connect", assigned.ServiceId, "--server", f.url, "--team", team, "--state-dir", person, "--listen", address})
		select {
		case <-ready:
		case <-time.After(25 * time.Second):
			t.Fatal("native service connector did not become ready")
		}
		visitors = append(visitors, visitor{name: assigned.Service, address: address, client: workflowNativeHTTPClient(t, f, service.Endpoint.Hostname), cancel: cancel, joined: joined})
	}
	assertBytes := func() {
		t.Helper()
		for _, visitor := range visitors {
			workflowWait(t, 10*time.Second, func() bool {
				response, err := visitor.client.Get("https://" + visitor.address + "/siblings")
				if err != nil {
					return false
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				return err == nil && response.StatusCode == http.StatusOK && string(body) == visitor.name+" application bytes" && response.TLS != nil && len(response.TLS.PeerCertificates) > 0
			})
		}
	}
	readRuns := func() map[string]string {
		t.Helper()
		runs := map[string]string{}
		for _, service := range environment.Services {
			var run string
			if err := inspect.QueryRow(t.Context(), `SELECT id FROM control.service_runs WHERE service_id=$1 AND closed_at IS NULL`, service.ServiceId).Scan(&run); err != nil {
				t.Fatal(err)
			}
			runs[service.ServiceId] = run
		}
		return runs
	}
	assertBytes()
	runs := readRuns()
	var acknowledged time.Time
	workflowWait(t, 15*time.Second, func() bool {
		status, err := control.ListEnvironmentPublishers(t.Context(), team, project, environment.Id)
		if err != nil || len(status) != 1 || !status[0].Healthy || status[0].AcknowledgedAt == nil {
			return false
		}
		acknowledged = *status[0].AcknowledgedAt
		return true
	})
	// two later successful acknowledgements cross the runtime's real assignment
	// polling boundary. neither service may be canceled/restarted to recover a
	// replica lease invalidated by its sibling's worker startup.
	for range 2 {
		previous := acknowledged
		workflowWait(t, 15*time.Second, func() bool {
			status, err := control.ListEnvironmentPublishers(t.Context(), team, project, environment.Id)
			if err != nil || len(status) != 1 || !status[0].Healthy || status[0].ObservedRevision != environment.MutationRevision || status[0].AcknowledgedAt == nil || !status[0].AcknowledgedAt.After(previous) {
				return false
			}
			acknowledged = *status[0].AcknowledgedAt
			return true
		})
		if current := readRuns(); !reflect.DeepEqual(current, runs) {
			t.Fatal("replica lease recovery restarted an independently assigned service", current, runs)
		}
		assertBytes()
	}
	if f.groupEnrollmentRequests.Load() != 2 {
		t.Fatal("service workers unexpectedly enrolled another publisher")
	}
	for _, visitor := range visitors {
		visitor.cancel()
		select {
		case <-visitor.joined:
		case <-time.After(10 * time.Second):
			t.Fatal("native service connector did not join")
		}
	}
	stopPublisher()
	select {
	case <-publisherJoined:
	case <-time.After(20 * time.Second):
		t.Fatal("multi-service publisher did not join")
	}
}
