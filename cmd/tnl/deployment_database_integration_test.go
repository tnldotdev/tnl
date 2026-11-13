package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	clientstate "github.com/tnldotdev/tnl/internal/client/state"
	connectorstream "github.com/tnldotdev/tnl/internal/connector/stream"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher/identity/credentialfile"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var (
	deploymentDatabaseAddress  = flag.String("tnl-test-postgres-address", "", "disposable verified TLS database target")
	deploymentDatabaseCA       = flag.String("tnl-test-postgres-ca-file", "", "disposable database CA")
	deploymentDatabaseHostname = flag.String("tnl-test-postgres-tls-hostname", "", "disposable database certificate hostname")
	_                          = flag.String("tnl-test-postgres-client-container", "", "disposable database container owned by the Task")
)

func TestDeploymentDatabaseWorkflow(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	if *deploymentDatabaseAddress == "" || *deploymentDatabaseCA == "" || *deploymentDatabaseHostname == "" {
		t.Fatal("run task go:test:integration:deployment-database for the isolated TLS target")
	}
	ca, err := os.ReadFile(*deploymentDatabaseCA)
	if err != nil {
		t.Fatal(err)
	}
	f := newCLIWorkflow(t, ca)
	person := f.state(t, "database-manager")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "deployment database workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	team, control := session.Identity().PersonalTeamId, session.Authenticated().Control
	_, err = control.ApplyProjectConfiguration(t.Context(), "database", controlv1.ApplyProjectConfigurationRequest{
		Deployment: "local", TeamId: team, Source: &controlv1.GitProjectSource{GitOrigin: "https://example.test/database.git", ConfigurationPath: "tnl.yml"},
		ServiceDeclarations: controlv1.ProjectServiceDeclarations{"db": "postgres", "admin": "postgres"},
		Configuration:       controlv1.ProjectConfiguration{Services: map[string]controlv1.ProjectServiceConfiguration{}},
	})
	if err != nil {
		t.Fatal(err)
	}
	remote := []string{"--server", f.url, "--team", team, "--project-key", "database", "--state-dir", person}
	create := func(name string) controlv1.Deployment {
		t.Helper()
		args := append([]string{"--no-config", "deployment", "create", name, "--target", "db=" + *deploymentDatabaseAddress, "--target", "admin=" + *deploymentDatabaseAddress, "--target-tls", "db=system", "--target-tls-hostname", "db=" + *deploymentDatabaseHostname, "--output", "json"}, remote...)
		var value controlv1.Deployment
		if err := json.Unmarshal(cliCall(t, t.Context(), args), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	customer, sibling := create("customer"), create("sibling")
	if customer.Id == sibling.Id || customer.Services["db"].Id == sibling.Services["db"].Id {
		t.Fatal("same logical service reused another deployment's identity")
	}
	setup := append([]string{"--no-config", "publisher", "setup", "--deployment", customer.Id, "--service", "db"}, remote...)
	enrollment := strings.TrimSpace(string(cliCall(t, t.Context(), setup)))
	task := f.state(t, "database-publisher")
	publishCtx, stopPublisher := context.WithCancel(t.Context())
	_, publisherJoined := f.command(t, publishCtx, stopPublisher, []string{"--no-config", "publisher", "serve", "--server", f.url, "--project-key", "database", "--deployment", customer.Id, "--enroll-key", enrollment, "--state-dir", task}, clientcontrol.ErrUnauthenticated, clientcontrol.ErrNotFound)
	var publisher controlv1.DeploymentPublisher
	workflowWait(t, 25*time.Second, func() bool {
		page, err := control.ListDeploymentPublishers(t.Context(), team, "database", customer.Id, "", 10)
		if err != nil || len(page.Publishers) != 1 || !page.Publishers[0].Healthy {
			return false
		}
		publisher = page.Publishers[0]
		return true
	})
	if len(publisher.Services) != 1 || publisher.Services["db"] != controlv1.Postgres {
		t.Fatal("setup approved the unrelated admin binding")
	}
	state, err := clientstate.Open(t.Context(), task)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := state.Server(t.Context(), f.url)
	if err != nil {
		t.Fatal(err)
	}
	identity, found, err := credentialfile.SavedDeployment(profile, f.url, "database", customer.Id, "default")
	closeErr := state.Close()
	if err != nil || closeErr != nil || !found {
		t.Fatal("native publisher did not retain its exact identity", err, closeErr)
	}
	credential := filepath.Join(t.TempDir(), "publisher.json")
	if err := credentialfile.WriteDeployment(credential, identity); err != nil {
		t.Fatal(err)
	}
	denialCtx, stopDenial := context.WithTimeout(t.Context(), 5*time.Second)
	err = run(denialCtx, []string{"--no-config", "--no-telemetry", "publisher", "serve", "--deployment", sibling.Id, "--identity-file", credential, "--state-dir", f.state(t, "wrong-deployment")}, io.Discard, io.Discard)
	stopDenial()
	if !errors.Is(err, credentialfile.ErrInvalid) {
		t.Fatal("customer identity served its sibling or waited for traffic", err)
	}
	device, err := session.Store().EnsureEnrolledVisitorDevice(t.Context(), session.Identity().Identity.Id, control.EnrollVisitorDevice)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{customer.Services["admin"].Id, sibling.Services["db"].Id} {
		if _, err := control.SelectServiceRun(t.Context(), service, device.ID); !errors.Is(err, clientcontrol.ErrNotFound) {
			t.Fatal("publisher acquired an unapproved or sibling service run", err)
		}
	}
	listener := workflowListen(t)
	address := listener.Addr().String()
	_ = listener.Close()
	connectCtx, stopConnector := context.WithCancel(t.Context())
	connectorReady, connectorJoined := f.commandWithStop(t, connectCtx, stopConnector, []string{"--no-config", "connect", customer.Services["db"].Id, "--server", f.url, "--team", team, "--state-dir", person, "--listen", address}, deploymentDatabaseConnectorStop)
	select {
	case <-connectorReady:
	case <-connectorJoined:
		t.Fatal("database connector ended before readiness")
	case <-time.After(25 * time.Second):
		t.Fatal("database connector did not become ready")
	}
	host, portText, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	// visitor and target TLS have separate certificates; database authentication
	// must not bind the visitor certificate to the target's TLS channel.
	config, err := pgx.ParseConfig("postgres://tnl_client:testpass@127.0.0.1/tnl_fixture?sslmode=require&channel_binding=disable")
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(f.issuer)
	config.Host, config.Port = host, uint16(port)
	config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: customer.Services["db"].Endpoint.Hostname}
	config.Fallbacks = nil
	var database *pgx.Conn
	lastConnectError := ""
	workflowWait(t, 25*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		database, err = pgx.ConnectConfig(ctx, config)
		if err != nil && err.Error() != lastConnectError {
			t.Logf("disposable database connect: %v", err)
			lastConnectError = err.Error()
		}
		return err == nil
	})
	defer func() { _ = database.Close(context.Background()) }()
	var answer int
	var targetTLS bool
	if err := database.QueryRow(t.Context(), `SELECT 42, ssl FROM pg_stat_ssl WHERE pid=pg_backend_pid()`).Scan(&answer, &targetTLS); err != nil || answer != 42 || !targetTLS {
		t.Fatal("real database query or verified publisher-to-target TLS failed", answer, targetTLS, err)
	}
	cliCall(t, t.Context(), append([]string{"--no-config", "publisher", "revoke", publisher.PublisherIdentityId, "--deployment", customer.Id}, remote...))
	workflowWait(t, 20*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, err := database.Exec(ctx, "SELECT 1")
		return err != nil
	})
	if _, err := control.SelectServiceRun(t.Context(), customer.Services["db"].Id, device.ID); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("revoked publisher retained a selectable database run", err)
	}
	page, err := control.ListDeploymentPublishers(t.Context(), team, "database", sibling.Id, "", 10)
	if err != nil || len(page.Publishers) != 0 {
		t.Fatal("customer setup or revocation changed sibling publisher authority", err)
	}
	stopConnector()
	stopPublisher()
	for _, joined := range []<-chan struct{}{connectorJoined, publisherJoined} {
		select {
		case <-joined:
		case <-time.After(15 * time.Second):
			t.Fatal("database workflow owner did not join")
		}
	}
}

// revocation can retire the run before selection or deny its established pair.
// accept only those leaves, never an independent joined cleanup failure.
func deploymentDatabaseConnectorStop(err error) bool {
	if err == nil {
		return true
	}
	if _, cleanup := err.(*connectorstream.CleanupError); cleanup {
		return false
	}
	if err == context.Canceled || err == clientcontrol.ErrNotFound || err == connectorstream.ErrServiceConnection {
		return true
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, child := range wrapped.Unwrap() {
			if !deploymentDatabaseConnectorStop(child) {
				return false
			}
		}
		return true
	case interface{ Unwrap() error }:
		return deploymentDatabaseConnectorStop(wrapped.Unwrap())
	}
	if problem, ok := err.(*clientcontrol.ProblemError); ok {
		return problem.Status == http.StatusForbidden && problem.Problem.Code == controlv1.Forbidden
	}
	return false
}

func TestDeploymentDatabaseConnectorStopPreservesFailures(t *testing.T) {
	denied := &clientcontrol.ProblemError{Status: http.StatusForbidden, Problem: controlv1.Problem{Code: controlv1.Forbidden}}
	revoked := failure.Wrap("authorize service connection", failure.ConnectAccessRequired,
		errors.Join(connectorstream.ErrServiceConnection, failure.Wrap("request control API", failure.ServerDenied, denied)))
	unrelated := errors.New("independent cleanup failure")
	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{"revoked", revoked, true},
		{"cancelled", context.Canceled, true},
		{"missing run", clientcontrol.ErrNotFound, true},
		{"joined failure", errors.Join(revoked, unrelated), false},
		{"cancelled failure", errors.Join(context.Canceled, unrelated), false},
		{"cleanup denial", errors.Join(revoked, &connectorstream.CleanupError{Err: denied}), false},
		{"different denial", &clientcontrol.ProblemError{Status: http.StatusUnauthorized, Problem: controlv1.Problem{Code: controlv1.Forbidden}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := deploymentDatabaseConnectorStop(test.err); got != test.want {
				t.Fatalf("accepted stop=%t, want %t: %v", got, test.want, test.err)
			}
		})
	}
}
