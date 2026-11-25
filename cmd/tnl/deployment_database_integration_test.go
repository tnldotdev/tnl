package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
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
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
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
	if _, err := exec.LookPath("psql"); err != nil {
		t.Fatal("deployment database workflow needs psql 16 or newer on PATH", err)
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
	project := deploymentDatabaseProject(t, f.url, team)
	var applied controlv1.AppliedProjectConfiguration
	if err := json.Unmarshal(cliCall(t, t.Context(), []string{"--config", filepath.Join(project, "tnl.json"), "apply", "--state-dir", person, "--output", "json"}), &applied); err != nil {
		t.Fatal(err)
	}
	remote := []string{"--server", f.url, "--team", team, "--project-key", applied.ProjectKey, "--state-dir", person}
	create := func(name string) controlv1.Deployment {
		t.Helper()
		args := append([]string{"--no-config", "deployment", "create", name, "--target", "orders=" + *deploymentDatabaseAddress, "--target", "admin=" + *deploymentDatabaseAddress, "--target-tls", "orders=system", "--target-tls-hostname", "orders=" + *deploymentDatabaseHostname, "--output", "json"}, remote...)
		var value controlv1.Deployment
		if err := json.Unmarshal(cliCall(t, t.Context(), args), &value); err != nil {
			t.Fatal(err)
		}
		return value
	}
	staging, sibling := create("staging"), create("sibling")
	orders := staging.Services["orders"]
	if staging.Id == sibling.Id || orders.Id == sibling.Services["orders"].Id {
		t.Fatal("same logical service reused another deployment's identity")
	}
	setup := append([]string{"--no-config", "publisher", "setup", "--deployment", staging.Id, "--service", "orders"}, remote...)
	enrollment := strings.TrimSpace(string(cliCall(t, t.Context(), setup)))
	task := f.state(t, "database-publisher")
	publishCtx, stopPublisher := context.WithCancel(t.Context())
	_, publisherJoined := f.command(t, publishCtx, stopPublisher, []string{"--no-config", "publisher", "serve", "--server", f.url, "--project-key", applied.ProjectKey, "--deployment", staging.Id, "--enroll-key", enrollment, "--state-dir", task}, clientcontrol.ErrUnauthenticated, clientcontrol.ErrNotFound)
	var publisher controlv1.DeploymentPublisher
	workflowWait(t, 25*time.Second, func() bool {
		page, err := control.ListDeploymentPublishers(t.Context(), team, applied.ProjectKey, staging.Id, "", 10)
		if err != nil || len(page.Publishers) != 1 || !page.Publishers[0].Healthy {
			return false
		}
		publisher = page.Publishers[0]
		return true
	})
	if len(publisher.Services) != 1 || publisher.Services["orders"] != controlv1.Postgres {
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
	identity, found, err := credentialfile.SavedDeployment(profile, f.url, applied.ProjectKey, staging.Id, "default")
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
		t.Fatal("staging identity served its sibling or waited for traffic", err)
	}
	device, err := session.Store().EnsureEnrolledVisitorDevice(t.Context(), session.Identity().Identity.Id, control.EnrollVisitorDevice)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{staging.Services["admin"].Id, sibling.Services["orders"].Id} {
		if _, err := control.SelectServiceRun(t.Context(), service, device.ID); !errors.Is(err, clientcontrol.ErrNotFound) {
			t.Fatal("publisher acquired an unapproved or sibling service run", err)
		}
	}
	workflowWait(t, 25*time.Second, func() bool {
		_, err := control.SelectServiceRun(t.Context(), orders.Id, device.ID)
		return err == nil
	})
	testDeploymentDatabaseClient(t, f, project, person, session.Store(), session.Identity().Identity.Id, device.ID, orders.Id)
	listener := workflowListen(t)
	address := listener.Addr().String()
	_ = listener.Close()
	connectCtx, stopConnector := context.WithCancel(t.Context())
	connectorReady, connectorJoined := f.commandWithStop(t, connectCtx, stopConnector, []string{"--no-config", "connect", orders.Id, "--server", f.url, "--team", team, "--state-dir", person, "--listen", address}, deploymentDatabaseConnectorStop)
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
	config.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: orders.Endpoint.Hostname}
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
	cliCall(t, t.Context(), append([]string{"--no-config", "publisher", "revoke", publisher.PublisherIdentityId, "--deployment", staging.Id}, remote...))
	workflowWait(t, 20*time.Second, func() bool {
		ctx, cancel := context.WithTimeout(t.Context(), time.Second)
		defer cancel()
		_, err := database.Exec(ctx, "SELECT 1")
		return err != nil
	})
	if _, err := control.SelectServiceRun(t.Context(), orders.Id, device.ID); !errors.Is(err, clientcontrol.ErrNotFound) {
		t.Fatal("revoked publisher retained a selectable database run", err)
	}
	page, err := control.ListDeploymentPublishers(t.Context(), team, applied.ProjectKey, sibling.Id, "", 10)
	if err != nil || len(page.Publishers) != 0 {
		t.Fatal("staging setup or revocation changed sibling publisher authority", err)
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

func deploymentDatabaseProject(t *testing.T, server, team string) string {
	t.Helper()
	root := t.TempDir()
	for _, args := range [][]string{{"init", "--quiet"}, {"remote", "add", "origin", "https://example.test/database.git"}} {
		git := exec.CommandContext(t.Context(), "git", args...)
		git.Dir = root
		if output, err := git.CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	targets := map[string]any{
		"orders": map[string]string{"address": *deploymentDatabaseAddress},
		"admin":  map[string]string{"address": *deploymentDatabaseAddress},
	}
	configuration, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{
		"server": server, "team": team,
		"services": map[string]any{"orders": map[string]string{"protocol": "postgres"}, "admin": map[string]string{"protocol": "postgres"}},
		"deployments": map[string]any{
			"staging": map[string]any{"targets": targets},
			"sibling": map[string]any{"targets": targets},
		},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tnl.json"), configuration, 0600); err != nil {
		t.Fatal(err)
	}
	return root
}

func testDeploymentDatabaseClient(t *testing.T, f *cliWorkflow, project, state string, store *clientstate.Store, identity, device, service string) {
	t.Helper()
	control, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close(t.Context())
	ownerCounts := func(t *testing.T) (total, outstanding int) {
		t.Helper()
		err := control.QueryRow(t.Context(), `SELECT count(*), count(*) FILTER (WHERE pair.retired_at IS NULL OR EXISTS (
			SELECT 1 FROM control.connector_peer_pair_leg_claims claim WHERE claim.pair_id = pair.id))
			FROM control.connector_peer_pairs pair WHERE pair.service_id = $1 AND pair.subject_kind = 'human_device' AND pair.subject_id = $2`,
			service, device).Scan(&total, &outstanding)
		if err != nil {
			t.Fatal(err)
		}
		return total, outstanding
	}
	ca := filepath.Join(t.TempDir(), "root.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	binary := workflowExecutable(t)
	connect := func(ctx context.Context, args ...string) *exec.Cmd {
		command := exec.CommandContext(ctx, binary, append([]string{"connect", "orders", "--deployment", "staging"}, args...)...)
		command.Dir = project
		command.Env = append(slices.DeleteFunc(command.Environ(), func(entry string) bool {
			return strings.HasPrefix(entry, "PG") || strings.HasPrefix(entry, "TNL_")
		}), "TNL_STATE_DIR="+state, "TNL_NO_TELEMETRY=true",
			"SSL_CERT_FILE="+ca, "SSL_CERT_DIR="+filepath.Dir(ca), "LC_ALL=C", "PSQLRC="+os.DevNull,
			"PGDATABASE=tnl_fixture", "PGUSER=tnl_client", "PGPASSWORD=testpass", "PGCONNECT_TIMEOUT=10")
		// quic-go logs a warning for the inner session's virtual packet socket.
		command.Env = append(command.Env, "QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING=true")
		command.WaitDelay = 5 * time.Second
		return command
	}
	address := func(t *testing.T) string {
		t.Helper()
		port, found, err := store.ServicePort(t.Context(), identity, service)
		if err != nil || !found {
			t.Fatal("staging connector did not bind its service's loopback port", found, err)
		}
		return net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	}
	rebind := func(t *testing.T) net.Listener {
		t.Helper()
		listener, err := net.Listen("tcp4", address(t))
		if err != nil {
			t.Fatal("connector returned before releasing the listener", err)
		}
		t.Cleanup(func() { _ = listener.Close() })
		return listener
	}
	query := []string{"--client", "psql", "--", "-At", "-c", "select 1"}
	missing := filepath.Join(project, "missing-client")
	for _, test := range []struct {
		name, input, stdout, stderr string
		args                        []string
		code                        int
	}{
		{name: "client cannot start", args: []string{"--", missing}, code: 1},
		{name: "query", args: query, stdout: "1\n"},
		{name: "SQL error", args: []string{"--client", "psql", "--", "-At", "-v", "ON_ERROR_STOP=1", "-f", "-"}, input: "select 'before error';\nselect 1 / 0;\n",
			stdout: "before error\n", stderr: "psql:<stdin>:2: ERROR:  division by zero\n", code: 3},
		{name: "busy port", args: query, code: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			busy := test.name == "busy port"
			if busy {
				rebind(t) // keep the socket open for the whole failed attempt.
			}
			before, _ := ownerCounts(t)
			ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
			defer cancel()
			command := connect(ctx, test.args...)
			var stdout, stderr bytes.Buffer
			command.Stdin, command.Stdout, command.Stderr = strings.NewReader(test.input), &stdout, &stderr
			err := command.Run()
			if ctx.Err() != nil || command.ProcessState == nil || command.ProcessState.ExitCode() != test.code || stdout.String() != test.stdout {
				t.Fatalf("connect exit=%v, stdout=%q, stderr=%q", err, stdout.String(), stderr.String())
			}
			if busy || test.name == "client cannot start" {
				if !strings.HasPrefix(stderr.String(), "Error: ") {
					t.Fatalf("expected a tnl diagnostic, got %q", stderr.String())
				}
			} else if stderr.String() != test.stderr {
				t.Fatalf("stderr = %q, want %q", stderr.String(), test.stderr)
			}
			t.Logf("exit=%d, stdout=%q, stderr=%q", test.code, stdout.String(), stderr.String())
			total, outstanding := ownerCounts(t)
			wantTotal := before
			if !busy {
				wantTotal++
			}
			if outstanding != 0 || total != wantTotal {
				t.Fatalf("connector owners before = %d, after = %d, still active = %d", before, total, outstanding)
			}
			if !busy {
				rebind(t)
			}
		})
	}
	t.Run("interrupt", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
		defer cancel()
		command := connect(ctx, "--client", "psql", "--", "-At")
		command.Cancel = func() error { return command.Process.Signal(os.Interrupt) }
		read, input, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer read.Close()
		defer input.Close()
		output, write, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer output.Close()
		defer write.Close()
		deadline, _ := ctx.Deadline()
		if err := output.SetReadDeadline(deadline); err != nil {
			t.Fatal(err)
		}
		var stderr bytes.Buffer
		command.Stdin, command.Stdout, command.Stderr = read, write, &stderr
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		waited := false
		defer func() {
			if !waited {
				_ = input.Close()
				cancel()
				_ = command.Wait()
			}
		}()
		_ = read.Close()
		_ = write.Close()
		if _, err := io.WriteString(input, "select 1;\n"); err != nil {
			t.Fatal(err)
		}
		reader := bufio.NewReader(output)
		if line, err := reader.ReadString('\n'); err != nil || line != "1\n" {
			t.Fatalf("psql did not query staging before interruption: %q, %v", line, err)
		}
		if _, active := ownerCounts(t); active != 1 {
			t.Fatalf("live psql owns %d connector pairs, want 1", active)
		}
		// psql is still waiting for another command: stdin stays open until
		// after tnl has returned and the child's stdout has closed.
		if err := command.Process.Signal(os.Interrupt); err != nil {
			t.Fatal(err)
		}
		err = command.Wait()
		waited = true
		if err != nil || ctx.Err() != nil || stderr.Len() != 0 {
			t.Fatalf("connect interrupt: %v, context=%v, stderr=%q", err, ctx.Err(), stderr.String())
		}
		if _, active := ownerCounts(t); active != 0 {
			t.Fatalf("connect returned with %d active connector pairs", active)
		}
		rebind(t)
		if extra, err := reader.ReadByte(); err != io.EOF {
			t.Fatalf("client retained stdout or produced extra output: %q, %v", extra, err)
		}
		t.Log(`exit=0 after SIGINT, stdout="1\n", stderr=""`)
	})
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
	if denial, ok := err.(*tunnel.ProtocolError); ok {
		return denial != nil && denial.Code == tunnelv1.Unauthenticated
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
		{"relay denial", &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, true},
		{"relay cleanup denial", &connectorstream.CleanupError{Err: &tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}}, false},
		{"relay denial with physical failure", errors.Join(&tunnel.ProtocolError{Code: tunnelv1.Unauthenticated}, unrelated), false},
		{"unavailable relay", &tunnel.ProtocolError{Code: tunnelv1.Unavailable}, false},
		{"different denial", &clientcontrol.ProblemError{Status: http.StatusUnauthorized, Problem: controlv1.Problem{Code: controlv1.Forbidden}}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := deploymentDatabaseConnectorStop(test.err); got != test.want {
				t.Fatalf("accepted stop=%t, want %t: %v", got, test.want, test.err)
			}
		})
	}
}
