package main

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

// use the real CLI as OpenSSH's ProxyCommand, with control, ingress, relay and
// publisher admission on both paths. the disposable sshd owns its keys/account.
func TestIntegrationCLIConnectSSHStdio(t *testing.T) {
	if !cliWorkflowInChild(t) {
		return
	}
	f := newCLIWorkflow(t)
	person := f.state(t, "person")
	f.loginPerson(t, person)
	session, err := openTeamSession(t.Context(), remoteFlags{ServerURL: f.url, StateDir: person}, "ssh workflow", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	root := t.TempDir()
	bin := filepath.Join(root, "tnl")
	repository, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	build := exec.CommandContext(t.Context(), "go", "build", "-buildvcs=false", "-o", bin, "./cmd/tnl")
	build.Dir = repository
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v\n%s", err, output)
	}
	ca := filepath.Join(root, "ca.pem")
	if err := os.WriteFile(ca, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.issuer.Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", ca)
	for _, args := range [][]string{{"init", "--quiet", root}, {"-C", root, "remote", "add", "origin", "https://example.test/cli/ssh.git"}} {
		if output, err := exec.CommandContext(t.Context(), "git", args...).CombinedOutput(); err != nil {
			t.Fatalf("Git fixture: %v %s", err, output)
		}
	}
	address, clientKey, hostPublic, username := connectWorkflowSSHD(t, root)
	configuration := filepath.Join(root, "tnl.json")
	data, err := json.Marshal(map[string]any{"version": 1, "tnl": map[string]any{"server": f.url, "team": session.Identity().PersonalTeamId,
		"publishers": map[string]any{"internal": map[string]any{}, "production": map[string]any{"public": true}},
		"services": map[string]any{
			"internal": map[string]any{"publisher": "internal", "protocol": "tcp", "target": map[string]any{"type": "address", "address": address}},
			"shell":    map[string]any{"publisher": "production", "protocol": "tcp", "target": map[string]any{"type": "address", "address": address}},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	var applied controlv1.AppliedProjectConfiguration
	if err := json.Unmarshal(cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--state-dir", person, "--output=json"}), &applied); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"internal", "production"} {
		bootstrap := strings.TrimSpace(string(cliCall(t, t.Context(), []string{"--config", configuration, "publisher", "enroll", "--group", group, "--members=1", "--expires-in=1h", "--state-dir", person})))
		ctx, cancel := context.WithCancel(t.Context())
		f.command(t, ctx, cancel, []string{"--no-config", "publisher", "serve", "--group", group, "--project-key", applied.ProjectKey, "--instance", "one", "--enroll-key", bootstrap, "--server", f.url, "--state-dir", f.state(t, group)})
	}
	project, err := loadProjectConfiguration(t.Context(), cli{ConfigPath: configuration}, person)
	if err != nil {
		t.Fatal(err)
	}
	inspect, err := pgx.Connect(t.Context(), f.databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer inspect.Close(t.Context())
	device, err := session.Store().EnsureEnrolledVisitorDevice(t.Context(), session.Identity().Identity.Id, session.Authenticated().Control.EnrollVisitorDevice)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"internal", "shell"} {
		t.Run(name, func(t *testing.T) {
			var service controlv1.PrivateService
			workflowWait(t, 30*time.Second, func() bool {
				service, err = connector.Select(t.Context(), session.Authenticated().Control, project.Project, name, session.Identity().PersonalTeamId)
				if err != nil {
					return false
				}
				_, err = session.Authenticated().Control.SelectPrivateServiceRun(t.Context(), service.Id, device.ID)
				return err == nil
			})
			endpoint := service.ManagedTls
			if endpoint.Public {
				f.connectDirectListener(t, endpoint)
			}
			// this Linux-only workflow runs inside its disposable runner. only its
			// hosts file changes; the CLI still receives the real managed hostname.
			hosts, err := os.ReadFile("/etc/hosts")
			if err != nil {
				t.Fatal(err)
			}
			ip := "127.0.0.1"
			writeConnectWorkflowHosts(t, append(bytes.Clone(hosts), []byte("\n"+ip+" "+endpoint.Hostname+"\n")...))
			t.Cleanup(func() { writeConnectWorkflowHosts(t, hosts) })
			known := filepath.Join(t.TempDir(), "known_hosts")
			if err := os.WriteFile(known, []byte(endpoint.Hostname+" "+hostPublic+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			proxyArgs := []string{bin, "--no-telemetry", "--config", configuration, "connect", name, "--stdio", "--state-dir", person}
			for i := range proxyArgs {
				proxyArgs[i] = "'" + strings.ReplaceAll(proxyArgs[i], "'", "'\\''") + "'"
			}
			args := []string{"-F", "/dev/null", "-T", "-i", clientKey, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "CheckHostIP=no", "-o", "ProxyCommand=" + strings.Join(proxyArgs, " "), username + "@" + endpoint.Hostname}
			var before int
			if err := inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.private_connector_sessions`).Scan(&before); err != nil {
				t.Fatal(err)
			}
			for _, remote := range []string{"cat", "printf 'remote-exit'; exit 7"} {
				ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
				command := exec.CommandContext(ctx, "ssh", append(args, remote)...)
				command.Stdin = strings.NewReader("exact stdin through SSH\n")
				var stdout, stderr bytes.Buffer
				command.Stdout, command.Stderr = &stdout, &stderr
				command.WaitDelay = time.Second
				err := command.Run()
				cancel()
				if remote == "cat" {
					if err != nil || stdout.String() != "exact stdin through SSH\n" {
						t.Fatalf("SSH stdin/stdout: %v %q\n%s", err, stdout.String(), stderr.String())
					}
				} else {
					var exit *exec.ExitError
					if !errors.As(err, &exit) || exit.ExitCode() != 7 || stdout.String() != "remote-exit" {
						t.Fatalf("remote exit/EOF: %v %q\n%s", err, stdout.String(), stderr.String())
					}
				}
			}
			var after int
			if err := inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.private_connector_sessions`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after <= before {
				t.Fatal("SSH skipped connector authentication")
			}
		})
	}
	// an open SSH input pipe must never turn a missing sign-in into a prompt or
	// a read from that pipe. authentication is an explicit, separate command.
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, bin, "--no-telemetry", "--no-config", "connect", "shell", "--stdio", "--server", f.url, "--state-dir", f.state(t, "signed-out"))
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	defer stdin.Close()
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	if err := command.Run(); err == nil || ctx.Err() != nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "run tnl auth") || !strings.Contains(stderr.String(), "login again") {
		t.Fatalf("stdio login consumed input or omitted explicit action: %v\n%s", err, stderr.String())
	}
}

func writeConnectWorkflowHosts(t *testing.T, data []byte) {
	t.Helper()
	if err := os.WriteFile("/etc/hosts", data, 0644); err == nil {
		return
	} else if !errors.Is(err, os.ErrPermission) {
		t.Fatal(err)
	}
	// CI grants passwordless sudo for fixture setup. tnl and sshd continue to
	// run as the test user; only this isolated hosts-file update is privileged.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "sudo", "-n", "tee", "/etc/hosts")
	command.Stdin = bytes.NewReader(data)
	command.Stdout = io.Discard
	var diagnostics bytes.Buffer
	command.Stderr = &diagnostics
	if err := command.Run(); err != nil {
		t.Fatalf("isolated Linux hosts fixture requires writable /etc/hosts or passwordless sudo: %v %s", err, diagnostics.String())
	}
}

func (f *cliWorkflow) connectDirectListener(t *testing.T, endpoint *controlv1.ManagedServiceTLS) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(endpoint.Port)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{DirectOnly: true, DirectConnector: f.directConnector, ServicePortRanges: []tcpport.Range{{First: endpoint.Port, Last: endpoint.Port}}, MaxConnections: 16, OnError: func(err error) { t.Logf("direct ingress: %v", err) }})
	if err != nil {
		_ = listener.Close()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve() }()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Drain(ctx)
		if err := <-done; err != nil {
			t.Error(err)
		}
	})
}

func connectWorkflowSSHD(t *testing.T, root string) (address, clientKey, hostPublic, username string) {
	t.Helper()
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		t.Fatal("CLI SSH workflow requires system sshd", err)
	}
	hostKey := filepath.Join(root, "host")
	clientKey = filepath.Join(root, "client")
	for _, key := range []string{hostKey, clientKey} {
		if output, err := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
			t.Fatalf("fixture key: %v %s", err, output)
		}
	}
	public, err := os.ReadFile(clientKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	authorized := filepath.Join(root, "authorized_keys")
	if err := os.WriteFile(authorized, public, 0600); err != nil {
		t.Fatal(err)
	}
	public, err = os.ReadFile(hostKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	hostPublic = strings.TrimSpace(string(public))
	identity, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	username = identity.Username
	listener := workflowListen(t)
	address = listener.Addr().String()
	_ = listener.Close()
	_, port, _ := net.SplitHostPort(address)
	configuration := filepath.Join(root, "sshd_config")
	data := strings.Join([]string{"ListenAddress 127.0.0.1", "Port " + port, "HostKey " + hostKey, "PidFile " + filepath.Join(root, "sshd.pid"), "AuthorizedKeysFile " + authorized, "StrictModes no", "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no", "AuthenticationMethods publickey", "PubkeyAuthentication yes", "PermitRootLogin prohibit-password", "AllowUsers " + username}, "\n") + "\n"
	if err := os.WriteFile(configuration, []byte(data), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	daemon := exec.CommandContext(ctx, sshd, "-D", "-e", "-f", configuration)
	var log bytes.Buffer
	daemon.Stderr = &log
	if err := daemon.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- daemon.Wait() }()
	t.Cleanup(func() { cancel(); <-done; t.Logf("disposable sshd: %s", log.String()) })
	workflowWait(t, 5*time.Second, func() bool {
		c, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err != nil {
			return false
		}
		_ = c.Close()
		return true
	})
	return
}
