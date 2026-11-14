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
	"syscall"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/tnldotdev/tnl/internal/connector"
	"github.com/tnldotdev/tnl/internal/ingress"
	"github.com/tnldotdev/tnl/internal/naming/tcpport"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
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
	bin := workflowExecutable(t)
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
		"services": map[string]any{"internal": map[string]any{"protocol": "tcp"}, "shell": map[string]any{"protocol": "tcp"}},
		"deployments": map[string]any{
			"internal":   map[string]any{"targets": map[string]any{"internal": map[string]any{"address": address}}},
			"production": map[string]any{"targets": map[string]any{"shell": map[string]any{"address": address, "public": true}}},
		}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configuration, data, 0600); err != nil {
		t.Fatal(err)
	}
	var applied controlv1.AppliedProjectConfiguration
	for _, deployment := range []string{"internal", "production"} {
		if err := json.Unmarshal(cliCall(t, t.Context(), []string{"--config", configuration, "apply", "--deployment", deployment, "--state-dir", person, "--output=json"}), &applied); err != nil {
			t.Fatal(err)
		}
		service := "shell"
		if deployment == "internal" {
			service = "internal"
		}
		bootstrap := strings.TrimSpace(string(cliCall(t, t.Context(), []string{"--config", configuration, "publisher", "setup", "--deployment", deployment, "--service", service, "--members=1", "--expires-in=1h", "--state-dir", person})))
		ctx, cancel := context.WithCancel(t.Context())
		f.command(t, ctx, cancel, []string{"--no-config", "publisher", "serve", "--deployment", deployment, "--project-key", applied.ProjectKey, "--instance", "one", "--enroll-key", bootstrap, "--server", f.url, "--state-dir", f.state(t, deployment)})
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
			deployment := "production"
			if name == "internal" {
				deployment = "internal"
			}
			project, err := loadProjectConfiguration(t.Context(), cli{ConfigPath: configuration, Connect: connectCommand{Start: connectStartCommand{Deployment: deployment}}}, person)
			if err != nil {
				t.Fatal(err)
			}
			var service controlv1.Service
			workflowWait(t, 30*time.Second, func() bool {
				service, err = connector.Select(t.Context(), session.Authenticated().Control, project.Project, name, session.Identity().PersonalTeamId)
				if err != nil {
					return false
				}
				_, err = session.Authenticated().Control.SelectServiceRun(t.Context(), service.Id, device.ID)
				return err == nil
			})
			endpoint := service.Endpoint
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
			// both SSH and signal checks use this exact selected binding.
			connectArgs := []string{"--no-telemetry", "--config", configuration, "connect", name, "--deployment", deployment, "--stdio", "--state-dir", person}
			proxyArgs := append([]string{bin}, connectArgs...)
			for i := range proxyArgs {
				proxyArgs[i] = "'" + strings.ReplaceAll(proxyArgs[i], "'", "'\\''") + "'"
			}
			args := []string{"-F", "/dev/null", "-T", "-i", clientKey, "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "UserKnownHostsFile=" + known, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "CheckHostIP=no", "-o", "ProxyCommand=" + strings.Join(proxyArgs, " "), username + "@" + endpoint.Hostname}
			var before int
			if err := inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_peer_pairs`).Scan(&before); err != nil {
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
			for _, signal := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
				t.Run(signal.String(), func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
					defer cancel()
					command := exec.CommandContext(ctx, bin, connectArgs...)
					input, err := command.StdinPipe()
					if err != nil {
						t.Fatal(err)
					}
					defer input.Close()
					output, err := command.StdoutPipe()
					if err != nil {
						t.Fatal(err)
					}
					var diagnostics bytes.Buffer
					command.Stderr = &diagnostics
					if err := command.Start(); err != nil {
						t.Fatal(err)
					}
					banner := make(chan error, 1)
					go func() {
						prefix := make([]byte, len("SSH-2.0"))
						_, err := io.ReadFull(output, prefix)
						if err == nil && string(prefix) != "SSH-2.0" {
							err = fmt.Errorf("unexpected SSH banner %q", prefix)
						}
						banner <- err
					}()
					select {
					case err := <-banner:
						if err != nil {
							_ = command.Process.Kill()
							_ = command.Wait()
							t.Fatal("stdio never carried the SSH banner", err, diagnostics.String())
						}
					case <-ctx.Done():
						_ = command.Wait()
						t.Fatal("stdio never became active", ctx.Err(), diagnostics.String())
					}
					if err := command.Process.Signal(signal); err != nil {
						_ = command.Wait()
						t.Fatal(err)
					}
					if err := command.Wait(); err != nil || ctx.Err() != nil {
						t.Fatal("signal did not join the active stdio stream cleanly", err, ctx.Err(), diagnostics.String())
					}
				})
			}
			var after int
			if err := inspect.QueryRow(t.Context(), `SELECT count(*) FROM control.connector_peer_pairs pair WHERE pair.publisher_prepared_until IS NOT NULL AND (SELECT count(*) FROM control.connector_peer_pair_leg_claims claim WHERE claim.pair_id=pair.id)=2`).Scan(&after); err != nil {
				t.Fatal(err)
			}
			if after != before+4 {
				t.Fatal("SSH and signal tests did not install four independent connector owners with both relay claims")
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

func (f *cliWorkflow) connectDirectListener(t *testing.T, endpoint *controlv1.ServiceEndpoint) {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", fmt.Sprint(endpoint.Port)))
	if err != nil {
		t.Fatal(err)
	}
	server, err := ingress.New(listener, ingress.Config{PublicServicesOnly: true, PublicServices: f.publicServices, ServicePortRanges: []tcpport.Range{{First: endpoint.Port, Last: endpoint.Port}}, MaxConnections: 16, OnError: func(err error) { t.Logf("direct ingress: %v", err) }})
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
