package stream

import (
	"bytes"
	"context"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/testutil"
)

// this fixture launches the system OpenSSH daemon as an ordinary target. tnl
// never owns an SSH account, host key, shell, or forwarding permission.
func TestIntegrationExistingOpenSSHOverPrivateTCP(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	sshd, err := exec.LookPath("sshd")
	if err != nil {
		if _, err = os.Stat("/usr/sbin/sshd"); err != nil {
			t.Fatal("existing-sshd integration requires the system sshd, ssh and ssh-keygen programs")
		}
		sshd = "/usr/sbin/sshd"
	}
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) {
			directory := t.TempDir()
			hostKey, clientKey := filepath.Join(directory, "host"), filepath.Join(directory, "client")
			for _, key := range []string{hostKey, clientKey} {
				if output, err := exec.CommandContext(t.Context(), "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key).CombinedOutput(); err != nil {
					t.Fatalf("generate fixture key: %v %s", err, output)
				}
			}
			public, err := os.ReadFile(clientKey + ".pub")
			if err != nil {
				t.Fatal(err)
			}
			authorized := filepath.Join(directory, "authorized_keys")
			if err := os.WriteFile(authorized, public, 0600); err != nil {
				t.Fatal(err)
			}
			identity, err := user.Current()
			if err != nil {
				t.Fatal(err)
			}
			address := unusedOpenSSHAddress(t)
			_, port, _ := net.SplitHostPort(address)
			config := strings.Join([]string{
				"ListenAddress 127.0.0.1", "Port " + port, "HostKey " + hostKey,
				"PidFile " + filepath.Join(directory, "sshd.pid"), "AuthorizedKeysFile " + authorized,
				"StrictModes no", "UsePAM no", "PasswordAuthentication no", "KbdInteractiveAuthentication no",
				"AuthenticationMethods publickey", "PubkeyAuthentication yes", "PermitRootLogin prohibit-password",
				"AllowTcpForwarding local", "GatewayPorts no", "AllowUsers " + identity.Username,
			}, "\n") + "\n"
			configPath := filepath.Join(directory, "sshd_config")
			if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
			defer cancel()
			daemon := exec.CommandContext(ctx, sshd, "-D", "-e", "-f", configPath)
			var daemonLog bytes.Buffer
			daemon.Stderr = &daemonLog
			if err := daemon.Start(); err != nil {
				t.Fatal(err)
			}
			daemonDone := make(chan error, 1)
			go func() { daemonDone <- daemon.Wait() }()
			t.Cleanup(func() { cancel(); <-daemonDone; t.Logf("disposable sshd: %s", daemonLog.String()) })
			waitOpenSSHListener(t, ctx, address)
			fixture := newConnectorFixture(t, transport, address)
			hostPublic, err := os.ReadFile(hostKey + ".pub")
			if err != nil {
				t.Fatal(err)
			}
			alias := "tnl-private-" + fixture.run.ServiceID
			known := filepath.Join(directory, "known_hosts")
			if err := os.WriteFile(known, []byte(alias+" "+strings.TrimSpace(string(hostPublic))+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			echo, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer echo.Close()
			go func() {
				for {
					c, err := echo.Accept()
					if err != nil {
						return
					}
					go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
				}
			}()
			forward := unusedOpenSSHAddress(t)
			_, localPort, _ := net.SplitHostPort(fixture.localAddress)
			clientCtx, stopClient := context.WithCancel(ctx)
			client := exec.CommandContext(clientCtx, "ssh", "-F", "/dev/null", "-N", "-T", "-p", localPort, "-i", clientKey,
				"-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
				"-o", "UserKnownHostsFile="+known, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "CheckHostIP=no",
				"-o", "HostKeyAlias="+alias, "-o", "ExitOnForwardFailure=yes", "-L", forward+":"+echo.Addr().String(), identity.Username+"@127.0.0.1")
			var clientLog bytes.Buffer
			client.Stderr = &clientLog
			if err := client.Start(); err != nil {
				stopClient()
				t.Fatal(err)
			}
			clientDone := make(chan error, 1)
			go func() { clientDone <- client.Wait() }()
			t.Cleanup(func() { stopClient(); <-clientDone; t.Logf("OpenSSH client: %s", clientLog.String()) })
			waitOpenSSHListener(t, ctx, forward)
			connection, err := net.DialTimeout("tcp", forward, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(5 * time.Second))
			payload := []byte("existing sshd owns this authenticated forwarding channel")
			if _, err := connection.Write(payload); err != nil {
				t.Fatal(err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(connection, response); err != nil || !bytes.Equal(payload, response) {
				t.Fatalf("OpenSSH forwarded bytes: %q %v", response, err)
			}
		})
	}
}

func unusedOpenSSHAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	return address
}

func waitOpenSSHListener(t *testing.T, ctx context.Context, address string) {
	t.Helper()
	for {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("OpenSSH fixture listener %s: %v", address, ctx.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
}
