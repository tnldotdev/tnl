package publisher

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/sshclient"
	"github.com/tnldotdev/tnl/internal/testutil"
	"golang.org/x/crypto/ssh"
)

var (
	managedSSHBinary       = flag.String("tnl-test-managed-ssh-binary", "", "Linux tnl binary mounted in the disposable container")
	managedSSHProxyAddress = flag.String("tnl-test-managed-ssh-proxy-address", "", "publisher fixture TLS address")
	managedSSHProxyCert    = flag.String("tnl-test-managed-ssh-proxy-cert", "", "visitor fixture certificate path")
	managedSSHProxyKey     = flag.String("tnl-test-managed-ssh-proxy-key", "", "visitor fixture private key path")
	managedSSHProxyRoots   = flag.String("tnl-test-managed-ssh-proxy-roots", "", "publisher fixture trust roots path")
)

// OpenSSH needs a stdio ProxyCommand for the outer TLS connection. use the
// production transport with fixture roots, without parsing or rewriting SSH.
func TestManagedSSHPublisherProxy(t *testing.T) {
	if os.Args[len(os.Args)-1] != "--managed-ssh-publisher-proxy" {
		return
	}
	certificate, err := tls.LoadX509KeyPair(*managedSSHProxyCert, *managedSSHProxyKey)
	if err != nil {
		os.Exit(1)
	}
	rootPEM, err := os.ReadFile(*managedSSHProxyRoots)
	if err != nil {
		os.Exit(1)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootPEM) {
		os.Exit(1)
	}
	err = sshclient.ConnectWithOptions(context.Background(), sshclient.ConnectOptions{
		Address: *managedSSHProxyAddress, ServerName: "shell.example", Certificate: certificate, RootCAs: roots,
	}, os.Stdin, os.Stdout)
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestIntegrationManagedSSHPublisherRoot(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *managedSSHRootUser == "" || *managedSSHBinary == "" {
		t.Skip("requires the explicit managed SSH root container target")
	}
	if _, err := os.Stat("/run/tnl-managedssh-fixture"); err != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("requires root inside the disposable managed SSH account fixture")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !bytes.Contains(status, []byte("NoNewPrivs:\t1")) {
		t.Fatal("requires the container's no-new-privileges boundary")
	}
	account, err := user.Lookup(*managedSSHRootUser)
	if err != nil || account.Uid == "0" {
		t.Fatal("requires an existing nonroot fixture account")
	}
	certificate := publicURLTestCertificate(t, "shell.example")
	visitorCertificate := publicURLTestCertificate(t, "visitor.example")
	fingerprint := sha256.Sum256(visitorCertificate.Certificate[0])
	config := managedSSHTestConfig(t)
	config.Certificate = certificate
	config.SSH.Runner = &managedssh.Runner{Executable: *managedSSHBinary}
	var revoked atomic.Bool
	var accountChecks, promotions atomic.Int32
	config.AuthorizeSSHVisitor = func(_ context.Context, visitor Visitor, state tls.ConnectionState, username string) (controlclient.SSHVisitorDecision, error) {
		if visitor.Run.PublishRunID != config.PublishRunID || visitor.Source.String() != "192.0.2.10:40001" || !state.HandshakeComplete || len(state.PeerCertificates) != 1 || sha256.Sum256(state.PeerCertificates[0].Raw) != fingerprint || revoked.Load() {
			return controlclient.SSHVisitorDecision{}, livevisitor.ErrDenied
		}
		if username != "" {
			accountChecks.Add(1)
			if username != *managedSSHRootUser {
				return controlclient.SSHVisitorDecision{}, livevisitor.ErrDenied
			}
		}
		return controlclient.SSHVisitorDecision{IdentityID: "visitor-identity", PublicURLID: config.PublicURLID, SSHUser: username, ValidUntil: time.Now().Add(4 * time.Second)}, nil
	}
	config.PromoteVisitor = func(context.Context, Visitor) error { promotions.Add(1); return nil }
	_, address := listenManagedSSHPublisher(t, config)
	connect := func(username string, proof tls.Certificate, key ssh.PublicKey) (*ssh.Client, error) {
		c, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			return nil, err
		}
		_ = c.SetDeadline(time.Now().Add(3 * time.Second))
		secured := tls.Client(c, managedSSHTestTLS(t, certificate, proof))
		if err := secured.HandshakeContext(t.Context()); err != nil {
			_ = c.Close()
			return nil, err
		}
		conn, channels, requests, err := ssh.NewClientConn(secured, "shell.example:2222", &ssh.ClientConfig{
			User: username, HostKeyCallback: ssh.FixedHostKey(key), HostKeyAlgorithms: []string{ssh.KeyAlgoED25519},
		})
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		_ = c.SetDeadline(time.Time{})
		return ssh.NewClient(conn, channels, requests), nil
	}
	for _, test := range []struct {
		name  string
		user  string
		proof tls.Certificate
		key   ssh.PublicKey
	}{
		{"no certificate", *managedSSHRootUser, tls.Certificate{}, config.SSH.HostKey.PublicKey()},
		{"no grant", *managedSSHRootUser, certificate, config.SSH.HostKey.PublicKey()},
		{"root account", "root", visitorCertificate, config.SSH.HostKey.PublicKey()},
		{"account outside host allowlist", "not-allowed", visitorCertificate, config.SSH.HostKey.PublicKey()},
		{"wrong SSH host key", *managedSSHRootUser, visitorCertificate, managedSSHTestSigner(t).PublicKey()},
	} {
		t.Run(test.name, func(t *testing.T) {
			if client, err := connect(test.user, test.proof, test.key); err == nil {
				_ = client.Close()
				t.Fatal("accepted a denied SSH connection")
			}
		})
	}
	t.Run("OpenSSH command uses production tnl child", func(t *testing.T) {
		directory := t.TempDir()
		certPath, keyPath := writeManagedSSHTestCertificate(t, directory, visitorCertificate)
		rootsPath := filepath.Join(directory, "roots.pem")
		if err := os.WriteFile(rootsPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
			t.Fatal(err)
		}
		knownHosts := filepath.Join(directory, "known_hosts")
		if err := os.WriteFile(knownHosts, []byte("shell.example "+strings.TrimSpace(string(ssh.MarshalAuthorizedKey(config.SSH.HostKey.PublicKey())))+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		proxy := []string{executable, "-test.run=^TestManagedSSHPublisherProxy$", "-tnl-test-managed-ssh-proxy-address=" + address,
			"-tnl-test-managed-ssh-proxy-cert=" + certPath, "-tnl-test-managed-ssh-proxy-key=" + keyPath, "-tnl-test-managed-ssh-proxy-roots=" + rootsPath, "--", "--managed-ssh-publisher-proxy"}
		for i, arg := range proxy {
			proxy[i] = "'" + strings.ReplaceAll(arg, "'", "'\"'\"'") + "'"
		}
		args := []string{"-F", "none", "-o", "ProxyCommand=" + strings.Join(proxy, " "), "-o", "BatchMode=yes", "-o", "PreferredAuthentications=none",
			"-o", "UserKnownHostsFile=" + knownHosts, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlgorithms=ssh-ed25519",
			"-l", *managedSSHRootUser, "--", "shell.example", "id -u; id -g; pwd; printf managed-ssh-ok"}
		ctx, cancel := context.WithTimeout(t.Context(), 8*time.Second)
		defer cancel()
		output, err := exec.CommandContext(ctx, "ssh", args...).CombinedOutput()
		want := fmt.Sprintf("%s\n%s\n%s\nmanaged-ssh-ok", account.Uid, account.Gid, account.HomeDir)
		if err != nil || string(output) != want {
			t.Fatalf("OpenSSH through publisher and production child = %q, %v; want %q", output, err, want)
		}
	})
	t.Run("active command and local forward close on revocation", func(t *testing.T) {
		client, err := connect(*managedSSHRootUser, visitorCertificate, config.SSH.HostKey.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		session, err := client.NewSession()
		if err != nil {
			t.Fatal(err)
		}
		defer session.Close()
		out, err := session.StdoutPipe()
		if err != nil {
			t.Fatal(err)
		}
		if err := session.Start("printf ready; exec sleep 60"); err != nil {
			t.Fatal(err)
		}
		var ready [5]byte
		if _, err := io.ReadFull(out, ready[:]); err != nil || string(ready[:]) != "ready" {
			t.Fatal("nonroot command did not start", err)
		}
		target, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer target.Close()
		closed := make(chan error, 1)
		go func() {
			c, err := target.Accept()
			if err != nil {
				closed <- err
				return
			}
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(6 * time.Second))
			var message [7]byte
			_, err = io.ReadFull(c, message[:])
			if err == nil && string(message[:]) == "forward" {
				_, err = c.Write(message[:])
			}
			if err == nil {
				_, err = c.Read(make([]byte, 1))
			}
			closed <- err
		}()
		forward, err := client.Dial("tcp", target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer forward.Close()
		if _, err := io.WriteString(forward, "forward"); err != nil {
			t.Fatal(err)
		}
		var echo [7]byte
		if _, err := io.ReadFull(forward, echo[:]); err != nil || string(echo[:]) != "forward" {
			t.Fatal("nonroot local forward failed", err)
		}
		revoked.Store(true)
		joined := make(chan error, 1)
		go func() { joined <- client.Wait() }()
		if err := awaitPublisherTest(t, joined); err == nil {
			t.Fatal("revocation did not terminate the SSH connection")
		}
		if err := awaitPublisherTest(t, closed); !errors.Is(err, io.EOF) {
			t.Fatalf("revocation did not close the backend forwarding socket: %v", err)
		}
		if err := session.Wait(); err == nil {
			t.Fatal("revocation left the command session alive")
		}
	})
	if os.Getuid() != 0 || os.Geteuid() != 0 || accountChecks.Load() < 2 || promotions.Load() < 2 {
		t.Fatalf("publisher identity/admission changed: uid=%d checks=%d promotions=%d", os.Getuid(), accountChecks.Load(), promotions.Load())
	}
	t.Log("verified publisher mTLS, no-cert/no-grant/account/host-key rejection, real OpenSSH command, production tnl root-to-user child, local forwarding, and active revocation")
}

func writeManagedSSHTestCertificate(t *testing.T, directory string, certificate tls.Certificate) (string, string) {
	t.Helper()
	private, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	certPath, keyPath := filepath.Join(directory, "visitor.pem"), filepath.Join(directory, "visitor-key.pem")
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}), 0600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath
}
