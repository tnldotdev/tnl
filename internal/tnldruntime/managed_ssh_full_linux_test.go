package tnldruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/testutil"
	"github.com/tnldotdev/tnl/internal/tnldconfig"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var (
	managedSSHFullUser   = flag.String("tnl-test-managed-ssh-root-user", "", "nonroot account in the disposable managed SSH fixture")
	managedSSHFullOther  = flag.String("tnl-test-managed-ssh-other-user", "", "second allowed account without a visitor grant")
	managedSSHFullBinary = flag.String("tnl-test-managed-ssh-binary", "", "production Linux tnl binary in the disposable managed SSH fixture")
)

// this proof starts at the public cli and ends in the production root-to-user
// child. address forwarding and private ca trust are fixture plumbing; control,
// acme, both relay transports, visitor certificates, and account grants are real.
func TestIntegrationFullManagedSSH(t *testing.T) {
	testutil.RequireTestTier(t, testutil.TestTierIntegration)
	if *managedSSHFullUser == "" || *managedSSHFullOther == "" || *managedSSHFullBinary == "" {
		t.Skip("requires the explicit testdata/managed-ssh-full/run.sh container fixture")
	}
	if _, err := os.Stat("/run/tnl-managedssh-fixture"); err != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("requires root inside the disposable managed SSH account fixture")
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil || !bytes.Contains(status, []byte("NoNewPrivs:\t1")) {
		t.Fatal("requires the container's no-new-privileges boundary")
	}
	account, err := user.Lookup(*managedSSHFullUser)
	if err != nil || account.Uid == "0" {
		t.Fatal("requires an existing named nonroot fixture account")
	}
	other, err := user.Lookup(*managedSSHFullOther)
	if err != nil || other.Uid == "0" || other.Uid == account.Uid {
		t.Fatal("requires a distinct second nonroot fixture account")
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	for _, transport := range []string{"quic", "tls-tcp"} {
		t.Run(transport, func(t *testing.T) { fullManagedSSH(t, transport, account, other) })
	}
	after, err := os.Getgroups()
	if err != nil || os.Getuid() != 0 || os.Geteuid() != 0 || !slices.Equal(groups, after) {
		t.Fatal("the root publisher changed its own credentials")
	}
}

type managedSSHFullAuthorization struct {
	scope       controlclient.VisitorCertificateScope
	fingerprint [32]byte
	username    string
	decision    controlclient.SSHVisitorDecision
	err         error
}

// observe decisions without replacing the real control client's authorization.
type managedSSHFullControl struct {
	*integrationScopedRunControl
	mu       sync.Mutex
	observed []managedSSHFullAuthorization
}

func (c *managedSSHFullControl) AuthorizeSSHVisitor(ctx context.Context, scope controlclient.VisitorCertificateScope, state tls.ConnectionState, username string) (controlclient.SSHVisitorDecision, error) {
	decision, err := c.Client.AuthorizeSSHVisitor(ctx, scope, state, username)
	observation := managedSSHFullAuthorization{scope: scope, username: username, decision: decision, err: err}
	if state.HandshakeComplete && len(state.PeerCertificates) == 1 {
		observation.fingerprint = sha256.Sum256(state.PeerCertificates[0].Raw)
	}
	c.mu.Lock()
	c.observed = append(c.observed, observation)
	c.mu.Unlock()
	return decision, err
}

func (c *managedSSHFullControl) latest(t *testing.T, username string) managedSSHFullAuthorization {
	t.Helper()
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, observation := range slices.Backward(c.observed) {
		if observation.username == username {
			return observation
		}
	}
	t.Fatalf("publisher did not ask real control about account %q", username)
	return managedSSHFullAuthorization{}
}

func fullManagedSSH(t *testing.T, transport string, account, other *user.User) {
	seed := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	f := newSplitPublishFixtureWithOptions(t, "full-shell", splitPublishOptions{proxyIngress: true, configureProcess: func(c *tnldconfig.Config) {
		if c.Role == tnldconfig.RoleControl {
			c.VisitorIssuerSeed = seed
		}
		if c.Role == tnldconfig.RoleIngress {
			c.RequireProxyHeader = true
		}
	}})
	listen, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listen.Close() })
	publicPort := listen.Addr().(*net.TCPAddr).Port
	if _, err := f.inspect.ExecContext(t.Context(), `UPDATE control.ingress_pools SET ipv4_address='127.0.0.1'::inet,state='enabled' WHERE id='ingress-a'`); err != nil {
		t.Fatal(err)
	}
	if _, err := f.inspect.ExecContext(t.Context(), `INSERT INTO control.ingress_pool_ports(ingress_pool_id,port,enabled) VALUES ('ingress-a',$1,true)`, publicPort); err != nil {
		t.Fatal(err)
	}
	startManagedSSHFullProxy(t, listen, f.ingressConfig.IngressListen, uint16(publicPort))
	controlListen, err := net.Listen("tcp4", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	startManagedSSHFullProxy(t, controlListen, f.controlConfig.ControlListen, 0)
	managedSSHFullHosts(t, "control.split.integration.test", f.identity.hostname)

	private, _, err := managedssh.GenerateHostKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := managedssh.ParseHostKey(private)
	if err != nil {
		t.Fatal(err)
	}
	quic, tcp := f.connectors()
	if transport == "quic" {
		tcp, _ = disabledIntegrationConnector("full managed SSH proof selects QUIC")
	} else {
		quic, _ = disabledIntegrationConnector("full managed SSH proof selects TLS/TCP")
	}
	publication := f.identity.publisherConfig("", quic, tcp)
	publication.ServiceProtocol, publication.AccessMode = controlv1.Ssh, controlv1.Restricted
	publication.SSH = &publisher.SSHConfig{HostKey: signer, Users: []string{account.Username, other.Username}, Runner: &managedssh.Runner{Executable: *managedSSHFullBinary}}
	control := &managedSSHFullControl{integrationScopedRunControl: publication.Control.(*integrationScopedRunControl)}
	publication.Control = control
	handle := startOwnedIntegrationPublisher(t, f.owner, publication, func() string { return integrationPublisherDiagnostics(f.inspect, f.pebble.logPath) })
	ready := waitForPublisherReady(t, handle)
	waitForReadyPublisherConnections(t, f.inspect, ready.PublicURLID, ready.PublishRunNumber, 2)
	waitForIngressRoutingCurrent(t, f.inspect, 1)
	_, port, err := net.SplitHostPort(ready.PublicURL)
	if err != nil || port != strconv.Itoa(publicPort) {
		t.Fatalf("managed SSH public address = %q, %v", ready.PublicURL, err)
	}

	// linux loads this private trust bundle in the unmodified public cli and its
	// hidden tls helper. no Connect helper or authorization callback is faked.
	chain, err := os.ReadFile(f.controlConfig.ControlTLSCertificateFile)
	if err != nil {
		t.Fatal(err)
	}
	trustFile := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(trustFile, append(chain, f.pebble.rootPEM...), 0o600); err != nil {
		t.Fatal(err)
	}
	environment := integrationBinaryEnvironment(map[string]string{
		"SSL_CERT_FILE": trustFile, "TNL_NO_TELEMETRY": "1", "TNL_SERVER": f.identity.controlOrigin,
		"TNL_STATE_DIR": filepath.Join(t.TempDir(), "visitor-state"),
	})
	login := append(slices.Clone(environment), "TNL_LOGIN_TOKEN="+testLoginToken)
	runIntegrationBinaryCommand(t, "", login, *managedSSHFullBinary, "auth", "login", "--login-token")
	destination := account.Username + "@" + f.identity.hostname
	invoke := func(args ...string) *managedSSHFullInvocation {
		return startManagedSSHFullInvocation(t, environment, append([]string{"ssh"}, args...)...)
	}
	denied := invoke(destination, "--", "printf must-not-run")
	if err := denied.wait(t, 10*time.Second); err == nil || denied.stdout.String() != "" {
		t.Fatalf("URL ownership without an SSH grant ran a command: %v, %q", err, denied.stdout.String())
	}
	identity, err := f.identity.authority.IdentityContext(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	grant, err := f.identity.routes.CreateIdentityVisitorGrant(t.Context(), ready.PublicURLID, "full-ssh-grant", controlv1.CreateIdentityVisitorGrantRequest{IdentityId: identity.Identity.Id, SshUser: &account.Username})
	if err != nil {
		t.Fatal(err)
	}
	command := invoke(destination, "--", "id -u; id -g; id -G; pwd; printf full-managed-ssh-ok")
	if err := command.wait(t, 10*time.Second); err != nil {
		t.Fatalf("public tnl ssh command failed: %v\n%s", err, command.stderr.String())
	}
	lines := strings.Split(command.stdout.String(), "\n")
	if len(lines) != 5 || lines[0] != account.Uid || lines[1] != account.Gid || lines[3] != account.HomeDir || lines[4] != "full-managed-ssh-ok" {
		t.Fatalf("production tnl child credentials/home = %q", command.stdout.String())
	}
	wantGroups, err := account.GroupIds()
	if err != nil {
		t.Fatal(err)
	}
	gotGroups := strings.Fields(lines[2])
	slices.Sort(wantGroups)
	slices.Sort(gotGroups)
	if !slices.Equal(wantGroups, gotGroups) || slices.Contains(gotGroups, "0") {
		t.Fatalf("production tnl child groups = %v, want %v", gotGroups, wantGroups)
	}
	allowed := control.latest(t, account.Username)
	if allowed.err != nil || allowed.decision.IdentityID != identity.Identity.Id || allowed.decision.SSHUser != account.Username || allowed.decision.PublicURLID != ready.PublicURLID || allowed.scope.PublicURLID != ready.PublicURLID || allowed.scope.PublishRunNumber != ready.PublishRunNumber || allowed.scope.SourceIP.String() != "127.0.0.1" || allowed.fingerprint == [32]byte{} {
		t.Fatalf("missing exact TLS identity/account/current-run control decision: %v", allowed.err)
	}

	// both accounts are host-allowed. only control's account-specific grant can
	// reject this second account after the same real certificate issuance path.
	wrong := invoke(other.Username+"@"+f.identity.hostname, "--", "printf must-not-run")
	if err := wrong.wait(t, 10*time.Second); err == nil || wrong.stdout.String() != "" {
		t.Fatalf("a grant for %s ran as %s: %v", account.Username, other.Username, err)
	}
	if proof := control.latest(t, other.Username); !splitSSHForbidden(proof.err) {
		t.Fatalf("wrong account did not reach real control denial: %v\n%s", proof.err, wrong.stderr.String())
	}

	fullManagedSSHRevoke(t, f, control, invoke, destination, account, ready.PublicURLID, grant.Id)
	denied = invoke(destination, "--", "printf must-not-run")
	if err := denied.wait(t, 10*time.Second); err == nil || denied.stdout.String() != "" {
		t.Fatalf("revoked grant admitted a new public CLI command: %v", err)
	}
	t.Logf("verified public tnl ssh over %s: ACME server TLS, control-issued visitor certificate, exact account grant, nonroot uid/gid/groups/home, local forwarding, and active grant revocation", transport)
}

func fullManagedSSHRevoke(t *testing.T, f *splitPublishFixture, control *managedSSHFullControl, invoke func(...string) *managedSSHFullInvocation, destination string, account *user.User, urlID, grantID string) {
	t.Helper()
	backend, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = backend.Close() })
	_ = backend.SetDeadline(time.Now().Add(time.Minute))
	backendClosed := make(chan error, 1)
	go func() {
		c, err := backend.Accept()
		if err == nil {
			defer c.Close()
			_ = c.SetDeadline(time.Now().Add(time.Minute))
			var message [7]byte
			_, err = io.ReadFull(c, message[:])
			if err == nil && string(message[:]) == "forward" {
				_, err = c.Write(message[:])
			}
			if err == nil {
				_, err = c.Read(make([]byte, 1))
			}
		}
		backendClosed <- err
	}()
	local := unusedTCPAddress(t)
	_, localPort, _ := net.SplitHostPort(local)
	pidFile := filepath.Join(account.HomeDir, "full-ssh-"+urlID+".pid")
	t.Cleanup(func() { _ = os.Remove(pidFile) })
	active := invoke(destination, "-L", localPort+":"+backend.Addr().String(), "--", "printf '%s' \"$$\" > "+strconv.Quote(pidFile)+"; printf ready; exec sleep 120")
	waitForIntegrationCondition(t, 10*time.Second, func(context.Context) (bool, error) {
		select {
		case <-active.done:
			return false, fmt.Errorf("public CLI exited: %v\n%s", active.result(), active.stderr.String())
		default:
			return active.stdout.String() == "ready", nil
		}
	})
	pid, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	if number, err := strconv.Atoi(string(pid)); err != nil || number <= 1 {
		t.Fatalf("invalid nonroot child pid %q", pid)
	}
	processPath := filepath.Join("/proc", string(pid))
	status, err := os.ReadFile(filepath.Join(processPath, "status"))
	if err != nil || !bytes.Contains(status, []byte("Uid:\t"+account.Uid+"\t"+account.Uid+"\t"+account.Uid+"\t"+account.Uid)) {
		t.Fatalf("active production command is not owned by the selected account: %v", err)
	}
	forward, err := net.DialTimeout("tcp", local, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = forward.Close() })
	_ = forward.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(forward, "forward"); err != nil {
		t.Fatal(err)
	}
	var echo [7]byte
	if _, err := io.ReadFull(forward, echo[:]); err != nil || string(echo[:]) != "forward" {
		t.Fatalf("public tnl ssh -L did not carry bytes: %q, %v", echo, err)
	}
	_ = forward.SetDeadline(time.Time{})
	before := control.latest(t, account.Username)
	if before.err != nil {
		t.Fatal(before.err)
	}
	revokedAt := time.Now()
	if err := f.identity.routes.RevokeVisitorGrant(t.Context(), urlID, grantID); err != nil {
		t.Fatal(err)
	}
	// production refresh is 30 seconds. require closure before the actual last
	// successful authorization deadline, rather than accepting certificate expiry.
	deadline := minTimeForManagedSSHFull(revokedAt.Add(35*time.Second), before.decision.ValidUntil.Add(-250*time.Millisecond))
	if err := active.wait(t, time.Until(deadline)); err == nil {
		t.Fatal("grant revocation left the remote command successful")
	}
	select {
	case err := <-backendClosed:
		if !errors.Is(err, io.EOF) {
			t.Fatalf("grant revocation did not close the forwarded backend: %v", err)
		}
	case <-time.After(max(0, time.Until(deadline))):
		t.Fatal("grant revocation left the forwarded backend open")
	}
	waitForIntegrationCondition(t, max(time.Millisecond, time.Until(deadline)), func(context.Context) (bool, error) {
		_, err := os.Stat(processPath)
		return errors.Is(err, os.ErrNotExist), err
	})
	after := control.latest(t, account.Username)
	if !splitSSHForbidden(after.err) || before.fingerprint != after.fingerprint || before.scope != after.scope || !time.Now().Before(before.decision.ValidUntil) {
		t.Fatalf("active revocation did not recheck the same TLS proof/current run before its deadline: %v", after.err)
	}
	t.Logf("real control revocation closed the public CLI, nonroot command, and -L backend in %s (last decision had %s remaining)", time.Since(revokedAt).Round(time.Millisecond), time.Until(before.decision.ValidUntil).Round(time.Millisecond))
}

func minTimeForManagedSSHFull(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

type managedSSHFullInvocation struct {
	*commandOwner
	stdout, stderr synchronizedBuffer
}

func startManagedSSHFullInvocation(t *testing.T, environment []string, args ...string) *managedSSHFullInvocation {
	t.Helper()
	p := &managedSSHFullInvocation{}
	command := exec.Command(*managedSSHFullBinary, args...)
	command.Env = environment
	command.Stdout, command.Stderr = &p.stdout, &p.stderr
	owner, err := startOwnedCommand(command, nil)
	if err != nil {
		t.Fatal(err)
	}
	p.commandOwner = owner
	t.Cleanup(func() {
		if err := p.shutdown(time.Second, 5*time.Second); err != nil {
			t.Errorf("public tnl ssh cleanup: %v\n%s", err, p.stderr.String())
		}
	})
	return p
}

func (p *managedSSHFullInvocation) wait(t *testing.T, timeout time.Duration) error {
	t.Helper()
	if err := waitForDoneWithin(p.done, max(0, timeout)); err != nil {
		t.Fatalf("public tnl ssh did not finish: %v\n%s", err, p.stderr.String())
	}
	return p.result()
}

// only the marked disposable container's hosts file is touched. the production
// cli still performs its normal hostname validation and system dns lookup.
func managedSSHFullHosts(t *testing.T, hosts ...string) {
	t.Helper()
	before, err := os.ReadFile("/etc/hosts")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile("/etc/hosts", before, 0o644); err != nil {
			t.Errorf("restore disposable container hosts: %v", err)
		}
	})
	if err := os.WriteFile("/etc/hosts", append(slices.Clone(before), []byte("\n127.0.0.1 "+strings.Join(hosts, " ")+"\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
}

// preserve all tls bytes. the public-port front adds the same trusted proxy v2
// metadata as the separated fixture's acme front; the control front adds none.
func startManagedSSHFullProxy(t *testing.T, listener net.Listener, backend string, publicPort uint16) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	var active sync.WaitGroup
	done := make(chan struct{})
	t.Cleanup(func() {
		cancel()
		_ = listener.Close()
		<-done
		active.Wait()
	})
	go func() {
		defer close(done)
		for {
			visitor, err := listener.Accept()
			if err != nil {
				return
			}
			active.Go(func() {
				defer visitor.Close()
				stopVisitor := context.AfterFunc(ctx, func() { _ = visitor.Close() })
				defer stopVisitor()
				upstream, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", backend)
				if err != nil {
					return
				}
				defer upstream.Close()
				stopUpstream := context.AfterFunc(ctx, func() { _ = upstream.Close() })
				defer stopUpstream()
				if publicPort != 0 {
					source := visitor.RemoteAddr().(*net.TCPAddr).AddrPort()
					header, err := proxyproto.Encode(proxyproto.Header{Source: netip.AddrPortFrom(source.Addr().Unmap(), source.Port()), Destination: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), publicPort)})
					if err != nil {
						return
					}
					if _, err := upstream.Write(header); err != nil {
						return
					}
				}
				finished := make(chan struct{})
				go func() {
					_, _ = io.Copy(visitor, upstream)
					_ = visitor.(*net.TCPConn).CloseWrite()
					close(finished)
				}()
				_, _ = io.Copy(upstream, visitor)
				_ = upstream.(*net.TCPConn).CloseWrite()
				<-finished
			})
		}
	}()
}
