package publisher

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os/user"
	"sync"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/livevisitor"
	"github.com/tnldotdev/tnl/internal/managedssh"
	"github.com/tnldotdev/tnl/internal/proxyproto"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
	"github.com/tnldotdev/tnl/pkg/protocol/tunnelv1"
	"golang.org/x/crypto/ssh"
)

var managedSSHRootUser = flag.String("tnl-test-managed-ssh-root-user", "", "nonroot account in the disposable managed SSH container")

func managedSSHTestUser(t *testing.T) string {
	t.Helper()
	if *managedSSHRootUser != "" {
		return *managedSSHRootUser
	}
	u, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if u.Uid == "0" {
		t.Skip("requires a nonroot developer account or the explicit disposable root fixture")
	}
	return u.Username
}

func managedSSHTestConfig(t *testing.T) PublicURLServerConfig {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	return PublicURLServerConfig{Hostname: "shell.example", ControlURL: "https://control.example", PublicURLID: "ssh-url", PublishRunID: "ssh-run", PublishRunNumber: 7,
		ServiceProtocol: controlv1.Ssh, PublicPort: 2222, AccessMode: controlv1.Restricted,
		SSH: &SSHConfig{HostKey: signer, Users: []string{managedSSHTestUser(t)}}, SSHAttempts: &rejectSSHAttempt{}}
}

type rejectSSHAttempt struct {
	recheck func(context.Context, managedssh.Binding, string) (managedssh.AttemptDecision, error)
}

func (*rejectSSHAttempt) StartSSHAttempt(context.Context, managedssh.Binding) (managedssh.Attempt, error) {
	return managedssh.Attempt{}, errors.New("unavailable")
}
func (*rejectSSHAttempt) WaitSSHAttempt(context.Context, string) (managedssh.AttemptDecision, error) {
	return managedssh.AttemptDecision{}, errors.New("unavailable")
}
func (*rejectSSHAttempt) ClaimSSHAttempt(context.Context, string, managedssh.Binding) (managedssh.AttemptDecision, error) {
	return managedssh.AttemptDecision{}, errors.New("unavailable")
}
func (*rejectSSHAttempt) CancelSSHAttempt(context.Context, string) error { return nil }

func (a *rejectSSHAttempt) RecheckSSHSession(ctx context.Context, b managedssh.Binding, id string) (managedssh.AttemptDecision, error) {
	if a.recheck != nil {
		return a.recheck(ctx, b, id)
	}
	return managedssh.AttemptDecision{}, errors.New("unavailable")
}

func listenManagedSSHPublisher(t *testing.T, config PublicURLServerConfig, stream tunnelv1.VisitorStreamHeader) (*PublicURLServer, string) {
	t.Helper()
	route, err := NewPublicURLServer(config)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		_ = route.Close()
		t.Fatal(err)
	}
	header, err := proxyproto.Encode(proxyproto.Header{Source: netip.MustParseAddrPort("192.0.2.10:40001"), Destination: netip.MustParseAddrPort("203.0.113.10:2222")})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var workers sync.WaitGroup
	go func() {
		defer close(done)
		defer workers.Wait()
		for {
			c, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Go(func() {
				route.handleVisitorHeader(&publicURLReaderConn{Conn: c, reader: io.MultiReader(bytes.NewReader(header), c)}, true, stream)
			})
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); _ = route.Close(); awaitPublisherTest(t, done) })
	return route, listener.Addr().String()
}

func TestManagedSSHRejectsUnmanagedConfiguration(t *testing.T) {
	for _, change := range []struct {
		name  string
		apply func(*PublicURLServerConfig)
	}{
		{"target", func(c *PublicURLServerConfig) { c.Target = "127.0.0.1:22" }},
		{"target TLS", func(c *PublicURLServerConfig) { c.TargetTLS = true }},
		{"anonymous", func(c *PublicURLServerConfig) { c.AccessMode = controlv1.Anonymous }},
		{"missing attempts", func(c *PublicURLServerConfig) { c.SSHAttempts = nil }},
		{"missing host", func(c *PublicURLServerConfig) { c.SSH = nil }},
		{"root", func(c *PublicURLServerConfig) { c.SSH.Users = []string{"root"} }},
		{"certificate plan", func(c *PublicURLServerConfig) { c.CertificatePlan.Identifiers = []string{c.Hostname} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			c := managedSSHTestConfig(t)
			change.apply(&c)
			if route, err := NewPublicURLServer(c); err == nil {
				_ = route.Close()
				t.Fatal("accepted unsafe SSH configuration")
			}
		})
	}
}

func TestManagedSSHRejectsUntrustedStreamBeforeSSHOrPromotion(t *testing.T) {
	config := managedSSHTestConfig(t)
	stream := tunnelv1.VisitorStreamHeader{PublicURLID: config.PublicURLID, PublishRunID: "replaced", PublishRunNumber: config.PublishRunNumber, VisitorConnectionID: "visitor-1"}
	route, address := listenManagedSSHPublisher(t, config, stream)
	if err := route.InstallCertificate(publicURLTestCertificate(t, config.Hostname)); err == nil {
		t.Fatal("SSH installed a public URL certificate")
	}
	c, err := net.DialTimeout("tcp", address, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(2 * time.Second))
	_, _ = io.WriteString(c, "SSH-2.0-client\r\n")
	answer, err := io.ReadAll(c)
	if len(answer) != 0 {
		t.Fatalf("untrusted run got SSH bytes: %q %v", answer, err)
	}
}

func TestManagedSSHReadyWithoutPublicURLCertificate(t *testing.T) {
	config := managedSSHTestConfig(t)
	route, err := NewPublicURLServer(config)
	if err != nil {
		t.Fatal(err)
	}
	defer route.Close()
	control := newCertificateTestControl(t, config.Hostname, controlv1.CertificatePlan{})
	confirmed := false
	control.ready = func() error { confirmed = true; return nil }
	if err := confirmPublishRunReady(t.Context(), control, control.setup, route, credentials.PublishRunToken(control.setup.PublishRunToken), func() error {
		if !confirmed || route.certificate.Load() != nil {
			t.Fatal("SSH readiness waited for or installed a public URL certificate")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestSSHRecheckBindsCurrentAccountSessionAndRun(t *testing.T) {
	bound := managedssh.Binding{Hostname: "shell.example", PublicURLID: "url", PublishRunID: "run", PublishRunNumber: 3,
		VisitorConnectionID: "visitor", Source: netip.MustParseAddrPort("192.0.2.2:40000")}
	identity := managedssh.Identity{IdentityID: "person", PublicURLID: "url", SessionID: "session-hash"}
	check := bound
	check.Username, check.SessionID = "worker", identity.SessionID
	returned := managedssh.AttemptDecision{Binding: check, IdentityID: identity.IdentityID, Approved: true, ValidUntil: time.Now().Add(time.Minute)}
	var providerErr error
	client := &rejectSSHAttempt{recheck: func(_ context.Context, got managedssh.Binding, id string) (managedssh.AttemptDecision, error) {
		if got != check || id != identity.IdentityID {
			t.Fatalf("lost trusted SSH recheck binding: %+v %q", got, id)
		}
		return returned, providerErr
	}}
	authorize := sshSessionAuthorization(client, bound)
	if result, err := authorize(t.Context(), identity, "worker"); err != nil || result.ValidUntil != returned.ValidUntil || result.SSHUser != "worker" {
		t.Fatalf("valid SSH session recheck: %+v %v", result, err)
	}
	for _, modify := range []func(*managedssh.AttemptDecision){
		func(d *managedssh.AttemptDecision) { d.Binding.Hostname = "other.example" },
		func(d *managedssh.AttemptDecision) { d.Binding.PublicURLID = "other" },
		func(d *managedssh.AttemptDecision) { d.Binding.PublishRunID = "other" },
		func(d *managedssh.AttemptDecision) { d.Binding.PublishRunNumber++ },
		func(d *managedssh.AttemptDecision) { d.Binding.VisitorConnectionID = "other" },
		func(d *managedssh.AttemptDecision) { d.Binding.Source = netip.MustParseAddrPort("192.0.2.3:40000") },
		func(d *managedssh.AttemptDecision) { d.Binding.Username = "other" },
		func(d *managedssh.AttemptDecision) { d.Binding.SessionID = "other" },
		func(d *managedssh.AttemptDecision) { d.IdentityID = "other" },
		func(d *managedssh.AttemptDecision) { d.Approved = false },
		func(d *managedssh.AttemptDecision) { d.ValidUntil = time.Now().Add(-time.Second) },
	} {
		returned = managedssh.AttemptDecision{Binding: check, IdentityID: identity.IdentityID, Approved: true, ValidUntil: time.Now().Add(time.Minute)}
		modify(&returned)
		if _, err := authorize(t.Context(), identity, "worker"); !errors.Is(err, livevisitor.ErrDenied) {
			t.Fatalf("stale SSH session accepted: %v", err)
		}
	}
	providerErr = &controlclient.ProblemError{Status: http.StatusForbidden}
	if _, err := authorize(t.Context(), identity, "worker"); !errors.Is(err, livevisitor.ErrDenied) {
		t.Fatalf("explicit revocation was not immediate: %v", err)
	}
	providerErr = errors.New("temporary control failure")
	if _, err := authorize(t.Context(), identity, "worker"); !errors.Is(err, providerErr) || errors.Is(err, livevisitor.ErrDenied) {
		t.Fatalf("temporary failure shortened the last known deadline: %v", err)
	}
}
