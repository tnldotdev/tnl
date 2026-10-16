package managedssh

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

type blockingApprover struct {
	mu          sync.Mutex
	bound       Binding
	decisions   chan AttemptDecision
	started     chan Binding
	canceled    chan string
	until       time.Duration
	claims      atomic.Int32
	change      func(*AttemptDecision)
	claimChange func(*AttemptDecision)
	approvalURL string
	code        string
}

func (a *blockingApprover) decision() AttemptDecision {
	a.mu.Lock()
	bound := a.bound
	a.mu.Unlock()
	d := AttemptDecision{Binding: bound, IdentityID: "identity-a", Approved: true, ValidUntil: time.Now().Add(time.Minute)}
	if a.change != nil {
		a.change(&d)
	}
	return d
}
func (a *blockingApprover) StartSSHAttempt(_ context.Context, b Binding) (Attempt, error) {
	a.mu.Lock()
	a.bound = b
	a.mu.Unlock()
	a.started <- b
	until := a.until
	if until == 0 {
		until = time.Minute
	}
	url := a.approvalURL
	if url == "" {
		url = "https://control.example/ssh/opaque-id"
	}
	code := a.code
	if code == "" {
		code = "ABCDEFG2"
	}
	return Attempt{ID: "opaque-id", Code: code, ApprovalURL: url, ValidUntil: time.Now().Add(until)}, nil
}
func (a *blockingApprover) WaitSSHAttempt(ctx context.Context, _ string) (AttemptDecision, error) {
	select {
	case <-ctx.Done():
		return AttemptDecision{}, ctx.Err()
	case d := <-a.decisions:
		return d, nil
	}
}
func (a *blockingApprover) ClaimSSHAttempt(ctx context.Context, _ string, b Binding) (AttemptDecision, error) {
	a.claims.Add(1)
	if ctx.Err() != nil || b != a.decision().Binding {
		return AttemptDecision{}, ErrUnauthorized
	}
	d := a.decision()
	if a.claimChange != nil {
		a.claimChange(&d)
	}
	return d, nil
}
func (a *blockingApprover) CancelSSHAttempt(_ context.Context, id string) error {
	a.canceled <- id
	return nil
}
func (a *blockingApprover) RecheckSSHSession(_ context.Context, b Binding, identity string) (AttemptDecision, error) {
	d := a.decision()
	if b != d.Binding || identity != d.IdentityID {
		return AttemptDecision{}, ErrUnauthorized
	}
	return d, nil
}

func approvalFixture(t *testing.T, alter func(*Config, *blockingApprover)) (Config, *blockingApprover, string, <-chan error) {
	t.Helper()
	c := protocolConfig(t)
	a := &blockingApprover{decisions: make(chan AttemptDecision, 1), started: make(chan Binding, 1), canceled: make(chan string, 2)}
	c.Attempts = a
	if alter != nil {
		alter(&c, a)
	}
	s, err := newServer(c, 0, func([]string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	address, done := protocolListen(t, s)
	return c, a, address, done
}

type dialOutcome struct {
	client *ssh.Client
	err    error
}

func approvalDial(address string, c Config, banner func(string) error) <-chan dialOutcome {
	done := make(chan dialOutcome, 1)
	go func() {
		cfg := protocolClientConfig(c, "worker")
		cfg.BannerCallback = banner
		client, err := ssh.Dial("tcp", address, cfg)
		done <- dialOutcome{client, err}
	}()
	return done
}

func TestBrowserApprovalNoInputAndPromotionBeforeAuth(t *testing.T) {
	promoted := make(chan struct{})
	c, a, address, serverDone := approvalFixture(t, func(c *Config, _ *blockingApprover) {
		c.Promote = func(context.Context) error { close(promoted); return nil }
	})
	banner := make(chan string, 1)
	connected := approvalDial(address, c, func(text string) error { banner <- text; return nil })
	text := awaitProtocol(t, banner)
	if !regexp.MustCompile(`code: [A-Z2-7]{8}\n`).MatchString(text) || !strings.Contains(text, "open https://control.example/ssh/opaque-id\n") || strings.Contains(text, "/ssh/ABCDEFG2") {
		t.Fatalf("invalid separate URL and code: %q", text)
	}
	bound := awaitProtocol(t, a.started)
	if bound.Hostname != c.Binding.Hostname || bound.PublicURLID != c.Binding.PublicURLID || bound.PublishRunID != c.Binding.PublishRunID || bound.PublishRunNumber != c.Binding.PublishRunNumber || bound.VisitorConnectionID != c.Binding.VisitorConnectionID || bound.Source != c.Binding.Source || bound.Username != "worker" || len(bound.SessionID) < 32 {
		t.Fatalf("lost trusted proof or SSH session hash: %+v", bound)
	}
	select {
	case got := <-connected:
		if got.client != nil {
			got.client.Close()
		}
		t.Fatalf("authenticated before decision: %v", got.err)
	case <-time.After(30 * time.Millisecond):
	}
	a.decisions <- a.decision()
	result := awaitProtocol(t, connected)
	if result.err != nil {
		t.Fatal(result.err)
	}
	select {
	case <-promoted:
	default:
		t.Fatal("SSH auth succeeded before ingress promotion")
	}
	if a.claims.Load() != 1 {
		t.Fatal("approval was not claimed exactly once")
	}
	_ = result.client.Close()
	awaitProtocol(t, serverDone)
	if awaitProtocol(t, a.canceled) != "opaque-id" {
		t.Fatal("attempt was not cleared")
	}
}

func TestBrowserApprovalMismatchDenialTimeoutAndPromotion(t *testing.T) {
	for _, mode := range []string{"hostname", "url", "run", "number", "visitor", "source", "account", "session", "identity", "deny", "timeout", "promotion"} {
		t.Run(mode, func(t *testing.T) {
			var promoted atomic.Int32
			c, a, address, serverDone := approvalFixture(t, func(c *Config, a *blockingApprover) {
				if mode == "timeout" {
					a.until = 100 * time.Millisecond
				}
				if mode == "identity" {
					a.claimChange = func(d *AttemptDecision) { d.IdentityID = "other" }
				}
				if mode == "promotion" {
					c.Promote = func(context.Context) error { promoted.Add(1); return errors.New("ingress rejected promotion") }
				} else {
					c.Promote = func(context.Context) error { promoted.Add(1); return nil }
				}
				a.change = func(d *AttemptDecision) {
					switch mode {
					case "hostname":
						d.Binding.Hostname = "other.example"
					case "url":
						d.Binding.PublicURLID = "other"
					case "run":
						d.Binding.PublishRunID = "other"
					case "number":
						d.Binding.PublishRunNumber++
					case "visitor":
						d.Binding.VisitorConnectionID = "other"
					case "source":
						d.Binding.Source = netip.MustParseAddrPort("192.0.2.99:1234")
					case "account":
						d.Binding.Username = "other"
					case "session":
						d.Binding.SessionID = "other"
					case "deny":
						d.Approved = false
					}
				}
			})
			ready := make(chan struct{}, 1)
			result := approvalDial(address, c, func(string) error { ready <- struct{}{}; return nil })
			awaitProtocol(t, ready)
			awaitProtocol(t, a.started)
			if mode != "timeout" {
				a.decisions <- a.decision()
			}
			got := awaitProtocol(t, result)
			if got.client != nil {
				got.client.Close()
				t.Fatal("unsafe approval authenticated")
			}
			awaitProtocol(t, serverDone)
			awaitProtocol(t, a.canceled)
			if mode != "promotion" && promoted.Load() != 0 {
				t.Fatal("denied decision reached ingress")
			}
		})
	}
}

func TestSSHDisconnectCancelsPendingAttempt(t *testing.T) {
	c, a, address, serverDone := approvalFixture(t, nil)
	raw, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		cfg := protocolClientConfig(c, "worker")
		cfg.BannerCallback = func(string) error { _ = raw.Close(); return nil }
		_, _, _, err := ssh.NewClientConn(raw, address, cfg)
		result <- err
	}()
	awaitProtocol(t, a.started)
	if err := awaitProtocol(t, result); err == nil {
		t.Fatal("closed socket authenticated")
	}
	awaitProtocol(t, serverDone)
	awaitProtocol(t, a.canceled)
	if a.claims.Load() != 0 {
		t.Fatal("disconnected attempt was claimed")
	}
}

func TestSSHOnlyKeyboardInteractiveIsAccepted(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, methods := range [][]ssh.AuthMethod{nil, {ssh.Password("unused")}, {ssh.PublicKeys(key)}} {
		c, a, address, done := approvalFixture(t, nil)
		cfg := &ssh.ClientConfig{User: "worker", HostKeyCallback: ssh.FixedHostKey(c.HostKey.PublicKey()), Auth: methods, Timeout: time.Second}
		client, err := ssh.Dial("tcp", address, cfg)
		if err == nil {
			client.Close()
			t.Fatal("non-interactive authentication succeeded")
		}
		awaitProtocol(t, done)
		if a.claims.Load() != 0 {
			t.Fatal("other SSH authentication claimed a decision")
		}
	}
	// a wrong key must also fail before showing a trusted approval URL.
	c, _, address, done := approvalFixture(t, nil)
	wrong := protocolClientConfig(c, "worker")
	wrong.HostKeyCallback = ssh.FixedHostKey(key.PublicKey())
	if client, err := ssh.Dial("tcp", address, wrong); err == nil {
		client.Close()
		t.Fatal("accepted an untrusted host key")
	}
	awaitProtocol(t, done)
}

func TestSSHRejectsUntrustedApprovalInstructions(t *testing.T) {
	for _, test := range []struct{ name, url, code string }{
		{"different host", "https://elsewhere.example/ssh/opaque-id", ""},
		{"plaintext", "http://control.example/ssh/opaque-id", ""},
		{"embedded code", "https://control.example/ssh/ABCDEFG2", ""},
		{"short code", "", "ABCDEF"},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, a, address, done := approvalFixture(t, func(_ *Config, a *blockingApprover) { a.approvalURL, a.code = test.url, test.code })
			var banner atomic.Bool
			result := approvalDial(address, c, func(text string) error {
				if text != "" {
					banner.Store(true)
				}
				return nil
			})
			got := awaitProtocol(t, result)
			if got.client != nil {
				got.client.Close()
				t.Fatal("untrusted instructions authenticated")
			}
			awaitProtocol(t, done)
			if banner.Load() || a.claims.Load() != 0 {
				t.Fatal("displayed an untrusted control URL or claimed approval")
			}
			awaitProtocol(t, a.canceled)
		})
	}
}

func TestSSHFirstByteIsRaw(t *testing.T) {
	_, _, address, done := approvalFixture(t, nil)
	c, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "SSH-2.0-") {
		t.Fatalf("raw SSH banner = %q %v", line, err)
	}
	_ = c.Close()
	awaitProtocol(t, done)
}
