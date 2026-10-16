package managedssh

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/livevisitor"
	"golang.org/x/crypto/ssh"
)

func TestSSHTransientRecheckRetainsDeadlineButRejectsNewWork(t *testing.T) {
	config := protocolConfig(t)
	config.RecheckInterval = 10 * time.Millisecond
	var unavailable atomic.Bool
	checked := make(chan struct{}, 1)
	deadline := time.Now().Add(400 * time.Millisecond)
	providerErr := errors.New("transient provider error")
	config.Authorize = func(_ context.Context, id Identity, user string) (Decision, error) {
		if unavailable.Load() {
			select {
			case checked <- struct{}{}:
			default:
			}
			return Decision{}, providerErr
		}
		return Decision{IdentityID: id.IdentityID, PublicURLID: id.PublicURLID, SSHUser: user, ValidUntil: deadline}, nil
	}
	started, joined := make(chan struct{}), make(chan struct{})
	client, done := protocolServer(t, config, protocolRunner{run: func(ctx context.Context, _ Request, _ Streams) (int, error) {
		close(started)
		<-ctx.Done()
		close(joined)
		return 0, ctx.Err()
	}})
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	awaitProtocol(t, started)
	idle, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer idle.Close()
	unavailable.Store(true)
	awaitProtocol(t, checked)
	select {
	case <-joined:
		t.Fatal("transient error killed active work before expiry")
	default:
	}
	if another, err := client.NewSession(); err == nil {
		another.Close()
		t.Fatal("new channel used an unknown authorization")
	}
	if err := idle.Start("new command"); err == nil {
		t.Fatal("existing idle channel started new work during unknown authorization")
	}
	awaitProtocol(t, done)
	awaitProtocol(t, joined)
	if time.Now().Before(deadline) {
		t.Fatal("transient failure shortened the successful deadline")
	}
}

func TestSSHRecheckRecoversAndExplicitDenialCloses(t *testing.T) {
	config := protocolConfig(t)
	config.RecheckInterval = 10 * time.Millisecond
	var state atomic.Int32
	observed := make(chan int32, 8)
	config.Authorize = func(_ context.Context, id Identity, user string) (Decision, error) {
		current := state.Load()
		select {
		case observed <- current:
		default:
		}
		if current == 1 {
			return Decision{}, errors.New("unavailable")
		}
		if current == 2 {
			return Decision{}, fmt.Errorf("revoked: %w", livevisitor.ErrDenied)
		}
		return Decision{IdentityID: id.IdentityID, PublicURLID: id.PublicURLID, SSHUser: user, ValidUntil: time.Now().Add(time.Second)}, nil
	}
	client, done := protocolServer(t, config, protocolRunner{})
	state.Store(1)
	for awaitProtocol(t, observed) != 1 {
	}
	if session, err := client.NewSession(); err == nil {
		session.Close()
		t.Fatal("unknown decision admitted new work")
	}
	state.Store(0)
	for awaitProtocol(t, observed) != 0 {
	}
	// the callback publishes its result just before the checker updates the gate.
	var session *ssh.Session
	for limit := time.Now().Add(time.Second); time.Now().Before(limit); {
		var err error
		session, err = client.NewSession()
		if err == nil {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if session == nil {
		t.Fatal("successful refresh did not restore admission")
	}
	defer session.Close()
	state.Store(2)
	awaitProtocol(t, done)
}

func TestSSHHostAccountRemovedDuringRecheck(t *testing.T) {
	config := protocolConfig(t)
	config.RecheckInterval = 10 * time.Millisecond
	var removed atomic.Bool
	server, err := newServer(config, 0, func([]string) error {
		if removed.Load() {
			return errors.New("account removed")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	address, done := protocolListen(t, server)
	client, err := ssh.Dial("tcp", address, protocolClientConfig(config, "worker"))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	removed.Store(true)
	awaitProtocol(t, done)
}

func TestSSHAuthorizePreservesTransientCause(t *testing.T) {
	config := protocolConfig(t)
	cause := errors.New("provider unavailable")
	config.Authorize = func(context.Context, Identity, string) (Decision, error) { return Decision{}, cause }
	server, err := newServer(config, 0, func([]string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	_, err = server.authorize(context.Background(), Identity{IdentityID: "id", PublicURLID: "url"}, "worker")
	if !errors.Is(err, cause) || errors.Is(err, livevisitor.ErrDenied) {
		t.Fatalf("transient classification = %v", err)
	}
}

func TestSSHChannelLimit(t *testing.T) {
	config := protocolConfig(t)
	config.MaxChannels = 257
	if _, err := newServer(config, 0, func([]string) error { return nil }); err != ErrConfiguration {
		t.Fatalf("unbounded channels = %v", err)
	}
	config.MaxChannels = 1
	client, done := protocolServer(t, config, protocolRunner{})
	first, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := client.NewSession(); err == nil {
		second.Close()
		t.Fatal("exceeded active channel limit")
	}
	_ = client.Close()
	awaitProtocol(t, done)
}
