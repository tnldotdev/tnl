package clientruntime

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tnldotdev/tnl/internal/credentials"
	"github.com/tnldotdev/tnl/internal/opaqueid"
	"github.com/tnldotdev/tnl/internal/privateprotocol"
)

func TestAdHocRegistrationsHaveIndependentOwnerLeasesAndPrivateStatus(t *testing.T) {
	token, _, _, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	var active atomic.Int32
	started := make(chan string, 2)
	manager := NewAdHocManager(t.Context(), func(ctx context.Context, request privateprotocol.AdHocRegister, update func(privateprotocol.AdHocStatus)) error {
		update(privateprotocol.AdHocStatus{Version: 1, RegistrationID: request.RegistrationID, State: "routable",
			PublicURLID: "url_ready", PublicURL: "https://eph-aaaaaaaaaaaaaaaaaaaaaaaaaa.example.test", PublishRunNumber: 2})
		started <- request.RegistrationID
		<-ctx.Done()
		return ctx.Err()
	}, func(pid int) bool { return pid == 123 }, func() func() {
		active.Add(1)
		return func() { active.Add(-1) }
	})
	t.Cleanup(manager.Close)
	register := func() privateprotocol.AdHocRegister {
		t.Helper()
		id, err := opaqueid.New(opaqueid.InvocationPrefix)
		if err != nil {
			t.Fatal(err)
		}
		return privateprotocol.AdHocRegister{Version: 1, RegistrationID: id,
			Owner: "0123456789abcdef0123456789abcdef", PID: 123,
			Target: "http://127.0.0.1:3000", Credential: token.String()}
	}
	first, second := register(), register()
	for _, request := range []privateprotocol.AdHocRegister{first, second} {
		if _, err := manager.Register(request); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("ad-hoc publisher did not start")
		}
	}
	if active.Load() != 2 {
		t.Fatal("multiple registrations did not retain independent ownership")
	}
	status, err := manager.Status(first.RegistrationID, first.Owner)
	if err != nil || status.State != "routable" || status.PublishRunNumber != 2 {
		t.Fatalf("routability status = %#v, %v", status, err)
	}
	encoded, err := json.Marshal(status)
	if err != nil || strings.Contains(string(encoded), token.String()) || strings.Contains(string(encoded), "credential") {
		t.Fatal("private status disclosed a credential")
	}
	if _, err := manager.Status(first.RegistrationID, second.Owner+"a"); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("wrong owner observed another registration: %v", err)
	}
	if err := manager.Unregister(first.RegistrationID, first.Owner); err != nil || active.Load() != 1 {
		t.Fatalf("unregister stopped another handle: %v, live=%d", err, active.Load())
	}
	if err := manager.Renew(second.RegistrationID, second.Owner); err != nil {
		t.Fatal(err)
	}
	manager.Close()
	if active.Load() != 0 {
		t.Fatalf("runtime left %d ad-hoc workers owned", active.Load())
	}
}

func TestAdHocLeaseLossStopsTheOwnedPublisher(t *testing.T) {
	token, _, _, err := credentials.NewEphemeralCredential()
	if err != nil {
		t.Fatal(err)
	}
	id, err := opaqueid.New(opaqueid.InvocationPrefix)
	if err != nil {
		t.Fatal(err)
	}
	var alive atomic.Bool
	alive.Store(true)
	done := make(chan struct{})
	manager := NewAdHocManager(t.Context(), func(ctx context.Context, _ privateprotocol.AdHocRegister, _ func(privateprotocol.AdHocStatus)) error {
		<-ctx.Done()
		close(done)
		return ctx.Err()
	}, func(int) bool { return alive.Load() }, nil)
	t.Cleanup(manager.Close)
	request := privateprotocol.AdHocRegister{Version: 1, RegistrationID: id,
		Owner: "0123456789abcdef0123456789abcdef", PID: 123,
		Target: "http://127.0.0.1:3000", Credential: token.String()}
	if _, err := manager.Register(request); err != nil {
		t.Fatal(err)
	}
	alive.Store(false)
	manager.Sweep()
	select {
	case <-done:
	default:
		t.Fatal("lost application owner kept its ad-hoc publisher running")
	}
	if _, err := manager.Status(id, request.Owner); !errors.Is(err, ErrRegistrationStale) {
		t.Fatalf("expired registration remained observable: %v", err)
	}
}
