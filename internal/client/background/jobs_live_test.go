package background

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestBackgroundLiveReadinessUsesSameJob(t *testing.T) {
	connectFirst := Readiness{Address: "127.0.0.1:15432", Target: "database", ServiceID: "svc_first",
		Profile: []byte(`{"protocol":"postgres"}`), ConnectCommand: []string{"first instruction"}}
	connectNext := Readiness{Address: "127.0.0.1:15433", Target: "replica", ServiceID: "svc_next",
		Profile: []byte(`{"protocol":"mysql"}`), ConnectCommand: []string{"next instruction"}}
	guestFirst := Readiness{Address: "https://demo.example.test", Target: "demo",
		GuestEntryURL: "https://demo.example.test/__tnl/share/shr_trial.first-secret"}
	guestNext := Readiness{Address: "https://replacement.example.test", Target: "demo",
		GuestEntryURL: "https://replacement.example.test/__tnl/share/shr_trial.next-secret"}
	for _, test := range []struct {
		name              string
		kind              Kind
		lossDuringHandoff bool
		first, next       Readiness
	}{
		{"connector loses readiness during handoff", KindConnect, true, connectFirst, connectNext},
		{"connector loses readiness after handoff", KindConnect, false, connectFirst, connectNext},
		{"guest URL stays private", KindPublish, false, guestFirst, guestNext},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, scope := testScope(t, filepath.Join(t.TempDir(), "state"))
			const id = "job_0123456789ABCDEFGHIJKL"
			reservation, listener, err := reserveSocket(scope, id)
			if err != nil {
				t.Fatal(err)
			}
			defer reservation.remove()
			parent, boot := net.Pipe()
			defer parent.Close()
			defer boot.Close()
			_ = parent.SetReadDeadline(time.Now().Add(5 * time.Second))
			runCtx, cancel := context.WithCancel(t.Context())
			defer cancel()
			control := &jobControl{
				entry:  Entry{JobID: id, Kind: test.kind, State: StateStarting, PID: os.Getpid()},
				runCtx: runCtx, cancel: cancel, boot: boot,
			}
			ctx := context.WithValue(runCtx, controlKey{}, control)
			served := make(chan struct{})
			go func() {
				defer close(served)
				control.serve(listener)
			}()
			defer func() {
				_ = listener.Close()
				<-served
			}()

			assertLive := func(state State, address, target, serviceID string) {
				t.Helper()
				entry, err := Status(t.Context(), root, id)
				if err != nil {
					t.Fatal(err)
				}
				listed, err := List(t.Context(), root)
				if err != nil || len(listed) != 1 {
					t.Fatalf("list: %+v (%v)", listed, err)
				}
				for _, live := range []Entry{entry, listed[0]} {
					if live.Profile != nil || live.ConnectCommand != nil || live.GuestEntryURL != "" {
						t.Fatal("live status exposed private startup fields")
					}
					if live.JobID != id || live.PID != os.Getpid() || live.Kind != test.kind ||
						live.State != state || live.Address != address || live.Target != target ||
						live.ServiceID != serviceID {
						t.Fatalf("wrong live status: %+v; want %s %q %q %q",
							live, state, address, target, serviceID)
					}
				}
			}

			Reconnecting(ctx)
			assertLive(StateStarting, "", "", "")
			first, next := test.first, test.next
			reported := make(chan error, 1)
			go func() { reported <- Ready(ctx, first) }()
			var receipt startupReply
			if err := readFrame(frameReader(parent), &receipt); err != nil {
				t.Fatal(err)
			}
			if err := <-reported; err != nil {
				t.Fatal(err)
			}
			if receipt.Entry.JobID != id || receipt.Entry.State != StateReady || receipt.Entry.Address != first.Address ||
				string(receipt.Entry.Profile) != string(first.Profile) || !slices.Equal(receipt.Entry.ConnectCommand, first.ConnectCommand) ||
				receipt.Entry.GuestEntryURL != first.GuestEntryURL {
				t.Fatal("startup receipt did not carry the initial readiness and private fields")
			}
			if test.lossDuringHandoff {
				Reconnecting(ctx)
				assertLive(StateStarting, "", "", "")
				if err := Ready(ctx, next); err != nil {
					t.Fatal(err)
				}
				if control.commit() {
					t.Fatal("committed a stale readiness receipt")
				}
				cancel()
				assertLive(StateStopping, "", "", "")
				return
			}
			assertLive(StateStarting, "", "", "")
			if !control.commit() {
				t.Fatal("ready receipt could not be committed")
			}
			_ = boot.Close()
			assertLive(StateReady, first.Address, first.Target, first.ServiceID)
			Reconnecting(ctx)
			assertLive(StateReconnecting, "", first.Target, first.ServiceID)

			if err := Ready(ctx, next); err != nil {
				t.Fatalf("recovery reused the closed startup channel: %v", err)
			}
			assertLive(StateReady, next.Address, next.Target, next.ServiceID)

			control.stop()
			Reconnecting(ctx)
			if err := Ready(ctx, next); err != nil {
				t.Fatal(err)
			}
			assertLive(StateStopping, "", "", "")
		})
	}
}
