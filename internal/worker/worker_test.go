package worker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"

	"github.com/tnldotdev/tnl/internal/tailtransport"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func TestEngineOwnsRouteLifecycle(t *testing.T) {
	engine, err := NewEngine(EngineConfig{Capacity: 1, Regions: testRegions()})
	if err != nil {
		t.Fatal(err)
	}
	var created []*fakeDialer
	engine.newDialer = func(tailtransport.DialerConfig) (sessionDialer, error) {
		dialer := new(fakeDialer)
		created = append(created, dialer)
		return dialer, nil
	}
	assignment := testAssignment("route-1", 1)
	first, err := engine.Attach(context.Background(), assignment)
	if err != nil {
		t.Fatal(err)
	}
	if capacity := engine.Capacity(); capacity.Active != 1 || capacity.Limit != 1 || capacity.Draining {
		t.Fatalf("capacity = %#v", capacity)
	}
	if _, err := first.Open(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.Attach(context.Background(), testAssignment("route-2", 1)); !errors.Is(err, ErrAtCapacity) {
		t.Fatalf("capacity error = %v", err)
	}

	replacement, err := engine.Attach(context.Background(), testAssignment("route-1", 2))
	if err != nil {
		t.Fatal(err)
	}
	replacementDialer := created[len(created)-1]
	if created[0].closes.Load() != 1 {
		t.Fatal("replacement did not close old route")
	}
	if _, err := first.Open(context.Background()); !errors.Is(err, ErrStaleAssignment) {
		t.Fatalf("old backend error = %v", err)
	}
	if _, err := engine.Attach(context.Background(), assignment); !errors.Is(err, ErrStaleAssignment) {
		t.Fatalf("stale attach error = %v", err)
	}
	if err := engine.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := replacement.Open(context.Background()); !errors.Is(err, ErrDraining) {
		t.Fatalf("open while draining error = %v", err)
	}
	if replacementDialer.drains.Load() != 1 {
		t.Fatal("engine did not drain active route")
	}
	if err := engine.Close(); err != nil {
		t.Fatal(err)
	}
	if replacementDialer.closes.Load() != 1 {
		t.Fatal("engine did not close active route")
	}
}

func TestEngineReportsDialerCreationFailure(t *testing.T) {
	var operation, reason string
	var logs []string
	engine, err := NewEngine(EngineConfig{
		Capacity: 3,
		Regions:  testRegions(),
		Logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
		OnTailcatFailure: func(gotOperation, gotReason string) {
			operation, reason = gotOperation, gotReason
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	failure := &net.OpError{
		Op:  "dial",
		Net: "udp",
		Err: &os.SyscallError{Syscall: "socket", Err: syscall.EMFILE},
	}
	engine.newDialer = func(tailtransport.DialerConfig) (sessionDialer, error) {
		return nil, failure
	}
	assignment := testAssignment("route-creation-failure", 7)

	_, err = engine.Attach(context.Background(), assignment)
	if !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("attach error = %v", err)
	}
	if operation != "create" || reason != "process_file_limit" {
		t.Fatalf("observed failure = (%q, %q)", operation, reason)
	}
	if len(logs) != 1 {
		t.Fatalf("logs = %q", logs)
	}
	for _, want := range []string{
		"operation=create",
		"reason=process_file_limit",
		`route_id="route-creation-failure"`,
		"version=7",
		"active=0",
		"limit=3",
		"worker: create route dialer",
	} {
		if !strings.Contains(logs[0], want) {
			t.Errorf("log %q does not contain %q", logs[0], want)
		}
	}
	for _, secret := range []string{assignment.Key.UntypedHexString(), assignment.Endpoint.PublisherPublicKey} {
		if strings.Contains(logs[0], secret) {
			t.Errorf("log contains assignment key material %q", secret)
		}
	}
}

func TestEngineReportsStartFailureAndRemovesRoute(t *testing.T) {
	var operation, reason string
	var logs []string
	engine, err := NewEngine(EngineConfig{
		Capacity: 1,
		Regions:  testRegions(),
		Logf: func(format string, args ...any) {
			logs = append(logs, fmt.Sprintf(format, args...))
		},
		OnTailcatFailure: func(gotOperation, gotReason string) {
			operation, reason = gotOperation, gotReason
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &fakeDialer{startErr: &net.OpError{
		Op:  "dial",
		Net: "udp",
		Err: &os.SyscallError{Syscall: "socket", Err: syscall.ENFILE},
	}}
	engine.newDialer = func(tailtransport.DialerConfig) (sessionDialer, error) {
		return dialer, nil
	}

	_, err = engine.Attach(context.Background(), testAssignment("route-start-failure", 2))
	if !errors.Is(err, syscall.ENFILE) {
		t.Fatalf("attach error = %v", err)
	}
	if operation != "start" || reason != "system_file_limit" {
		t.Fatalf("observed failure = (%q, %q)", operation, reason)
	}
	if capacity := engine.Capacity(); capacity.Active != 0 {
		t.Fatalf("capacity after failed start = %#v", capacity)
	}
	if dialer.closes.Load() != 1 {
		t.Fatalf("dialer closes = %d", dialer.closes.Load())
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "active=0") || !strings.Contains(logs[0], "limit=1") {
		t.Fatalf("logs = %q", logs)
	}
}

func TestTailcatFailureReasonIsBounded(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "process file limit",
			err: &net.OpError{Op: "dial", Net: "udp", Err: &os.SyscallError{
				Syscall: "socket", Err: syscall.EMFILE,
			}},
			want: "process_file_limit",
		},
		{
			name: "system file limit",
			err: &net.OpError{Op: "dial", Net: "udp", Err: &os.SyscallError{
				Syscall: "socket", Err: syscall.ENFILE,
			}},
			want: "system_file_limit",
		},
		{name: "deadline", err: fmt.Errorf("ping: %w", context.DeadlineExceeded), want: "timeout"},
		{name: "canceled", err: fmt.Errorf("ping: %w", context.Canceled), want: "canceled"},
		{name: "network", err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}, want: "network"},
		{name: "other", err: errors.New("specific internal failure"), want: "other"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			wrapped := fmt.Errorf("worker boundary: %w", test.err)
			if got := tailcatFailureReason(wrapped); got != test.want {
				t.Fatalf("reason = %q, want %q", got, test.want)
			}
		})
	}
}

func testAssignment(routeID string, version uint64) Assignment {
	return Assignment{
		RouteRef: RouteRef{RouteID: routeID, Version: version},
		Endpoint: tailtransport.Endpoint{Version: 1, PublisherPublicKey: key.NewNode().Public().String(), RelayRegion: "test"},
		Key:      key.NewNode(),
	}
}

func testRegions() map[string]*tailcfg.DERPRegion {
	return map[string]*tailcfg.DERPRegion{"test": {
		RegionID: 1,
		Nodes:    []*tailcfg.DERPNode{{RegionID: 1, HostName: "derp.example"}},
	}}
}

type fakeDialer struct {
	drains   atomic.Int32
	closes   atomic.Int32
	startErr error
}

func (d *fakeDialer) Start(context.Context) error { return d.startErr }

func (*fakeDialer) Open(context.Context) (net.Conn, error) {
	local, remote := net.Pipe()
	_ = remote.Close()
	return local, nil
}

func (d *fakeDialer) Drain(context.Context) error {
	d.drains.Add(1)
	return nil
}

func (d *fakeDialer) Close() error {
	d.closes.Add(1)
	return nil
}
