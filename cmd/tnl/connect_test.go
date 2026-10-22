package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisherjob"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

func TestPrivateInstallPreflightPrecedesClientAndSupervisorState(t *testing.T) {
	for _, command := range [][]string{
		{"connect", "orders", "--install"},
		{"publish", "127.0.0.1:5432", "--protocol=postgres", "--name=orders", "--install"},
		{"publish", "127.0.0.1:22", "--protocol=tcp", "--publisher=pub_missing", "--server=https://control.example", "--system", "--install"},
	} {
		t.Run(command[0]+"/"+command[1], func(t *testing.T) {
			root := t.TempDir()
			state, supervisor := filepath.Join(root, "client"), filepath.Join(root, "supervisor")
			args := append([]string{"--no-config"}, command...)
			args = append(args, "--state-dir="+state, "--system-state-dir="+supervisor)
			err := run(t.Context(), args, io.Discard, io.Discard)
			systemOwnerPreflight := slices.Contains(command, "--system") && os.Geteuid() != 0 && errors.Is(err, publisherjob.ErrUnsafeState)
			if reason, ok := failure.ReasonOf(err); !systemOwnerPreflight && (!ok || reason != failure.ServiceNotInstalled) {
				t.Fatalf("preflight = %v", err)
			}
			for _, path := range []string{state, supervisor} {
				if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
					t.Fatalf("install preflight changed %s: %v", path, err)
				}
			}
		})
	}
}

func TestConnectShorthandAndExplicitModes(t *testing.T) {
	for _, args := range [][]string{
		{"connect", "orders", "--listen", "15432"},
		{"connect", "start", "orders", "--detach"},
		{"connect", "start", "orders", "--install"},
	} {
		var flags cli
		parser, err := kong.New(&flags)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := parser.Parse(args)
		if err != nil {
			t.Fatal(err)
		}
		if parsed.Command() != "connect start <name>" || flags.Connect.Start.Name != "orders" {
			t.Fatalf("connect dispatch = %q, %+v", parsed.Command(), flags.Connect.Start)
		}
		if err := validateConnectMode(flags.Connect.Start); err != nil {
			t.Fatal(err)
		}
	}
	for _, flags := range []connectStartCommand{{System: true}, {Install: true, Detach: true}, {Foreground: true, Detach: true}, {Foreground: true, Install: true}} {
		if err := validateConnectMode(flags); err == nil {
			t.Fatalf("invalid connector mode accepted: %+v", flags)
		}
	}
}

func TestConnectListenRejectsNonLoopbackAndInvalidPorts(t *testing.T) {
	for _, value := range []string{"0.0.0.0:5432", "192.0.2.1:5432", "localhost:5432", "[::]:5432", "127.0.0.1:0", "65536", "bad"} {
		if _, err := connectListen(value); err == nil {
			t.Fatalf("unsafe listener %q accepted", value)
		}
	}
	for input, want := range map[string]string{"15432": "127.0.0.1:15432", "[::1]:13306": "[::1]:13306"} {
		if got, err := connectListen(input); err != nil || got != want {
			t.Fatalf("listener %q = %q, %v", input, got, err)
		}
	}
}

func TestConnectSelectionRequiresExactIdentityInventoryAndTeam(t *testing.T) {
	services := []controlv1.PrivateService{{Id: "first", Name: "orders", TeamId: "one"}, {Id: "second", Name: "orders", TeamId: "two"}}
	if _, err := privateServiceSelection(services, "orders", ""); err == nil {
		t.Fatal("ambiguous name accepted")
	}
	for _, selection := range [][2]string{{"orders", "two"}, {"second", ""}} {
		got, err := privateServiceSelection(services, selection[0], selection[1])
		if err != nil || got.Id != "second" {
			t.Fatalf("selection = %+v, %v", got, err)
		}
	}
	if _, err := privateServiceSelection(services, "second", "one"); err == nil {
		t.Fatal("exact ID bypassed team selection")
	}
	if _, err := privateServiceSelection(services, "absent", ""); err == nil {
		t.Fatal("unavailable service accepted")
	}
}
