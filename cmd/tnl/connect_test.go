package main

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/alecthomas/kong"
	clientSupervisor "github.com/tnldotdev/tnl/internal/client/supervisor"
	"github.com/tnldotdev/tnl/internal/failure"
)

func TestPrivateInstallPreflightPrecedesClientAndSupervisorState(t *testing.T) {
	for _, command := range [][]string{
		{"connect", "orders", "--install"},
		{"publish", "127.0.0.1:5432", "--protocol=postgres", "--name=orders", "--install"},
		{"publish", "127.0.0.1:22", "--protocol=tcp", "--publisher-identity=pub_missing", "--server=https://control.example", "--system", "--install"},
	} {
		t.Run(command[0]+"/"+command[1], func(t *testing.T) {
			root := t.TempDir()
			state, supervisor := filepath.Join(root, "client"), filepath.Join(root, "supervisor")
			args := append([]string{"--no-config"}, command...)
			args = append(args, "--state-dir="+state, "--system-state-dir="+supervisor)
			err := run(t.Context(), args, io.Discard, io.Discard)
			systemOwnerPreflight := slices.Contains(command, "--system") && os.Geteuid() != 0 && errors.Is(err, clientSupervisor.ErrUnsafeState)
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
