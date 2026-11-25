package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	installedjobs "github.com/tnldotdev/tnl/internal/installed"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func TestConnectAvailableReportsOnlyObservedRuns(t *testing.T) {
	runID, number := "run_observed", int64(1)
	services := []controlv1.ServiceSummary{
		{Name: "db", TeamName: "shop", Id: "svc_db", Enabled: true, ServiceRunId: &runID, RunNumber: &number},
		{Name: "web", TeamName: "shop", Id: "svc_web", Enabled: true},
		{Name: "api", TeamName: "shop", Id: "svc_api", Enabled: true, RunNumber: &number},
		{Name: "old", TeamName: "shop", Id: "svc_old", ServiceRunId: &runID, RunNumber: &number},
	}
	var out bytes.Buffer
	if err := writeAvailableConnectServices(&out, services); err != nil {
		t.Fatal(err)
	}
	got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	for i := range got {
		got[i] = strings.Join(strings.Fields(got[i]), " ")
	}
	if !slices.Equal(got, []string{"SERVICE TEAM STATUS SERVICE ID", "db shop ready run reported svc_db", "web shop run not reported svc_web", "api shop run not reported svc_api", "old shop disabled svc_old"}) {
		t.Fatalf("unexpected connector inventory:\n%s", &out)
	}
}

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
			systemOwnerPreflight := slices.Contains(command, "--system") && os.Geteuid() != 0 && errors.Is(err, installedjobs.ErrUnsafeState)
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
		parser := commandForTest(&flags, io.Discard)
		parsed, err := parser(args)
		if err != nil {
			t.Fatal(err)
		}
		if commandID(parsed) != "connect start <name>" || flags.Connect.Start.Name != "orders" {
			t.Fatalf("connect dispatch = %q, %+v", commandID(parsed), flags.Connect.Start)
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

func TestConnectDistinguishesFlagTerminatorFromClientArgs(t *testing.T) {
	for _, test := range []struct {
		args   []string
		client []string
	}{
		{[]string{"connect", "start", "--", "orders"}, nil},
		{[]string{"connect", "--", "orders"}, nil},
		{[]string{"connect", "orders", "--", "custom", "--arg"}, []string{"custom", "--arg"}},
		{[]string{"connect", "start", "--client", "psql", "orders", "--", "-c", "SELECT 1"}, []string{"-c", "SELECT 1"}},
		{[]string{"connect", "start", "--client", "psql", "--", "orders"}, nil},
	} {
		var flags cli
		_, err := commandForTest(&flags, io.Discard)(test.args)
		if err != nil || flags.Connect.Start.Name != "orders" || !slices.Equal(flags.Connect.Start.clientArgs, test.client) {
			t.Errorf("%v: selector %q, client args %v, error %v", test.args, flags.Connect.Start.Name, flags.Connect.Start.clientArgs, err)
		}
	}
}
