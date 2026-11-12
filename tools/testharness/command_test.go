package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestParseTestCommandSeparatesCompilationAndExecution(t *testing.T) {
	plan, err := parseTestCommand([]string{"go", "test", "-race", "-v", "./first", "./second", "-run", "^TestSelected$/child", "-skip=^TestIgnored$", "-count=2", "-timeout=3m", "-args", "-tnl-test-tier=integration"})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(plan.packages, []string{"./first", "./second"}) || !reflect.DeepEqual(plan.buildFlags, []string{"-race"}) {
		t.Fatalf("compilation inputs = %+v", plan)
	}
	want := []string{"-test.v=true", "-test.run=^TestSelected$/child", "-test.skip=^TestIgnored$", "-test.count=2", "-test.timeout=3m", "-tnl-test-tier=integration"}
	if !reflect.DeepEqual(plan.arguments, want) || plan.run != "^TestSelected$/child" || plan.skip != "^TestIgnored$" || !plan.explicitRun {
		t.Fatalf("execution inputs = %+v", plan)
	}
	for _, command := range [][]string{
		{"go", "test", "-race=false", "-v=false"},
		{"go", "test"},
	} {
		plan, err := parseTestCommand(command)
		if err != nil || !reflect.DeepEqual(plan.packages, []string{"."}) || !strings.Contains(strings.Join(plan.arguments, " "), "-test.timeout=10m") {
			t.Fatalf("default test invocation = %+v, %v", plan, err)
		}
	}
}

func TestPreparedInvocationRunsWithoutGoAndRemovesArtifactsAfterFailure(t *testing.T) {
	prepared, err := prepareTests(t.Context(), ".", []string{"go", "test", "./testdata/shards", "-run=^TestAlpha$", "-args", "-tnl-probe=missing"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := prepared.close(); err != nil {
			t.Error(err)
		}
	})
	info, err := os.Stat(prepared.binaries[0].path)
	if err != nil || info.Mode().Perm() != 0o555 {
		t.Fatalf("test executable is not read-only: %v, %v", info, err)
	}
	t.Setenv("PATH", t.TempDir())
	if err := prepared.selectShard(t.Context(), ""); err != nil {
		t.Fatal(err)
	}
	err = prepared.run(t.Context(), nil)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 1 {
		t.Fatalf("test failure lost its exit: %v", err)
	}
	if err := prepared.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(prepared.directory); !os.IsNotExist(err) {
		t.Fatalf("failed invocation artifacts remain: %v", err)
	}
}

func TestPreparationFailureRemovesArtifacts(t *testing.T) {
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
	_, err := prepareTests(t.Context(), ".", []string{"go", "test", "./testdata/missing"})
	if err == nil {
		t.Fatal("prepared a missing package")
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed preparation left artifacts: %v, %v", entries, err)
	}
}

func TestRunTestCommandRejectsEmptySelectionBeforeStartingPostgres(t *testing.T) {
	temporary := t.TempDir()
	t.Setenv("TMPDIR", temporary)
	err := runTestCommand(t.Context(), ".", harnessArguments{
		Service: "postgres",
		Command: []string{"go", "test", "./testdata/shards", "-run=^TestMissing$", "-args", "-tnl-probe=kept"},
	})
	if err == nil || !strings.Contains(err.Error(), "selected no tests") {
		t.Fatalf("empty selection reached service startup: %v", err)
	}
	entries, err := os.ReadDir(temporary)
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty selection left artifacts: %v, %v", entries, err)
	}
}

func TestPreparedInvocationHonorsCanceledContext(t *testing.T) {
	directory := t.TempDir()
	// cancellation must not launch a test process.
	binary := filepath.Join(directory, "blocked")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nexec /bin/sleep 30\n"), 0o555); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	prepared := &preparedTests{binaries: []testBinary{{path: binary, directory: directory}}}
	if err := prepared.run(ctx, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation was lost: %v", err)
	}
}

func TestPreparedInvocationJoinsChildBeforeArtifactCleanup(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("parent failure=%t", fail), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			record := filepath.Join(t.TempDir(), "cleanup")
			prepared, err := prepareTests(t.Context(), ".", []string{"go", "test", "./testdata/children", "-run=^TestParent$", "-args", "-tnl-parent-address=" + listener.Addr().String(), "-tnl-record=" + record, fmt.Sprintf("-tnl-parent-fail=%t", fail)})
			if err != nil {
				t.Fatal(err)
			}
			prepared.arguments = append(prepared.arguments, "-tnl-artifacts="+prepared.directory)
			cause := errors.New("cancel prepared fixture")
			ctx, cancel := context.WithCancelCause(t.Context())
			done := make(chan error, 1)
			go func() { done <- errors.Join(prepared.run(ctx, nil), prepared.close()) }()
			joined := false
			t.Cleanup(func() {
				cancel(cause)
				if !joined {
					<-done
				}
			})
			if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			connection, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
				t.Fatal(err)
			}
			var child int
			if _, err := fmt.Fscanln(connection, &child); err != nil {
				t.Fatal(err)
			}
			cancel(cause)
			var state string
			if _, err := fmt.Fscanln(connection, &state); err != nil || state != "stopping" {
				t.Fatalf("child cleanup did not start: %q, %v", state, err)
			}
			select {
			case err := <-done:
				joined = true
				t.Fatalf("owner returned before child cleanup: %v", err)
			default:
			}
			if _, err := os.Stat(prepared.directory); err != nil {
				t.Fatalf("artifacts removed during child cleanup: %v", err)
			}
			if _, err := fmt.Fprintln(connection, "finish"); err != nil {
				t.Fatal(err)
			}
			err = <-done
			joined = true
			if !errors.Is(err, cause) {
				t.Fatalf("cancellation cause was lost: %v", err)
			}
			var exit *exec.ExitError
			if errors.As(err, &exit) != fail {
				t.Fatalf("independent test failure changed: %v", err)
			}
			if strings.Contains(err.Error(), "exceeded termination grace") {
				t.Fatalf("graceful child cleanup was killed: %v", err)
			}
			if err := syscall.Kill(child, 0); !errors.Is(err, syscall.ESRCH) {
				t.Fatalf("child remains after owner returned: %v", err)
			}
			data, err := os.ReadFile(record)
			if err != nil || string(data) != "child cleaned\nparent joined child\n" {
				t.Fatalf("cleanup/reaping evidence = %q, %v", data, err)
			}
			if _, err := os.Stat(prepared.directory); !os.IsNotExist(err) {
				t.Fatalf("artifacts remain after child join: %v", err)
			}
		})
	}
}

func TestPreparedInvocationKillsAndJoinsAnUnresponsiveTest(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	prepared, err := prepareTests(t.Context(), ".", []string{"go", "test", "./testdata/children", "-run=^TestUnresponsive$", "-args", "-tnl-parent-address=" + listener.Addr().String()})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- errors.Join(prepared.run(ctx, nil), prepared.close()) }()
	joined := false
	t.Cleanup(func() {
		cancel()
		if !joined {
			<-done
		}
	})
	if err := listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer connection.Close()
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Fscanln(connection, &pid); err != nil {
		t.Fatal(err)
	}
	cancel()
	var state string
	if _, err := fmt.Fscanln(connection, &state); err != nil || state != "stopping" {
		t.Fatalf("test did not receive termination: %q, %v", state, err)
	}
	err = <-done
	joined = true
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "exceeded termination grace") {
		t.Fatalf("forced cancellation was lost: %v", err)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState.Sys().(syscall.WaitStatus).Signal() != syscall.SIGKILL {
		t.Fatalf("test process was not killed and joined: %v", err)
	}
	if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("test remains after forced join: %v", err)
	}
	if _, err := os.Stat(prepared.directory); !os.IsNotExist(err) {
		t.Fatalf("artifacts remain after forced join: %v", err)
	}
}

func TestPreparationBuildsOneCLIWithTheConsumerInstrumentation(t *testing.T) {
	for _, consumer := range []string{"cmd/tnl", "tests/integration/connector"} {
		t.Run(consumer, func(t *testing.T) {
			root := t.TempDir()
			log := filepath.Join(root, "commands")
			goPath := filepath.Join(root, "go")
			program := `#!/bin/sh
printf '%s\n' "$*" >> "$COMMANDS"
while [ "$1" != -o ]; do shift; done
printf '#!/bin/sh\nexit 0\n' > "$2"
`
			if err := os.WriteFile(goPath, []byte(program), 0o755); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", root)
			t.Setenv("COMMANDS", log)
			prepared, err := prepareTests(t.Context(), root, []string{"go", "test", "-race", "./" + consumer})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := prepared.close(); err != nil {
					t.Error(err)
				}
			})
			commands, err := os.ReadFile(log)
			if err != nil {
				t.Fatal(err)
			}
			lines := strings.Split(strings.TrimSpace(string(commands)), "\n")
			if len(lines) != 2 || !strings.HasPrefix(lines[0], "test -c -buildvcs=false -o ") || !strings.Contains(lines[0], " -race ") || !strings.HasPrefix(lines[1], "build -buildvcs=false -o ") {
				t.Fatalf("unexpected preparation commands:\n%s", commands)
			}
			if strings.Contains(lines[1], " -race ") != (consumer == "tests/integration/connector") {
				t.Fatalf("CLI race instrumentation changed: %s", lines[1])
			}
			cli := filepath.Join(prepared.directory, "tnl")
			if !strings.Contains(strings.Join(prepared.arguments, " "), "-tnl-cli-binary="+cli) {
				t.Fatal("missing prepared CLI argument")
			}
			info, err := os.Stat(cli)
			if err != nil || info.Mode().Perm() != 0o555 {
				t.Fatalf("CLI is not read-only: %v, %v", info, err)
			}
		})
	}
}
