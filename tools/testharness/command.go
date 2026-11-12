package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"
)

type testCommand struct {
	packages, buildFlags, arguments []string
	run, skip                       string
	explicitRun                     bool
}

// accept the go test options used by the owned tasks, not a second go command.
func parseTestCommand(command []string) (testCommand, error) {
	plan := testCommand{run: "."}
	if len(command) < 2 || command[0] != "go" || command[1] != "test" {
		return plan, errors.New("testharness requires a go test command")
	}
	seen := make(map[string]bool)
	for index := 2; index < len(command); index++ {
		argument := command[index]
		if argument == "-args" {
			plan.arguments = append(plan.arguments, command[index+1:]...)
			break
		}
		if !strings.HasPrefix(argument, "-") {
			if (argument != "." && !strings.HasPrefix(argument, "./")) || strings.Contains(argument, "...") {
				return plan, errors.New("testharness requires explicit local package directories")
			}
			plan.packages = append(plan.packages, argument)
			continue
		}
		name, value, assigned := strings.Cut(strings.TrimPrefix(argument, "-"), "=")
		if seen[name] {
			return plan, fmt.Errorf("testharness requires a single -%s option", name)
		}
		seen[name] = true
		switch name {
		case "race":
			plan.buildFlags = append(plan.buildFlags, argument)
			continue
		case "v":
			if !assigned {
				value = "true"
			}
		case "run", "skip", "count", "timeout":
			if !assigned {
				index++
				if index == len(command) || strings.HasPrefix(command[index], "-") {
					return plan, fmt.Errorf("testharness requires a value for -%s", name)
				}
				value = command[index]
			}
		default:
			return plan, fmt.Errorf("unsupported testharness Go test option -%s", name)
		}
		if name == "run" {
			plan.run, plan.explicitRun = value, true
		}
		if name == "skip" {
			plan.skip = value
		}
		plan.arguments = append(plan.arguments, "-test."+name+"="+value)
	}
	if len(plan.packages) == 0 {
		plan.packages = []string{"."}
	}
	if !seen["timeout"] {
		plan.arguments = append(plan.arguments, "-test.timeout=10m")
	}
	return plan, nil
}

type testBinary struct {
	path, directory string
}

type preparedTests struct {
	directory string
	binaries  []testBinary
	arguments []string
	plan      testCommand
}

// compilation finishes before disposable services and test timeout clocks start.
func prepareTests(ctx context.Context, root string, command []string) (_ *preparedTests, retErr error) {
	plan, err := parseTestCommand(command)
	if err != nil {
		return nil, err
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	directory, err := os.MkdirTemp("", "tnl-tests-")
	if err != nil {
		return nil, err
	}
	prepared := &preparedTests{directory: directory, plan: plan, arguments: slices.Clone(plan.arguments)}
	defer func() {
		if retErr != nil {
			retErr = errors.Join(retErr, prepared.close())
		}
	}()
	var needsCLI, cliRace bool
	for index, packagePath := range plan.packages {
		packageDirectory := filepath.Join(root, packagePath)
		binary := testBinary{path: filepath.Join(directory, fmt.Sprintf("%d.test", index)), directory: packageDirectory}
		build := append([]string{"test", "-c", "-buildvcs=false", "-o", binary.path}, plan.buildFlags...)
		build = append(build, packageDirectory)
		if err := runBuild(ctx, root, build); err != nil {
			return nil, err
		}
		if err := os.Chmod(binary.path, 0o555); err != nil {
			return nil, err
		}
		prepared.binaries = append(prepared.binaries, binary)
		if packageDirectory == filepath.Join(root, "cmd/tnl") || packageDirectory == filepath.Join(root, "tests/integration/connector") {
			needsCLI = true
			cliRace = cliRace || packageDirectory == filepath.Join(root, "tests/integration/connector")
		}
	}
	if needsCLI {
		cli := filepath.Join(directory, "tnl")
		build := []string{"build", "-buildvcs=false", "-o", cli}
		// cli workflows use an ordinary cli; connection-owner proofs instrument it.
		if cliRace {
			build = append(build, plan.buildFlags...)
		}
		if err := runBuild(ctx, root, append(build, "./cmd/tnl")); err != nil {
			return nil, err
		}
		if err := os.Chmod(cli, 0o555); err != nil {
			return nil, err
		}
		prepared.arguments = append(prepared.arguments, "-tnl-cli-binary="+cli)
	}
	return prepared, nil
}

func runBuild(ctx context.Context, root string, arguments []string) error {
	command := exec.CommandContext(ctx, "go", arguments...)
	command.Dir = root
	command.Stdout, command.Stderr = os.Stdout, os.Stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("prepare test executable: %w", err)
	}
	return nil
}

func (p *preparedTests) close() error { return os.RemoveAll(p.directory) }

func (p *preparedTests) run(ctx context.Context, flags []string) error {
	var result error
	for _, binary := range p.binaries {
		command := exec.Command(binary.path, append(slices.Clone(p.arguments), flags...)...)
		command.Dir = binary.directory
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stderr
		if err := runTestProcess(ctx, command); err != nil {
			result = errors.Join(result, fmt.Errorf("test %s: %w", binary.directory, err))
		}
		if cause := context.Cause(ctx); cause != nil {
			if !errors.Is(result, cause) {
				result = errors.Join(result, cause)
			}
			return result
		}
	}
	return result
}

// a test process owns its process group, including ordinary cli/sdk children.
// always join Wait and group shutdown before infrastructure or artifact cleanup.
func runTestProcess(ctx context.Context, command *exec.Cmd) (result error) {
	defer func() {
		if cause := context.Cause(ctx); cause != nil && !errors.Is(result, cause) {
			result = errors.Join(result, cause)
		}
	}()
	if cause := context.Cause(ctx); cause != nil {
		return cause
	}
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	// discovery captures output; a retained descriptor must not block Wait forever.
	command.WaitDelay = time.Second
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	waiting := (<-chan error)(done)
	select {
	case result = <-waiting:
		waiting = nil
	case <-ctx.Done():
		result = context.Cause(ctx)
	}
	group := command.Process.Pid
	if waiting == nil {
		alive, err := testGroupAlive(group)
		if !alive {
			return errors.Join(result, err)
		}
		result = errors.Join(result, errors.New("test process exited with remaining subprocesses"))
	}
	result = errors.Join(result, signalTestGroup(group, syscall.SIGTERM))
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	killed := false
	for {
		alive, err := testGroupAlive(group)
		if err != nil || !alive {
			if err != nil {
				result = errors.Join(result, signalTestGroup(group, syscall.SIGKILL))
			}
			if waiting != nil {
				result = errors.Join(result, <-waiting)
			}
			return errors.Join(result, err)
		}
		select {
		case err := <-waiting:
			result = errors.Join(result, err)
			waiting = nil
		case <-poll.C:
		case <-deadline.C:
			if killed {
				if waiting != nil {
					result = errors.Join(result, <-waiting)
				}
				return errors.Join(result, errors.New("test process group remains after SIGKILL"))
			}
			result = errors.Join(result, errors.New("test process group exceeded termination grace; killed"), signalTestGroup(group, syscall.SIGKILL))
			killed = true
			// grandchildren are reaped by their parent or the operating system, not by Wait above.
			deadline.Reset(5 * time.Second)
		}
	}
}

func testGroupAlive(group int) (bool, error) {
	err := syscall.Kill(-group, 0)
	if errors.Is(err, syscall.ESRCH) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("inspect test process group: %w", err)
	}
	return true, nil
}

func signalTestGroup(group int, signal syscall.Signal) error {
	if err := syscall.Kill(-group, signal); err != nil && !errors.Is(err, syscall.ESRCH) {
		return fmt.Errorf("signal test process group %s: %w", signal, err)
	}
	return nil
}

func runTestCommand(ctx context.Context, root string, arguments harnessArguments) (retErr error) {
	prepared, err := prepareTests(ctx, root, arguments.Command)
	if err != nil {
		return err
	}
	defer func() { retErr = errors.Join(retErr, prepared.close()) }()
	if err := prepared.selectShard(ctx, arguments.TestShard); err != nil {
		return err
	}
	flags, cleanup, err := startTestService(ctx, arguments.Service)
	if cleanup != nil {
		defer func() { retErr = errors.Join(retErr, cleanup()) }()
	}
	if err != nil {
		return err
	}
	return prepared.run(ctx, flags)
}
