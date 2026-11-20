// command testharness owns disposable services for explicit Go test tiers.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/spf13/cobra"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/modules/compose"
)

const (
	postgresImage = "docker.io/library/postgres:17.10-alpine@sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193"
	mysqlImage    = "docker.io/library/mysql:8.4.13@sha256:a81d043930e51745522bd5c430961cf8286f0a23f0a9a2a6e0108f7ea71b0902"
	redisImage    = "docker.io/library/redis:7.4.11-alpine@sha256:d9436322172a5b482c187bf1f363d3c4fea086fcca6b9c8a94de8f0f39ed3193"
)

type harnessArguments struct {
	TestShard string
	Service   string
	Command   []string
}

func parseHarnessArguments(arguments []string) (harnessArguments, error) {
	var parsed harnessArguments
	root := &cobra.Command{Use: "testharness", SilenceErrors: true, SilenceUsage: true, Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error { return errors.New("suite is required") }}
	root.CompletionOptions.DisableDefaultCmd = true
	root.PersistentFlags().StringVar(&parsed.TestShard, "tnl-test-shard", "", "Run one stable test-name shard, numbered 1/N through N/N.")
	for _, suite := range []string{"postgres", "postgres-tls", "mysql", "mysql-tls", "redis", "deployment-database", "connector-wasm", "connections", "dns", "runtime", "publisher-install"} {
		root.AddCommand(&cobra.Command{Use: suite, RunE: func(cmd *cobra.Command, args []string) error {
			parsed.Service = suite
			switch suite {
			case "dns", "runtime", "publisher-install":
				if len(args) != 0 || cmd.ArgsLenAtDash() >= 0 || parsed.TestShard != "" {
					return errors.New("dns, runtime, and publisher-install do not take a test command or shard")
				}
			default:
				if cmd.ArgsLenAtDash() != 0 || len(args) == 0 {
					return errors.New("usage: testharness postgres|postgres-tls|mysql|mysql-tls|redis|connections -- go test [arguments...]")
				}
				parsed.Command = args
			}
			_, err := parseTestShard(parsed.TestShard)
			return err
		}})
	}
	root.SetArgs(arguments)
	err := root.Execute()
	return parsed, err
}

func main() {
	tclog.SetDefault(tclog.NewNoopLogger())
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	arguments, err := parseHarnessArguments(os.Args[1:])
	if err != nil {
		return err
	}
	if arguments.Service == "" {
		return nil
	}
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	if arguments.Service == "dns" {
		return runDNS(ctx, root)
	}
	if arguments.Service == "runtime" {
		return runRuntime(ctx, root)
	}
	if arguments.Service == "publisher-install" {
		return runPublisherInstall(ctx, root)
	}
	return runTestCommand(ctx, root, arguments)
}

func runDNS(ctx context.Context, root string) error {
	stack, err := compose.NewDockerComposeWith(compose.WithStackFiles(
		filepath.Join(root, "tests/integration/fixtures/dns/compose.yaml")))
	if err != nil {
		return fmt.Errorf("configure disposable DNS test topology: %w", err)
	}
	defer stack.Close()
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := stack.Down(cleanup, compose.RemoveOrphans(true), compose.RemoveVolumes(true)); err != nil {
			fmt.Fprintln(os.Stderr, "remove disposable DNS test topology:", err)
		}
	}()
	if err := stack.Up(ctx); err != nil {
		return fmt.Errorf("start disposable DNS test topology: %w", err)
	}
	container, err := stack.ServiceContainer(ctx, "test")
	if err != nil {
		return fmt.Errorf("find DNS test process: %w", err)
	}
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		state, err := container.State(ctx)
		if err != nil {
			return fmt.Errorf("read DNS test process state: %w", err)
		}
		if !state.Running {
			logs, logErr := container.Logs(ctx)
			// successful DNS proofs contain bounded per-service measurements too.
			if logErr == nil {
				defer logs.Close()
				_, _ = io.Copy(os.Stdout, io.LimitReader(logs, 1<<20))
			} else if logs != nil {
				_ = logs.Close()
			}
			if state.ExitCode != 0 {
				return fmt.Errorf("DNS integration test exited with status %d", state.ExitCode)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func repositoryRoot() (string, error) {
	directory, err := os.Getwd()
	if err != nil {
		return "", err
	}
	root := filepath.Clean(filepath.Join(directory, "../.."))
	if _, err := os.Stat(filepath.Join(root, "Taskfile.yml")); err != nil {
		return "", fmt.Errorf("locate repository root: %w", err)
	}
	return root, nil
}

func loopbackPort(port string) testcontainers.CustomizeRequestOption {
	return testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
		if config.PortBindings == nil {
			config.PortBindings = make(network.PortMap)
		}
		config.PortBindings[network.MustParsePort(port+"/tcp")] = []network.PortBinding{{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: "0"}}
	})
}

// reservedLoopbackPort asks the OS for a free port before assigning it to a
// disposable container. docker's port-0 allocator can select a busy host port
// after the larger integration suite has opened many short-lived sockets.
func reservedLoopbackPort(port string) testcontainers.CustomizeRequestOption {
	return func(request *testcontainers.GenericContainerRequest) error {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return fmt.Errorf("select disposable MySQL port: %w", err)
		}
		selected := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
		if err := listener.Close(); err != nil {
			return fmt.Errorf("release disposable MySQL port: %w", err)
		}
		return testcontainers.WithHostConfigModifier(func(config *container.HostConfig) {
			if config.PortBindings == nil {
				config.PortBindings = make(network.PortMap)
			}
			config.PortBindings[network.MustParsePort(port+"/tcp")] = []network.PortBinding{{HostIP: netip.MustParseAddr("127.0.0.1"), HostPort: selected}}
		}).Customize(request)
	}
}

func terminate(container testcontainers.Container) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := container.Terminate(ctx); err != nil {
		return fmt.Errorf("remove disposable test container: %w", err)
	}
	return nil
}
