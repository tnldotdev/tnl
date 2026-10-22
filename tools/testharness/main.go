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
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	postgresImage = "mirror.gcr.io/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
	mysqlImage    = "mirror.gcr.io/library/mysql:8.4@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"
	redisImage    = "mirror.gcr.io/library/redis:7.4-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499"
)

type harnessArguments struct {
	TestShard string   `name:"tnl-test-shard" help:"Run one stable test-name shard, numbered 1/N through N/N."`
	Service   string   `arg:"" enum:"postgres,mysql,postgres-tls,mysql-tls,redis,dns,runtime,publisher-install" help:"Disposable service for the test command."`
	Command   []string `arg:"" optional:"" passthrough:"" sep:"none" help:"Test command and arguments after --."`
}

func parseHarnessArguments(arguments []string) (harnessArguments, error) {
	var parsed harnessArguments
	parser, err := kong.New(&parsed, kong.Name("testharness"), kong.Writers(os.Stdout, os.Stderr))
	if err != nil {
		return parsed, err
	}
	if _, err := parser.Parse(arguments); err != nil {
		return parsed, err
	}
	if parsed.Service == "dns" || parsed.Service == "runtime" || parsed.Service == "publisher-install" {
		if len(parsed.Command) != 0 || parsed.TestShard != "" {
			return parsed, errors.New("dns, runtime, and publisher-install do not take a test command or shard")
		}
	} else if len(parsed.Command) < 2 || parsed.Command[0] != "--" {
		return parsed, errors.New("usage: testharness postgres|postgres-tls|mysql|mysql-tls|redis -- go test [arguments...], or testharness dns|runtime")
	} else {
		// kong's passthrough includes the separator; only the child command
		// and its arguments belong in the process we launch.
		parsed.Command = parsed.Command[1:]
	}
	if _, err := parseTestShard(parsed.TestShard); err != nil {
		return parsed, err
	}
	return parsed, nil
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
	command, err := shardGoTestCommand(ctx, root, arguments.Command, arguments.TestShard)
	if err != nil {
		return err
	}
	switch arguments.Service {
	case "postgres-tls", "mysql", "mysql-tls":
		fixture, err := startDatabaseTLS(ctx, arguments.Service)
		if err != nil {
			return err
		}
		defer fixture.Close()
		command = append(command, fixture.Flags...)
	case "postgres":
		container, err := postgres.Run(ctx, postgresImage, postgres.BasicWaitStrategies(), loopbackPort("5432"))
		if err != nil {
			return fmt.Errorf("start disposable PostgreSQL: %w", err)
		}
		defer terminate(container)
		address, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			return fmt.Errorf("read disposable PostgreSQL address: %w", err)
		}
		command = append(command, "-tnl-test-postgres-url="+address)
	case "redis":
		container, err := testcontainers.Run(ctx, redisImage,
			testcontainers.WithExposedPorts("6379/tcp"), loopbackPort("6379"),
			testcontainers.WithCmd("redis-server", "--requirepass", "testpass"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp")),
		)
		if err != nil {
			return fmt.Errorf("start disposable Redis: %w", err)
		}
		defer terminate(container)
		host, err := container.Host(ctx)
		if err != nil {
			return fmt.Errorf("read disposable Redis host: %w", err)
		}
		port, err := container.MappedPort(ctx, "6379/tcp")
		if err != nil {
			return fmt.Errorf("read disposable Redis port: %w", err)
		}
		command = append(command, "-tnl-test-redis-address="+net.JoinHostPort(host, port.Port()))
	default:
		return errors.New("test service must be postgres, mysql, or redis")
	}
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Dir = root
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		return fmt.Errorf("test command: %w", err)
	}
	return nil
}

func runDNS(ctx context.Context, root string) error {
	stack, err := compose.NewDockerComposeWith(compose.WithStackFiles(
		filepath.Join(root, "internal/tnldruntime/testdata/dns-integration.compose.yaml")))
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
			if logErr == nil && state.ExitCode != 0 {
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

func terminate(container testcontainers.Container) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := container.Terminate(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "remove disposable test container:", err)
	}
}
