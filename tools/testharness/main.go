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
	"strings"
	"syscall"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	tclog "github.com/testcontainers/testcontainers-go/log"
	"github.com/testcontainers/testcontainers-go/modules/compose"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	postgresImage = "mirror.gcr.io/library/postgres:17.6-alpine@sha256:ef257d85f76e48da1c64832459b59fcaba1a4dac97bf5d7450c77753542eee94"
	mysqlImage    = "mirror.gcr.io/library/mysql:8.4@sha256:6ea90827b1100f8f2ae306a539f86d2c264a26ed435a2a9f75551dd5c3aeb242"
)

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
	if len(os.Args) == 2 && os.Args[1] == "dns" {
		return runDNS(ctx)
	}
	if len(os.Args) == 2 && os.Args[1] == "runtime" {
		return runRuntime(ctx)
	}
	separator := -1
	for index, argument := range os.Args {
		if argument == "--" {
			separator = index
			break
		}
	}
	if separator != 2 || separator == len(os.Args)-1 {
		return errors.New("usage: testharness postgres|mysql -- go test [arguments...], or testharness dns")
	}
	command := os.Args[separator+1:]
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
	switch os.Args[1] {
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
	case "mysql":
		var container *mysql.MySQLContainer
		for range 3 {
			container, err = mysql.Run(ctx, mysqlImage,
				mysql.WithUsername("root"), mysql.WithPassword("testpass"), mysql.WithDatabase("mysql"),
				testcontainers.WithEnv(map[string]string{"MYSQL_ROOT_HOST": "%"}),
				testcontainers.WithCmdArgs("--require_secure_transport=OFF", "--auto_generate_certs=OFF"),
				reservedLoopbackPort("3306"),
				testcontainers.WithAdditionalWaitStrategy(wait.ForListeningPort("3306/tcp")),
			)
			if err == nil {
				break
			}
			if container == nil {
				return fmt.Errorf("start disposable MySQL: %w", err)
			}
			// docker can create the container but fail to bind its chosen host
			// port. remove that failed attempt before asking docker to choose again.
			canRetry := !container.IsRunning() && ctx.Err() == nil
			terminate(container)
			if !canRetry {
				return fmt.Errorf("start disposable MySQL: %w", err)
			}
		}
		if err != nil {
			return fmt.Errorf("start disposable MySQL after 3 attempts: %w", err)
		}
		defer terminate(container)
		code, output, err := container.Exec(ctx, []string{"mysql", "--protocol=socket", "--user=root", "--password=testpass",
			"--execute=CREATE USER 'tnl_client'@'%' IDENTIFIED WITH caching_sha2_password BY 'testpass'; GRANT SELECT ON mysql.* TO 'tnl_client'@'%';"})
		if err != nil || code != 0 {
			var message []byte
			if output != nil {
				message, _ = io.ReadAll(io.LimitReader(output, 4096))
			}
			return fmt.Errorf("configure disposable MySQL client: exit %d: %s: %v", code, strings.TrimSpace(string(message)), err)
		}
		host, err := container.Host(ctx)
		if err != nil {
			return fmt.Errorf("read disposable MySQL host: %w", err)
		}
		port, err := container.MappedPort(ctx, "3306/tcp")
		if err != nil {
			return fmt.Errorf("read disposable MySQL port: %w", err)
		}
		command = append(command, "-tnl-test-mysql-address="+net.JoinHostPort(host, port.Port()))
	default:
		return errors.New("test service must be postgres or mysql")
	}
	child := exec.CommandContext(ctx, command[0], command[1:]...)
	child.Dir = root
	child.Stdin, child.Stdout, child.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := child.Run(); err != nil {
		return fmt.Errorf("test command: %w", err)
	}
	return nil
}

func runDNS(ctx context.Context) error {
	root, err := repositoryRoot()
	if err != nil {
		return err
	}
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
