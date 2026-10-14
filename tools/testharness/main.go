// command testharness owns disposable services for explicit Go test tiers.
package main

import (
	"bytes"
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

	"github.com/alecthomas/kong"
	"github.com/moby/moby/api/pkg/stdcopy"
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
	redisImage    = "mirror.gcr.io/library/redis:7.4-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499"
	sshImage      = "ghcr.io/linuxserver/openssh-server:latest@sha256:46f115de7c251558297e7e87566fc3fc08544b63e55502b5cf294454db5d29d1"
)

type harnessArguments struct {
	Service string   `arg:"" enum:"postgres,postgres-tls,mysql,redis,ssh,dns,runtime" help:"Disposable service for the test command."`
	Command []string `arg:"" optional:"" passthrough:"" sep:"none" help:"Test command and arguments after --."`
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
	if parsed.Service == "dns" || parsed.Service == "runtime" {
		if len(arguments) != 1 {
			return parsed, errors.New("dns and runtime do not take a test command")
		}
	} else if len(arguments) < 3 || arguments[1] != "--" || len(parsed.Command) == 0 {
		return parsed, errors.New("usage: testharness postgres|postgres-tls|mysql|redis|ssh -- go test [arguments...], or testharness dns|runtime")
	} else {
		// kong's passthrough includes the separator; only the child command
		// and its arguments belong in the process we launch.
		parsed.Command = parsed.Command[1:]
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
	command := arguments.Command
	switch arguments.Service {
	case "postgres", "postgres-tls":
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
		if arguments.Service == "postgres-tls" {
			certificate, key, rootCA, cleanup, err := preparePostgresTLS(ctx, container)
			if cleanup != nil {
				defer cleanup()
			}
			if err != nil {
				return fmt.Errorf("enable disposable PostgreSQL TLS: %w", err)
			}
			command = append(command, "-tnl-test-postgres-cert="+certificate,
				"-tnl-test-postgres-key="+key, "-tnl-test-postgres-ca="+rootCA)
		}
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
	case "ssh":
		container, err := testcontainers.Run(ctx, sshImage,
			testcontainers.WithExposedPorts("2222/tcp"), loopbackPort("2222"),
			testcontainers.WithEnv(map[string]string{
				"PUID": "1000", "PGID": "1000", "USER_NAME": "tnl_test",
				"PASSWORD_ACCESS": "true", "USER_PASSWORD": "testpass",
			}),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("2222/tcp")),
		)
		if err != nil {
			return fmt.Errorf("start disposable SSH server: %w", err)
		}
		defer terminate(container)
		host, err := container.Host(ctx)
		if err != nil {
			return fmt.Errorf("read disposable SSH host: %w", err)
		}
		port, err := container.MappedPort(ctx, "2222/tcp")
		if err != nil {
			return fmt.Errorf("read disposable SSH port: %w", err)
		}
		code, output, err := container.Exec(ctx, []string{"ssh-keyscan", "-T", "5", "-p", "2222", "-t", "ed25519", "127.0.0.1"})
		var key bytes.Buffer
		var readErr error
		if output != nil {
			_, readErr = stdcopy.StdCopy(&key, &key, io.LimitReader(output, 4096))
		}
		if err != nil || code != 0 {
			return fmt.Errorf("read disposable SSH host key: exit %d: %v: %s", code, err, strings.TrimSpace(key.String()))
		}
		if readErr != nil {
			return fmt.Errorf("read disposable SSH host key: %w", readErr)
		}
		hostKey := ""
		for line := range strings.SplitSeq(key.String(), "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "[127.0.0.1]:2222" && fields[1] == "ssh-ed25519" {
				hostKey = fields[1] + " " + fields[2]
			}
		}
		if hostKey == "" {
			return errors.New("disposable SSH host key is missing")
		}
		// the go test runs on the host, so it connects to docker's mapped port.
		// pass the fixture sshd's public key separately for the visiting SSH
		// client to pin; tnl forwards SSH bytes without checking the host key.
		command = append(command, "-tnl-test-ssh-address="+net.JoinHostPort(host, port.Port()),
			"-tnl-test-ssh-host-key="+hostKey)
	default:
		return errors.New("test service must be postgres, mysql, redis, or ssh")
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
