package main

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func startTestService(ctx context.Context, service string) ([]string, func() error, error) {
	switch service {
	case "deployment-database":
		flags, closeControl, err := startTestService(ctx, "postgres")
		if err != nil {
			return flags, closeControl, err
		}
		target, err := startDatabaseTLS(ctx, "postgres-tls")
		if err != nil {
			return nil, closeControl, err
		}
		return append(flags, target.Flags...), func() error { return errors.Join(target.Close(), closeControl()) }, nil
	case "connections":
		return nil, nil, nil
	case "postgres-tls", "mysql", "mysql-tls":
		fixture, err := startDatabaseTLS(ctx, service)
		if err != nil {
			return nil, nil, err
		}
		return fixture.Flags, fixture.Close, nil
	case "postgres":
		if err := prepareFixtureImage(ctx, postgresImage); err != nil {
			return nil, nil, err
		}
		container, err := postgres.Run(ctx, postgresImage, postgres.BasicWaitStrategies(), loopbackPort("5432"))
		var cleanup func() error
		if container != nil {
			cleanup = func() error { return terminate(container) }
		}
		if err != nil {
			return nil, cleanup, fmt.Errorf("start disposable PostgreSQL: %w", err)
		}
		address, err := container.ConnectionString(ctx, "sslmode=disable")
		if err != nil {
			return nil, cleanup, fmt.Errorf("read disposable PostgreSQL address: %w", err)
		}
		return []string{"-tnl-test-postgres-url=" + address}, cleanup, nil
	case "redis":
		if err := prepareFixtureImage(ctx, redisImage); err != nil {
			return nil, nil, err
		}
		container, err := testcontainers.Run(ctx, redisImage,
			testcontainers.WithExposedPorts("6379/tcp"), loopbackPort("6379"),
			testcontainers.WithCmd("redis-server", "--requirepass", "testpass"),
			testcontainers.WithWaitStrategy(wait.ForListeningPort("6379/tcp")),
		)
		var cleanup func() error
		if container != nil {
			cleanup = func() error { return terminate(container) }
		}
		if err != nil {
			return nil, cleanup, fmt.Errorf("start disposable Redis: %w", err)
		}
		host, err := container.Host(ctx)
		if err != nil {
			return nil, cleanup, fmt.Errorf("read disposable Redis host: %w", err)
		}
		port, err := container.MappedPort(ctx, "6379/tcp")
		if err != nil {
			return nil, cleanup, fmt.Errorf("read disposable Redis port: %w", err)
		}
		return []string{"-tnl-test-redis-address=" + net.JoinHostPort(host, port.Port())}, cleanup, nil
	default:
		return nil, nil, fmt.Errorf("unknown test service %q", service)
	}
}
