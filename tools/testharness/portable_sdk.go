package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// the portable SDK scenario reuses both digest-pinned database owners. control
// and the application database share the disposable postgres server, not a schema.
func startPortableSDKDatabases(ctx context.Context) ([]string, func() error, error) {
	control, closeControl, err := startTestService(ctx, "postgres")
	if err != nil {
		return control, closeControl, err
	}
	target, err := startDatabaseTLS(ctx, "mysql-tls")
	if err != nil {
		return nil, closeControl, err
	}
	closeAll := func() error { return errors.Join(target.Close(), closeControl()) }
	flags, err := portableMySQLFlags(target.Flags)
	if err != nil {
		return nil, closeAll, err
	}
	redis, closeRedis, err := startTestService(ctx, "redis")
	cleanup := func() error {
		if closeRedis != nil {
			return errors.Join(closeRedis(), closeAll())
		}
		return closeAll()
	}
	if err != nil {
		return nil, cleanup, err
	}
	return append(append(control, flags...), redis...), cleanup, nil
}

func portableMySQLFlags(input []string) ([]string, error) {
	values := make(map[string]string)
	for _, argument := range input {
		name, value, ok := strings.Cut(argument, "=")
		if !ok || value == "" || values[name] != "" {
			return nil, errors.New("invalid disposable MySQL fixture flag")
		}
		switch name {
		case "-tnl-test-mysql-address", "-tnl-test-mysql-ca-file", "-tnl-test-mysql-tls-hostname", "-tnl-test-mysql-client-container":
			values[name] = value
		default:
			return nil, fmt.Errorf("unexpected disposable MySQL fixture flag %q", name)
		}
	}
	for _, name := range []string{"address", "ca-file", "tls-hostname"} {
		if values["-tnl-test-mysql-"+name] == "" {
			return nil, fmt.Errorf("disposable MySQL fixture is missing %s", name)
		}
	}
	return []string{
		"-tnl-wasm-mysql-url=mysql://tnl_client:testpass@" + values["-tnl-test-mysql-address"] + "/tnl_fixture",
		"-tnl-wasm-mysql-ca-file=" + values["-tnl-test-mysql-ca-file"],
		"-tnl-wasm-mysql-tls-hostname=" + values["-tnl-test-mysql-tls-hostname"],
	}, nil
}
