package main

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	benchmarkAuthoritativeDNSAddress = "127.0.0.1:8053"
	benchmarkPebbleCommand           = "/tnlbench resolver & exec /pebble -config /etc/tnlbench/pebble-config.json -strict=false -dnsserver " + benchmarkAuthoritativeDNSAddress
	benchmarkLoadCommand             = "/tnlbench resolver & exec /tnlbench load"
	benchmarkPebbleReady             = "wget -q --spider --no-check-certificate https://127.0.0.1:14000/dir"
	benchmarkPebbleRoots             = "printf 'TNL_BENCH_ROOTS_BEGIN\\n'; cat /etc/tnlbench/benchmark-api-root.pem; printf '\\n'; wget -qO- --no-check-certificate https://127.0.0.1:15000/roots/0; printf '\\nTNL_BENCH_ROOTS_END\\n'"
	benchmarkRootsBegin              = "TNL_BENCH_ROOTS_BEGIN\n"
	benchmarkRootsEnd                = "\nTNL_BENCH_ROOTS_END"
)

func provisionBenchmarkPebble(
	ctx context.Context,
	fly flyPlatform,
	app, image, size string,
	serverZone, managedZone manifestZone,
) (string, error) {
	machine, err := fly.runMachine(ctx, machineSpec{
		App: app, Name: "pebble", Image: image, Command: benchmarkPebbleCommand, Size: size, Restart: "no",
		Env: benchmarkResolverEnvironment(serverZone, managedZone, map[string]string{
			"PEBBLE_AUTHZREUSE": "0", "PEBBLE_VA_ALWAYS_VALID": "0", "PEBBLE_VA_NOSLEEP": "1",
			"PEBBLE_WFE_NONCEREJECT": "0",
		}),
	})
	if err != nil {
		return "", err
	}
	if err := fly.waitMachineCommandReady(ctx, app, machine.ID, benchmarkPebbleReady, 5*time.Minute); err != nil {
		return "", err
	}
	output, err := fly.machineCommand(ctx, app, machine.ID, benchmarkPebbleRoots)
	if err != nil {
		return "", err
	}
	bundle, err := extractBenchmarkRootBundle(output)
	if err != nil {
		return "", fmt.Errorf("read benchmark Pebble trust roots: %w", err)
	}
	if err := validateBenchmarkRootBundle(bundle); err != nil {
		return "", fmt.Errorf("read benchmark Pebble trust roots: %w", err)
	}
	return strings.TrimSpace(string(bundle)) + "\n", nil
}

func benchmarkResolverEnvironment(serverZone, managedZone manifestZone, values map[string]string) map[string]string {
	if values == nil {
		values = make(map[string]string)
	}
	values["TNL_BENCH_RESOLVER_SERVER_DOMAIN"] = serverZone.Name
	values["TNL_BENCH_RESOLVER_SERVER_NAME_SERVERS"] = strings.Join(serverZone.NameServers, ",")
	values["TNL_BENCH_RESOLVER_MANAGED_DOMAIN"] = managedZone.Name
	values["TNL_BENCH_RESOLVER_MANAGED_NAME_SERVERS"] = strings.Join(managedZone.NameServers, ",")
	return values
}

func extractBenchmarkRootBundle(output []byte) ([]byte, error) {
	text := string(output)
	begin := strings.Index(text, benchmarkRootsBegin)
	if begin < 0 {
		return nil, errors.New("root certificate bundle start marker is missing")
	}
	begin += len(benchmarkRootsBegin)
	end := strings.Index(text[begin:], benchmarkRootsEnd)
	if end < 0 {
		return nil, errors.New("root certificate bundle end marker is missing")
	}
	return []byte(text[begin : begin+end]), nil
}

func validateBenchmarkRootBundle(bundle []byte) error {
	return validateBenchmarkRootBundleCount(bundle, 2)
}

func validateBenchmarkRootBundleCount(bundle []byte, minimum int) error {
	rest := bundle
	certificates := 0
	for {
		block, remaining := pem.Decode(rest)
		if block == nil {
			if len(bytes.TrimSpace(rest)) != 0 {
				return errors.New("root certificate bundle contains non-PEM data")
			}
			break
		}
		if block.Type != "CERTIFICATE" {
			return fmt.Errorf("root certificate bundle contains PEM block %q", block.Type)
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return errors.New("root certificate bundle contains an invalid certificate")
		}
		certificates++
		rest = remaining
	}
	if certificates < minimum {
		return fmt.Errorf("root certificate bundle contains %d certificates, need at least %d", certificates, minimum)
	}
	return nil
}
