package main

import (
	"encoding/pem"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestProvisionBenchmarkPebbleUsesRealValidationAndReturnsRoots(t *testing.T) {
	roots := benchmarkTestRootBundle(t)
	rootOutput := append([]byte("Connecting to machine...\n"+benchmarkRootsBegin), roots...)
	rootOutput = append(rootOutput, []byte(benchmarkRootsEnd+"\nconnection closed\n")...)
	executor := &executorStub{responses: [][]byte{
		nil,
		[]byte(`[{"id":"pebble-machine","name":"pebble","state":"started"}]`),
		nil,
		rootOutput,
	}}
	got, err := provisionBenchmarkPebble(t.Context(), flyPlatform{
		binary: "fly", region: "sjc", executor: executor,
	}, "pebble-app", "registry/image:tag", "shared-cpu-1x",
		manifestZone{Name: "run.bench.example.com", NameServers: []string{"ns-1.example.net", "ns-2.example.net"}},
		manifestZone{Name: "public-urls.run.bench.example.com", NameServers: []string{"ns-3.example.net", "ns-4.example.net"}},
	)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(got) != strings.TrimSpace(string(roots)) || len(executor.calls) != 4 {
		t.Fatalf("roots = %q, calls = %#v", got, executor.calls)
	}
	arguments := executor.calls[0].args
	for _, want := range []string{
		benchmarkPebbleCommand, "PEBBLE_VA_ALWAYS_VALID=0", "PEBBLE_VA_NOSLEEP=1", "--restart", "no",
		"TNL_BENCH_RESOLVER_SERVER_DOMAIN=run.bench.example.com",
		"TNL_BENCH_RESOLVER_SERVER_NAME_SERVERS=ns-1.example.net,ns-2.example.net",
		"TNL_BENCH_RESOLVER_MANAGED_DOMAIN=public-urls.run.bench.example.com",
		"TNL_BENCH_RESOLVER_MANAGED_NAME_SERVERS=ns-3.example.net,ns-4.example.net",
	} {
		if !slices.Contains(arguments, want) {
			t.Fatalf("machine arguments omit %q: %v", want, arguments)
		}
	}
	if !strings.Contains(benchmarkPebbleCommand, "-dnsserver "+benchmarkAuthoritativeDNSAddress) {
		t.Fatalf("Pebble command does not select the benchmark DNS resolver: %q", benchmarkPebbleCommand)
	}
	if !strings.HasPrefix(benchmarkPebbleCommand, "/tnlbench resolver & ") {
		t.Fatalf("Pebble command does not start the benchmark DNS resolver: %q", benchmarkPebbleCommand)
	}
	if slices.Contains(arguments, "--port") {
		t.Fatalf("private Pebble received a public port: %v", arguments)
	}
	if !strings.Contains(strings.Join(executor.calls[3].args, " "), "/etc/tnlbench/benchmark-api-root.pem") {
		t.Fatalf("root extraction omitted the static API root: %#v", executor.calls[3])
	}
}

func TestValidateBenchmarkRootBundleRejectsUnexpectedContent(t *testing.T) {
	root := benchmarkTestRootBundle(t)
	for _, bundle := range [][]byte{root[:len(root)/2], append(root, []byte("secret")...)} {
		if err := validateBenchmarkRootBundle(bundle); err == nil {
			t.Fatalf("invalid bundle was accepted: %q", bundle)
		}
	}
}

func benchmarkTestRootBundle(t *testing.T) []byte {
	t.Helper()
	server := httptest.NewTLSServer(nil)
	t.Cleanup(server.Close)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	return append(append([]byte(nil), certificate...), certificate...)
}
