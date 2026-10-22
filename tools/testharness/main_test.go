package main

import (
	"reflect"
	"testing"
)

func TestHarnessArgumentsPreserveChildCommand(t *testing.T) {
	arguments := []string{"postgres", "--", "go", "test", "-race", "-run=^Test(A,B)$", "-args", "-tnl-test-tier=integration"}
	parsed, err := parseHarnessArguments(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Service != "postgres" || !reflect.DeepEqual(parsed.Command, arguments[2:]) {
		t.Fatalf("parsed test command = %+v", parsed)
	}
	sharded, err := parseHarnessArguments(append([]string{"--tnl-test-shard=2/4"}, arguments...))
	if err != nil || sharded.TestShard != "2/4" || !reflect.DeepEqual(sharded.Command, arguments[2:]) {
		t.Fatalf("parsed sharded command = %+v, %v", sharded, err)
	}
	for _, input := range [][]string{{"mysql", "--", "go", "test"}, {"mysql-tls", "--", "go", "test"}, {"postgres-tls", "--", "go", "test"}, {"redis", "--", "go", "test"}, {"dns"}, {"runtime"}} {
		if _, err := parseHarnessArguments(input); err != nil {
			t.Fatalf("parse %v: %v", input, err)
		}
	}
}

func TestHarnessArgumentsRejectInvalidCommands(t *testing.T) {
	for _, input := range [][]string{{}, {"unknown"}, {"postgres"}, {"postgres", "--"}, {"postgres", "go", "test"}, {"ssh", "--", "go", "test"}, {"dns", "--", "go", "test"}, {"runtime", "--", "go", "test"}, {"--tnl-test-shard=0/4", "postgres", "--", "go", "test"}, {"--tnl-test-shard=1/4", "dns"}} {
		if _, err := parseHarnessArguments(input); err == nil {
			t.Errorf("accepted %v", input)
		}
	}
}
