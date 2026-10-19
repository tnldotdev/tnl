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
	for _, input := range [][]string{{"mysql", "--", "go", "test"}, {"mysql-tls", "--", "go", "test"}, {"postgres-tls", "--", "go", "test"}, {"redis", "--", "go", "test"}, {"dns"}, {"runtime"}} {
		if _, err := parseHarnessArguments(input); err != nil {
			t.Fatalf("parse %v: %v", input, err)
		}
	}
}

func TestHarnessArgumentsRejectInvalidCommands(t *testing.T) {
	for _, input := range [][]string{{}, {"unknown"}, {"postgres"}, {"postgres", "--"}, {"postgres", "go", "test"}, {"ssh", "--", "go", "test"}, {"dns", "--", "go", "test"}, {"runtime", "--", "go", "test"}} {
		if _, err := parseHarnessArguments(input); err == nil {
			t.Errorf("accepted %v", input)
		}
	}
}
