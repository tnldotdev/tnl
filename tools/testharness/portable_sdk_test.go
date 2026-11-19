package main

import (
	"reflect"
	"testing"
)

func TestPortableSDKDatabaseScenario(t *testing.T) {
	if _, err := parseHarnessArguments([]string{"connector-wasm", "--", "go", "test", "./internal/daemon"}); err != nil {
		t.Fatal(err)
	}
	actual, err := portableMySQLFlags([]string{
		"-tnl-test-mysql-address=127.0.0.1:3306",
		"-tnl-test-mysql-ca-file=/private/fixture/ca.pem",
		"-tnl-test-mysql-tls-hostname=db.fixture.test",
		"-tnl-test-mysql-client-container=container",
	})
	expected := []string{
		"-tnl-wasm-mysql-url=mysql://tnl_client:testpass@127.0.0.1:3306/tnl_fixture",
		"-tnl-wasm-mysql-ca-file=/private/fixture/ca.pem",
		"-tnl-wasm-mysql-tls-hostname=db.fixture.test",
	}
	if err != nil || !reflect.DeepEqual(actual, expected) {
		t.Fatalf("portable database inputs: %v, %v", actual, err)
	}
	for _, input := range [][]string{nil, {"-tnl-test-mysql-address="}, {"-tnl-test-mysql-typo=value"}, {"-tnl-test-mysql-address=one", "-tnl-test-mysql-address=two"}} {
		if _, err := portableMySQLFlags(input); err == nil {
			t.Fatalf("accepted incomplete or ambiguous fixture flags: %v", input)
		}
	}
}
