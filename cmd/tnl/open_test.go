package main

import (
	"reflect"
	"testing"
)

func TestBrowserCommand(t *testing.T) {
	target := "https://demo.example/path?value=one two"
	for _, test := range []struct {
		goos       string
		executable string
	}{
		{goos: "darwin", executable: "open"},
		{goos: "linux", executable: "xdg-open"},
	} {
		executable, arguments, err := browserCommand(test.goos, target)
		if err != nil {
			t.Fatal(err)
		}
		if executable != test.executable || !reflect.DeepEqual(arguments, []string{target}) {
			t.Fatalf("%s command = %q %#v", test.goos, executable, arguments)
		}
	}
	if _, _, err := browserCommand("unsupported", target); err == nil {
		t.Fatal("unsupported platform was accepted")
	}
}
