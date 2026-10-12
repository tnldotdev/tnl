package dockertarget

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestComposePortSelectsOnlyTheMatchingProjectAndPrivatePort(t *testing.T) {
	path := t.TempDir()
	log := filepath.Join(path, "arguments")
	docker := filepath.Join(path, "docker")
	script := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$DOCKER_ARGS\"\nprintf '0.0.0.0:49153\\n'\n"
	if err := os.WriteFile(docker, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", path+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("DOCKER_ARGS", log)
	address, err := ComposePort(t.Context(), path, "shop-main-k7n2p9", "orders", 5432)
	if err != nil || address != "127.0.0.1:49153" {
		t.Fatalf("resolved target = %q, %v", address, err)
	}
	data, err := os.ReadFile(log)
	if err != nil {
		t.Fatal(err)
	}
	arguments := strings.Split(strings.TrimSpace(string(data)), "\n")
	want := []string{"compose", "--project-directory", path, "--project-name", "shop-main-k7n2p9", "port", "orders", "5432"}
	if strings.Join(arguments, "|") != strings.Join(want, "|") {
		t.Fatalf("Compose arguments = %q, want %q", arguments, want)
	}
}

func TestComposePortRejectsAmbiguousAndNonlocalBindings(t *testing.T) {
	for _, output := range []string{
		"", "0.0.0.0:49153\n127.0.0.1:49154", "192.0.2.1:49153",
		"0.0.0.0:0", "host.example:49153", "0.0.0.0:49153:23",
	} {
		if address, err := parsePort(output); err == nil {
			t.Fatalf("accepted unsafe Docker binding %q as %q", output, address)
		}
	}
	for output, want := range map[string]string{
		"127.0.0.1:49153\n": "127.0.0.1:49153",
		"[::]:49154\n":      "[::1]:49154",
		"[::1]:49155\n":     "[::1]:49155",
	} {
		if address, err := parsePort(output); err != nil || address != want {
			t.Fatalf("binding %q resolved to %q, %v; want %q", output, address, err, want)
		}
	}
	if _, err := ComposePort(context.Background(), ".", "shop", "orders", 5432); err == nil {
		t.Fatal("accepted relative project directory")
	}
	if _, err := ComposePort(context.Background(), t.TempDir(), "shop", "--flag", 5432); err == nil {
		t.Fatal("accepted a Compose option as a service")
	}
}
