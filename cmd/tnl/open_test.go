package main

import (
	"context"
	"errors"
	"net"
	"reflect"
	"testing"
	"time"
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

func TestWaitForBrowserDNSRetriesNegativeAnswer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	calls := 0
	err := waitForBrowserDNS(ctx, "api.member.tnl.wtf", func(_ context.Context, hostname string) ([]net.IPAddr, error) {
		if hostname != "api.member.tnl.wtf" {
			t.Errorf("lookup hostname = %q", hostname)
		}
		calls++
		if calls == 1 {
			return nil, &net.DNSError{IsNotFound: true}
		}
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
	}, time.Millisecond)
	if err != nil || calls != 2 {
		t.Fatalf("DNS retry = %d lookups, %v", calls, err)
	}
}

func TestWaitForBrowserDNSStopsWhenUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
	defer cancel()
	err := waitForBrowserDNS(ctx, "api.member.tnl.wtf", func(context.Context, string) ([]net.IPAddr, error) {
		return nil, &net.DNSError{IsNotFound: true}
	}, time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("DNS timeout = %v", err)
	}
}
