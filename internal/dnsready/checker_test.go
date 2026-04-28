package dnsready

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type testResolver struct {
	mu      sync.Mutex
	control []net.IPAddr
	route   []net.IPAddr
	err     error
	cname   string
	lookups []string
}

func (r *testResolver) LookupIPAddr(_ context.Context, hostname string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return nil, r.err
	}
	r.lookups = append(r.lookups, hostname)
	if hostname == "tnl.example.com" {
		return r.control, nil
	}
	return r.route, nil
}

func (r *testResolver) LookupCNAME(_ context.Context, hostname string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return "", r.err
	}
	r.lookups = append(r.lookups, hostname)
	return r.cname, nil
}

func TestCheckerReadinessAndHostnameOverlap(t *testing.T) {
	resolver := &testResolver{
		control: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}, {IP: net.ParseIP("2001:db8::1")}},
		route:   []net.IPAddr{{IP: net.ParseIP("2001:db8::1")}},
	}
	checker := New("tnl.example.com", "example.com")
	checker.resolver = resolver
	if err := checker.Check(context.Background()); err != nil {
		t.Fatal(err)
	}
	if addresses := checker.IngressAddresses(); len(addresses) != 2 || addresses[0] != "192.0.2.1" || addresses[1] != "2001:db8::1" {
		t.Fatalf("ingress addresses = %q", addresses)
	}
	resolver.mu.Lock()
	lookups := append([]string(nil), resolver.lookups...)
	resolver.mu.Unlock()
	if len(lookups) < 3 || strings.Count(lookups[2], ".") != strings.Count("example.com", ".")+9 {
		t.Fatalf("maximum-depth lookup = %q", lookups)
	}
	if err := checker.CheckHostname(context.Background(), "api.chase.example.com"); err != nil {
		t.Fatal(err)
	}

	resolver.route = []net.IPAddr{{IP: net.ParseIP("192.0.2.2")}}
	if err := checker.Check(context.Background()); err == nil {
		t.Fatal("non-overlapping route DNS accepted")
	}
}

func TestCheckerDomainProof(t *testing.T) {
	resolver := &testResolver{
		control: []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}},
		route:   []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}},
		cname:   "token.domains.example.com.",
	}
	checker := New("tnl.example.com", "example.com")
	checker.resolver = resolver
	if err := checker.CheckDomain(context.Background(), "other.com", "token.domains.example.com", true); err != nil {
		t.Fatal(err)
	}
	resolver.cname = "wrong.domains.example.com."
	if err := checker.CheckDomain(context.Background(), "docs.other.com", "token.domains.example.com", false); err == nil {
		t.Fatal("wrong CNAME accepted")
	}
}

func TestCheckerMonitorLogsTransitionsOnly(t *testing.T) {
	oldInterval := checkInterval
	checkInterval = time.Millisecond
	t.Cleanup(func() { checkInterval = oldInterval })
	resolver := &testResolver{err: errors.New("DNS lookup failed")}
	checker := New("tnl.example.com", "example.com")
	checker.resolver = resolver
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var mu sync.Mutex
	var logs []string
	go checker.Monitor(ctx, func(format string, values ...any) {
		mu.Lock()
		logs = append(logs, format)
		mu.Unlock()
	})
	waitFor := func(condition func() bool) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for !condition() && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if !condition() {
			t.Fatal("condition not reached")
		}
	}
	waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(logs) == 1
	})
	resolver.mu.Lock()
	resolver.err = nil
	resolver.control = []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}
	resolver.route = []net.IPAddr{{IP: net.ParseIP("192.0.2.1")}}
	resolver.mu.Unlock()
	waitFor(checker.Ready)
	waitFor(func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(logs) == 3
	})
	time.Sleep(5 * time.Millisecond)
	mu.Lock()
	defer mu.Unlock()
	if len(logs) != 3 || !strings.Contains(logs[0], "not ready") || logs[1] != "Public DNS ready" || logs[2] != "%s ingress: %s" {
		t.Fatalf("transition logs = %q", logs)
	}
}

func TestCheckerLookupError(t *testing.T) {
	checker := New("tnl.example.com", "example.com")
	checker.resolver = &testResolver{err: errors.New("offline")}
	if err := checker.CheckHostname(context.Background(), "route.example.com"); err == nil {
		t.Fatal("lookup error accepted")
	}
}
