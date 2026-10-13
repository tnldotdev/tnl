package ingress

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"testing"
)

func testTrafficAdmission(t *testing.T, rate, burst int) *trafficAdmission {
	t.Helper()
	traffic, err := newTrafficAdmission(TrafficLimits{Connections: 4, Rate: rate, Burst: burst,
		UploadBytes: 64 << 10, DownloadBytes: 64 << 10}, 1, 1, 100, 100, 128<<10, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	return traffic
}

func TestTrafficAdmissionBoundsSourcesAndResetsOnlyOnNewRun(t *testing.T) {
	traffic := testTrafficAdmission(t, 1, 1)
	first := netip.MustParseAddr("198.51.100.1")
	if ok, reason := traffic.allowSource(first); !ok || reason != "" {
		t.Fatalf("first source = %t, %s", ok, reason)
	}
	if ok, reason := traffic.allowSource(first); ok || reason != "source_connection_rate" {
		t.Fatalf("repeat source = %t, %s", ok, reason)
	}
	if ok, reason := traffic.allowSource(netip.MustParseAddr("198.51.100.2")); !ok || reason != "" {
		t.Fatalf("independent source = %t, %s", ok, reason)
	}
	firstRun := trafficKey{url: "url_1", run: 1}
	if !traffic.allowConnection(firstRun) || traffic.allowConnection(firstRun) ||
		!traffic.allowConnection(trafficKey{url: "url_2", run: 1}) ||
		!traffic.allowConnection(trafficKey{url: "url_1", run: 2}) {
		t.Fatal("public URL rate state was reset by a connection or shared with another publish run")
	}
	// an IPv6 /64 shares one source allowance across rotating addresses.
	if ok, _ := traffic.allowSource(netip.MustParseAddr("2001:db8::1")); !ok {
		t.Fatal("IPv6 source rejected initially")
	}
	if ok, _ := traffic.allowSource(netip.MustParseAddr("2001:db8::2")); ok {
		t.Fatal("IPv6 /64 source rate bypassed")
	}
}

func TestTrafficAdmissionBoundsBothByteDirectionsWithoutBlockingOthers(t *testing.T) {
	traffic := testTrafficAdmission(t, 10, 10)
	key := trafficKey{url: "url_1", run: 1}
	if err := traffic.waitBytes(t.Context(), key, true, 64<<10); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := traffic.waitBytes(ctx, key, true, 64<<10); !errors.Is(err, context.Canceled) {
		t.Fatalf("exhausted upload = %v", err)
	}
	if err := traffic.waitBytes(t.Context(), key, false, 64<<10); err != nil {
		t.Fatalf("upload consumed the download budget: %v", err)
	}
	if err := traffic.waitBytes(t.Context(), trafficKey{url: "url_2", run: 1}, true, 64<<10); err != nil {
		t.Fatalf("one public URL consumed another's upload: %v", err)
	}
}

type halfCloseTrafficConn struct {
	net.Conn
	closed bool
}

func (c *halfCloseTrafficConn) CloseWrite() error {
	c.closed = true
	return nil
}

func TestBudgetConnPreservesWriteHalfClose(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	underlying := &halfCloseTrafficConn{Conn: a}
	budget := &budgetConn{Conn: underlying, ctx: t.Context(), beforeWrite: func(context.Context, int) error { return nil }}
	if err := budget.CloseWrite(); err != nil || !underlying.closed {
		t.Fatalf("half-close = %t, %v", underlying.closed, err)
	}
	if err := (&budgetConn{Conn: b, ctx: t.Context(), beforeWrite: func(context.Context, int) error { return nil }}).CloseWrite(); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("unsupported half-close = %v", err)
	}
}

func TestTrafficAdmissionRejectsCeilingBelowDefault(t *testing.T) {
	config := TrafficConfig{Default: defaultTrafficLimits(), Ceiling: TrafficLimits{Connections: 1,
		Rate: 100, Burst: 200, UploadBytes: 64 << 20, DownloadBytes: 128 << 20}}
	if err := config.resolve(); err == nil {
		t.Fatal("operator ceiling below the default was accepted")
	}
}
