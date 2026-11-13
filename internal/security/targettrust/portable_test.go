package targettrust

import (
	"context"
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/security/rdsroots"
)

func TestPortableTrustIsOfflineAndBoundToTheTarget(t *testing.T) {
	const hostname = "orders.abc123.us-east-1.rds.amazonaws.com"
	rds, err := CapturePortable(t.Context(), "postgres", hostname+":5432", "aws-rds", "")
	if err != nil || rds.System || rds.Hostname != hostname {
		t.Fatal(rds, err)
	}
	bundle, err := rdsroots.BundleForHostname(hostname)
	if err != nil {
		t.Fatal(err)
	}
	explicit, err := CapturePortable(t.Context(), "postgres", hostname+":5432", bundle, hostname)
	if err != nil || explicit.Digest != rds.Digest {
		t.Fatal("explicit PEM and RDS selection diverged", err)
	}
	for _, input := range []struct{ protocol, address, ca, hostname string }{
		{"postgres", hostname + ":5432", "aws-rds", "different.internal"},
		{"tcp", hostname + ":5432", "aws-rds", ""},
		{"postgres", "custom.internal:5432", "aws-rds", ""},
		{"postgres", "orders.abc.cn-north-1.rds.amazonaws.com.cn:5432", "aws-rds", ""},
		{"postgres", "db.internal:5432", "./ca.pem", ""},
		{"postgres", "db.internal:5432", "https://invalid.example/ca.pem", ""},
	} {
		if _, err := CapturePortable(t.Context(), input.protocol, input.address, input.ca, input.hostname); err == nil {
			t.Fatal("portable trust accepted a path, URL, or unrelated RDS identity", input)
		}
	}
	system, err := CapturePortable(t.Context(), "tcp", "127.0.0.1:443", "system", "verified.internal")
	if err != nil || !system.System || system.Hostname != "verified.internal" {
		t.Fatal(system, err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := CapturePortable(ctx, "postgres", hostname+":5432", bundle, ""); !errors.Is(err, context.Canceled) {
		t.Fatal("capture ignored cancellation", err)
	}
}
