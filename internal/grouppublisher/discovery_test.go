package grouppublisher

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/rdsroots"
	"github.com/tnldotdev/tnl/internal/targetdiscovery"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

type assignmentDiscovery struct {
	t       *testing.T
	request targetdiscovery.Request
}

func (p assignmentDiscovery) Discover(_ context.Context, request targetdiscovery.Request) (targetdiscovery.ResolvedTarget, error) {
	p.t.Helper()
	if request != p.request {
		p.t.Fatal("assignment selector was replaced by local config")
	}
	ca, err := rdsroots.Bundle(request.Region)
	if err != nil {
		p.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(ca))
	return targetdiscovery.ResolvedTarget{Address: "database.abc.us-east-1.rds.amazonaws.com:5432", ServerName: "database.abc.us-east-1.rds.amazonaws.com", CA: ca, CADigest: hex.EncodeToString(sum[:]), ARN: "arn:aws:rds:us-east-1:123456789012:db:database", ResourceID: "db-resource", Protocol: request.Protocol}, nil
}

func TestPrepareCloudAssignmentUsesAssignedSelectorAndNormalPrivateHealth(t *testing.T) {
	// until the control descriptor lands, this is the exact source adapter used
	// to project its identical selected fields into the normalized request.
	region, instance := "us-east-1", "database"
	request, err := targetdiscovery.FromServiceTarget(config.ServiceTarget{Type: "rds", Region: &region, Instance: &instance}, config.ProtocolPostgres)
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := targetdiscovery.New(assignmentDiscovery{t, request}, targetdiscovery.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	run, err := PrepareCloudAssignment(t.Context(), resolver, request, privatepublisher.RunConfig{Metadata: controlv1.PrivateServiceMetadata{Protocol: controlv1.PrivateServiceProtocol("postgres")}, Healthy: func(context.Context) bool { t.Fatal("static health bypassed discovery freshness"); return true }})
	if err != nil {
		t.Fatal(err)
	}
	if run.TargetResolver == nil || run.Healthy != nil {
		t.Fatal("private run did not own discovery freshness and native TLS health")
	}
	address, verifier, err := run.TargetResolver.ResolveTarget(t.Context())
	if err != nil || address != run.Target || verifier == nil || verifier.ServerName != "database.abc.us-east-1.rds.amazonaws.com" || verifier.InsecureSkipVerify {
		t.Fatal("assigned endpoint/trust not consumed", err)
	}
	if _, err := PrepareCloudAssignment(t.Context(), resolver, request, privatepublisher.RunConfig{Metadata: controlv1.PrivateServiceMetadata{Protocol: controlv1.PrivateServiceProtocol("mysql")}}); err == nil {
		t.Fatal("assignment protocol mismatch accepted")
	}
}

func TestCloudDiscoveryRetryBoundary(t *testing.T) {
	for _, kind := range []targetdiscovery.Kind{targetdiscovery.Unavailable, targetdiscovery.NotReady, targetdiscovery.Stale, targetdiscovery.Permission, targetdiscovery.Metadata, targetdiscovery.NotFound, targetdiscovery.Changed} {
		want := kind == targetdiscovery.Unavailable || kind == targetdiscovery.NotReady || kind == targetdiscovery.Stale
		if got := retryablePublication(errors.Join(&targetdiscovery.Error{Kind: kind}, &net.DNSError{IsTemporary: true})); got != want {
			t.Fatalf("retry %s = %v, want %v", kind, got, want)
		}
	}
}
