package group

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"testing"

	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	"github.com/tnldotdev/tnl/internal/publisher/target/discovery/rdsroots"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type assignmentDiscovery struct {
	t       *testing.T
	request publisherdiscovery.Request
}

func (p assignmentDiscovery) Discover(_ context.Context, request publisherdiscovery.Request) (publisherdiscovery.ResolvedTarget, error) {
	p.t.Helper()
	if request != p.request {
		p.t.Fatal("assignment selector was replaced by local config")
	}
	ca, err := rdsroots.Bundle(request.Region)
	if err != nil {
		p.t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(ca))
	return publisherdiscovery.ResolvedTarget{Address: "database.abc.us-east-1.rds.amazonaws.com:5432", ServerName: "database.abc.us-east-1.rds.amazonaws.com", CA: ca, CADigest: hex.EncodeToString(sum[:]), ARN: "arn:aws:rds:us-east-1:123456789012:db:database", ResourceID: "db-resource", Protocol: request.Protocol}, nil
}

func TestPrepareCloudAssignmentUsesAssignedSelectorAndNormalPrivateHealth(t *testing.T) {
	request, err := AssignmentDiscovery(controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocol("postgres")), PublisherGroup: new("cloud"), TargetDiscovery: &controlv1.ProjectTargetDiscovery{Type: controlv1.Rds, Region: "us-east-1", Instance: new("database")}})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := publisherdiscovery.New(assignmentDiscovery{t, request}, publisherdiscovery.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer resolver.Close()
	run, err := PrepareCloudAssignment(t.Context(), resolver, request, publisherservice.RunConfig{Metadata: controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocol("postgres")}, Healthy: func(context.Context) bool { t.Fatal("static health bypassed discovery freshness"); return true }})
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
	if _, err := PrepareCloudAssignment(t.Context(), resolver, request, publisherservice.RunConfig{Metadata: controlv1.ServiceMetadata{Protocol: controlv1.ServiceProtocol("mysql")}}); err == nil {
		t.Fatal("assignment protocol mismatch accepted")
	}
}

func TestCloudDiscoveryRetryBoundary(t *testing.T) {
	for _, kind := range []publisherdiscovery.Kind{publisherdiscovery.Unavailable, publisherdiscovery.NotReady, publisherdiscovery.Stale, publisherdiscovery.Permission, publisherdiscovery.Metadata, publisherdiscovery.NotFound, publisherdiscovery.Changed} {
		want := kind == publisherdiscovery.Unavailable || kind == publisherdiscovery.NotReady || kind == publisherdiscovery.Stale
		if got := retryablePublication(errors.Join(&publisherdiscovery.Error{Kind: kind}, &net.DNSError{IsTemporary: true})); got != want {
			t.Fatalf("retry %s = %v, want %v", kind, got, want)
		}
	}
}

func TestAssignmentDiscoveryPreservesTypedSelectorsAndEndpointIntent(t *testing.T) {
	for _, tc := range []struct {
		name       string
		descriptor controlv1.ProjectTargetDiscovery
		protocol   string
		want       publisherdiscovery.Request
	}{
		{"eks", controlv1.ProjectTargetDiscovery{Type: controlv1.Eks, Region: "us-west-2", Cluster: new("production-cluster")}, "kubernetes", publisherdiscovery.Request{Type: "eks", Region: "us-west-2", Cluster: "production-cluster", Protocol: "kubernetes"}},
		{"instance-writer-default", controlv1.ProjectTargetDiscovery{Type: controlv1.Rds, Region: "eu-west-1", Instance: new("orders")}, "postgres", publisherdiscovery.Request{Type: "rds", Region: "eu-west-1", Instance: "orders", Endpoint: "writer", Protocol: "postgres"}},
		{"cluster-writer", controlv1.ProjectTargetDiscovery{Type: controlv1.Rds, Region: "us-east-1", Cluster: new("orders"), Endpoint: new(controlv1.Writer)}, "mysql", publisherdiscovery.Request{Type: "rds", Region: "us-east-1", Cluster: "orders", Endpoint: "writer", Protocol: "mysql"}},
		{"cluster-reader", controlv1.ProjectTargetDiscovery{Type: controlv1.Rds, Region: "us-east-2", Cluster: new("orders"), Endpoint: new(controlv1.Reader)}, "postgres", publisherdiscovery.Request{Type: "rds", Region: "us-east-2", Cluster: "orders", Endpoint: "reader", Protocol: "postgres"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := AssignmentDiscovery(controlv1.ProjectServiceConfiguration{Protocol: new(controlv1.ServiceProtocol(tc.protocol)), PublisherGroup: new("cloud"), TargetDiscovery: &tc.descriptor})
			if err != nil || got != tc.want {
				t.Fatalf("descriptor projection = %#v, %v", got, err)
			}
		})
	}
}
