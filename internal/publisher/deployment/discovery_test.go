package deployment

import (
	"bytes"
	"strings"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
)

func TestDiscoveryPermissionsUseDeclaredResourcesOnTaskRoles(t *testing.T) {
	text := func(value string) *string { return &value }
	configuration := testConfig(2)
	configuration.Services = config.Services{
		"cluster": {PublisherGroup: text("production"), Protocol: text("kubernetes"), Target: &config.ServiceTarget{Type: "eks", Cluster: text("development"), Region: text("us-east-1")}},
		"db":      {PublisherGroup: text("production"), Protocol: text("postgres"), Target: &config.ServiceTarget{Type: "rds", Instance: text("orders"), Region: text("eu-west-1")}},
		"mysql":   {PublisherGroup: text("production"), Protocol: text("mysql"), Target: &config.ServiceTarget{Type: "rds", Cluster: text("billing"), Region: text("us-west-2")}},
	}
	bundle, err := Generate(configuration, testSource(), []byte("// portable types\n"))
	if err != nil {
		t.Fatal(err)
	}
	data := bundle.Files["aws/production.yaml"]
	for _, resource := range []string{"eks:us-east-1:${AWS::AccountId}:cluster/development", "rds:eu-west-1:${AWS::AccountId}:db:orders", "rds:us-west-2:${AWS::AccountId}:cluster:billing"} {
		if bytes.Count(data, []byte(resource)) != 2 {
			t.Fatalf("replicas lost scoped resource %s", resource)
		}
	}
	for _, action := range []string{"eks:DescribeCluster", "rds:DescribeDBInstances", "rds:DescribeDBClusters"} {
		if bytes.Count(data, []byte(action)) != 2 {
			t.Fatal("missing task discovery", action)
		}
	}
	if bytes.Count(data, []byte("secretsmanager:GetSecretValue")) != 2 {
		t.Fatal("discovery introduced application secret access")
	}
	directory := testDirectory(t)
	if err := bundle.Write(directory); err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(directory, configuration, testSource()); err != nil {
		t.Fatal("bootstrap could not validate bundle with portable types", err)
	}
	if !strings.Contains(string(bundle.Files[ManifestPath]), "declarations_sha256") {
		t.Fatal("types missing from ownership manifest")
	}
}
