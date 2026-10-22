// fixture renders the reviewed two-replica example from the product renderer.
package main

import (
	"os"
	"path/filepath"
	"strings"

	clientproject "github.com/tnldotdev/tnl/internal/client/project"
	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/publisher/deployment"
)

func main() {
	count := 2
	bundle, err := deployment.Generate(config.TNL{PublisherGroups: map[string]config.PublisherGroup{"production": {AWS: &config.PublisherGroupAWS{Replicas: &count}}}}, clientproject.SourceIdentity{Key: "project-example", Fingerprint: strings.Repeat("a", 64)})
	if err != nil {
		panic(err)
	}
	for source, destination := range map[string]string{"aws/production.yaml": "fargate.yaml", "aws/production.parameters.example.json": "fargate.parameters.example.json", "aws/production.storage-policy.json": "fargate.storage-policy.json", "manifest.json": "fargate.manifest.example.json"} {
		if err := os.WriteFile(filepath.Join("..", "..", "..", "deploy", "publisher", "fargate", destination), bundle.Files[source], 0644); err != nil {
			panic(err)
		}
	}
}
