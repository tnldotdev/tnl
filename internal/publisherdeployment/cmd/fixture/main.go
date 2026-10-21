// fixture renders the reviewed two-replica example from the product renderer.
package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/projectconfig"
	"github.com/tnldotdev/tnl/internal/publisherdeployment"
)

func main() {
	count := 2
	bundle, err := publisherdeployment.Generate(config.TNL{Publishers: map[string]config.Publisher{"production": {AWS: &config.PublisherAWS{Replicas: &count}}}}, projectconfig.SourceIdentity{Key: "project-example", Fingerprint: strings.Repeat("a", 64)})
	if err != nil {
		panic(err)
	}
	for source, destination := range map[string]string{"aws/production.yaml": "fargate.yaml", "aws/production.parameters.example.json": "fargate.parameters.example.json", "manifest.json": "fargate.manifest.example.json"} {
		if err := os.WriteFile(filepath.Join("..", "..", "deploy", "publishers", destination), bundle.Files[source], 0644); err != nil {
			panic(err)
		}
	}
}
