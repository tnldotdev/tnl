package project

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPublisherAWSConfigurationIsRejected(t *testing.T) {
	for name, source := range map[string]string{
		"tnl.json":      `{"version":1,"tnl":{"deployments":{"production":{"aws":{"replicas":2}}}}}`,
		"tnl.config.ts": `export default {deploymentPublishers: {production: {aws: {replicas: 2}}}};`,
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, name)
			if err := os.WriteFile(path, []byte(source), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := Resolve(t.Context(), Selection{Path: path}, root, [32]byte{}); err == nil {
				t.Fatal("retired AWS infrastructure configuration accepted")
			}
		})
	}
}
