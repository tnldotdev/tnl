package config

import (
	"testing"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/region"
)

func TestProviderRegionConfig(t *testing.T) {
	base := []string{"--role=ingress", "--ingress-id=ingress-a", "--control-hostname=control.example.test", "--cluster-secret=" + testClusterSecret}
	for _, id := range []string{"local", "fly:sjc", "aws:us-west-1", "gcp:us-west1"} {
		cfg, err := Parse(append(base, "--region="+id))
		if err != nil || string(cfg.ServingRegion()) != id {
			t.Fatal("region identity lost", id, err)
		}
	}
	for _, id := range []string{"sjc", "us-west-1", "aws:sjc", "fly:us-west-1", "FLY:SJC"} {
		_, err := Parse(append(base, "--region="+id))
		typed, ok := failure.Of(err)
		if !ok || typed.Reason() != failure.ServerConfigInvalid {
			t.Fatal("noncanonical region accepted", id, err)
		}
	}
	if (Config{}).ServingRegion() != region.Local {
		t.Fatal("embedded default asserted a provider")
	}
}
