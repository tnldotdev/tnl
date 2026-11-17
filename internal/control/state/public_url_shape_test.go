package state

import "testing"

func TestPublicURLCreateTargetShape(t *testing.T) {
	for _, protocol := range []string{"http", "tcp", "postgres", "mysql", "kubernetes"} {
		for _, ephemeral := range []bool{false, true} {
			for _, target := range []string{"", "localhost:3000", "app"} {
				declaration := ProjectServiceConfiguration{Protocol: protocol, Target: target, Ephemeral: ephemeral}
				_, err := normalizeServiceConfiguration("web", &declaration)
				want := target == "localhost:3000" || protocol == "http" && target == "app"
				if (err == nil) != want {
					t.Errorf("%s target=%q ephemeral=%t: %v", protocol, target, ephemeral, err)
				}
			}
		}
	}
	for _, protocol := range []string{"", "ssh", "redis", "unknown"} {
		if protocol == "" {
			continue
		}
		if _, err := normalizeServiceConfiguration("web", &ProjectServiceConfiguration{Protocol: protocol, Target: "localhost:3000"}); err == nil {
			t.Errorf("unknown protocol %q accepted", protocol)
		}
	}
}
