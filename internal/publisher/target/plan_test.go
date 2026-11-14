package target

import (
	"errors"
	"testing"

	"github.com/tnldotdev/tnl/internal/config"
	"github.com/tnldotdev/tnl/internal/security/targettrust"
)

func TestTargetPlanNormalizesExplicitKubernetesAddressWithVerifiedTrust(t *testing.T) {
	trust, err := targettrust.CapturePortable(t.Context(), "kubernetes", "cluster.example:6443", "system", "cluster.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		protocol config.ProtocolName
		address  string
		trust    *targettrust.Snapshot
		want     string
	}{
		{config.ProtocolKubernetes, "cluster.example:6443", &trust, "https://cluster.example:6443"},
		{config.ProtocolKubernetes, "https://cluster.example:6443", &trust, "https://cluster.example:6443"},
		{config.ProtocolKubernetes, "[::1]:6443", &trust, "https://[::1]:6443"},
		{config.ProtocolKubernetes, "cluster.example:6443", nil, ""},
		{config.ProtocolKubernetes, "https://cluster.example:6443", nil, ""},
		{config.ProtocolKubernetes, "http://cluster.example:6443", &trust, ""},
		{config.ProtocolKubernetes, "http://cluster.example:6443", nil, ""},
		{config.ProtocolKubernetes, "ftp://cluster.example:6443", &trust, ""},
		{config.ProtocolHTTP, "cluster.example:6443", &trust, "https://cluster.example:6443"},
		{config.ProtocolHTTP, "cluster.example:6443", nil, "http://cluster.example:6443"},
		{config.ProtocolPostgres, "cluster.example:5432", &trust, "cluster.example:5432"},
	} {
		t.Run(string(test.protocol)+"/"+test.address+"/"+test.want, func(t *testing.T) {
			plan := TargetPlan{Protocol: test.protocol, Target: test.address, Trust: test.trust}
			err := plan.Normalize()
			if test.want == "" {
				if !errors.Is(err, ErrScope) {
					t.Fatalf("unsafe target accepted: %q, %v", plan.Target, err)
				}
				return
			}
			if err != nil || plan.Target != test.want || plan.Trust != test.trust {
				t.Fatalf("normalized target = %q, trust=%p, err=%v", plan.Target, plan.Trust, err)
			}
		})
	}
	if trust.Hostname != "cluster.example" {
		t.Fatal("normalization changed the verified target identity")
	}
}
