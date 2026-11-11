package daemon

import "testing"

func TestIngressRuntimeRequiresExplicitControl(t *testing.T) {
	d := new(daemon)
	if err := d.startIngressRuntime(t.Context(), ingressSettings{}, nil, ingressRuntimeConfig{}); err == nil {
		t.Fatal("ingress runtime accepted missing control dependencies")
	}
}
