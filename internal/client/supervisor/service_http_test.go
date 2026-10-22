package supervisor

import "testing"

func TestPrivateJobRejectsUncapturedTargetTLSName(t *testing.T) {
	job := Job{Kind: KindService, Protocol: "http", Target: "https://127.0.0.1:443", TargetTLSName: "unexpected"}
	if err := validateTarget(&job); err == nil {
		t.Fatal("private publication accepted publisher-side target TLS")
	}
}
