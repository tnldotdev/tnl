package publisherproof

import "testing"

func TestRuntimeScopePreservesAbsentDeploymentBinding(t *testing.T) {
	const want = "runtime:635eaf0c9943e691f18ee038f2949aa4e6d24dfb2338b8ed5ad31c148afd9eed"
	if got := RuntimeScope("scope", "start", "run", 7, ""); got != want {
		t.Fatalf("absent deployment scope = %q, want %q", got, want)
	}
	if got := RuntimeScope("scope", "start", "run", 7, "report-digest"); got == want {
		t.Fatal("deployment digest did not change the runtime scope")
	}
}
