package readinessproof

import "testing"

func TestRunProofChangesWithRunAndSeed(t *testing.T) {
	first := ForRun("local-secret", 3)
	if len(first) != 43 || first != ForRun("local-secret", 3) || first == ForRun("local-secret", 4) ||
		first == ForRun("other-secret", 3) || ForRun("", 3) != "" || ForRun("local-secret", 0) != "" {
		t.Fatal("readiness proof was reusable across publisher runs or accepted an empty seed")
	}
}
