package buildinfo

import "testing"

func TestLine(t *testing.T) {
	previousVersion, previousCommit := Version, Commit
	t.Cleanup(func() { Version, Commit = previousVersion, previousCommit })
	Version, Commit = "v0.1.0", "0123456789abcdef"
	if got := Line("tnl"); got != "tnl v0.1.0 (0123456789abcdef)" {
		t.Fatalf("Line = %q", got)
	}
	Commit = ""
	if got := Line("tnld"); got != "tnld v0.1.0" {
		t.Fatalf("Line without commit = %q", got)
	}
}
