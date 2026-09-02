package naming

import (
	"strings"
	"testing"
)

func TestFriendlyCorpusAndVersion(t *testing.T) {
	if err := ValidateFriendlyCorpus(); err != nil {
		t.Fatal(err)
	}
	manifest, err := FriendlyCorpusManifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.PredicateCount != 1450 || manifest.ObjectCount != 3062 ||
		manifest.RemainingNamespaceCapacity != 4_429_593 {
		t.Fatalf("manifest = %#v", manifest)
	}
	for range 100 {
		name, err := FriendlyName()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(name, "-") != 1 || len(name) > MaxLabelBytes {
			t.Fatalf("friendly name = %q", name)
		}
		if canonical, err := CanonicalizeHostname(name); err != nil || canonical != name {
			t.Fatalf("friendly name %q is not canonical: %v", name, err)
		}
	}
}
