package naming

import (
	"strings"
	"testing"
)

func TestGeneratedHostnameCorpusAndVersion(t *testing.T) {
	if err := ValidateGeneratedHostnameCorpus(); err != nil {
		t.Fatal(err)
	}
	manifest, err := GeneratedHostnameCorpusManifest()
	if err != nil {
		t.Fatal(err)
	}
	if manifest.PredicateCount != 1450 || manifest.ObjectCount != 3062 ||
		manifest.RemainingNamespaceCapacity != 4_429_593 {
		t.Fatalf("manifest = %#v", manifest)
	}
	for range 100 {
		label, err := GeneratedHostnameLabel()
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(label, "-") != 1 || len(label) > MaxLabelBytes {
			t.Fatalf("generated hostname label = %q", label)
		}
		if canonical, err := CanonicalizeHostname(label); err != nil || canonical != label {
			t.Fatalf("generated hostname label %q is not canonical: %v", label, err)
		}
	}
}
