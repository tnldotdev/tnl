package naming

import (
	"slices"
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

func TestGeneratedHostnameExclusions(t *testing.T) {
	if err := ValidateGeneratedHostnameCorpus(); err != nil {
		t.Fatal(err)
	}
	// check every reviewed exclusion against the loaded corpus, rather than
	// hoping a random generation happens to select an excluded word.
	for _, word := range strings.Split(strings.TrimSpace(string(generatedHostnameExclusions)), "\n") {
		if slices.Contains(generatedHostnameCorpus.Predicates, word) || slices.Contains(generatedHostnameCorpus.Objects, word) {
			t.Errorf("excluded word %q remains selectable", word)
		}
	}
	words := []string{"amber", "blocked", "cedar", "blocked"}
	if got := filterWords(words, map[string]struct{}{"blocked": {}}); !slices.Equal(got, []string{"amber", "cedar"}) {
		t.Fatalf("filtered words = %v", got)
	}
}
