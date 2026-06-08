package naming

import (
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"sync"
)

//go:embed corpus/friendly-words.json
var generatedHostnameWordsJSON []byte

//go:embed corpus/manifest.json
var generatedHostnameManifestJSON []byte

//go:embed corpus/exclusions.txt
var generatedHostnameExclusions []byte

//go:embed corpus/quarantined-pairs.txt
var generatedHostnamePairQuarantine []byte

type generatedHostnameWords struct {
	Predicates []string `json:"predicates"`
	Objects    []string `json:"objects"`
}

type GeneratedHostnameManifest struct {
	FormatVersion              int    `json:"format_version"`
	UpstreamRepository         string `json:"upstream_repository"`
	UpstreamCommit             string `json:"upstream_commit"`
	PredicateCount             int    `json:"predicate_count"`
	ObjectCount                int    `json:"object_count"`
	FriendlyWordsSHA256        string `json:"friendly_words_sha256"`
	ExclusionListSHA256        string `json:"exclusion_list_sha256"`
	PairQuarantineSHA256       string `json:"pair_quarantine_sha256"`
	RemainingNamespaceCapacity int64  `json:"remaining_namespace_capacity"`
}

var (
	generatedHostnameOnce      sync.Once
	generatedHostnameCorpus    generatedHostnameWords
	generatedHostnameManifest  GeneratedHostnameManifest
	generatedHostnamePairs     map[string]struct{}
	generatedHostnameCorpusErr error
)

// GeneratedHostnameLabel returns one cryptographically selected, reviewed DNS label.
func GeneratedHostnameLabel() (string, error) {
	if err := loadGeneratedHostnameCorpus(); err != nil {
		return "", err
	}
	for range 32 {
		predicate, err := randomWord(generatedHostnameCorpus.Predicates)
		if err != nil {
			return "", err
		}
		object, err := randomWord(generatedHostnameCorpus.Objects)
		if err != nil {
			return "", err
		}
		candidate := predicate + "-" + object
		if len(candidate) > MaxLabelBytes {
			continue
		}
		if _, quarantined := generatedHostnamePairs[candidate]; quarantined {
			continue
		}
		return candidate, nil
	}
	return "", errors.New("naming: generated hostname label selection exhausted")
}

// ValidateGeneratedHostnameCorpus validates hashes, filtering, and remaining capacity.
func ValidateGeneratedHostnameCorpus() error { return loadGeneratedHostnameCorpus() }

// GeneratedHostnameCorpusManifest returns the validated vendored corpus metadata.
func GeneratedHostnameCorpusManifest() (GeneratedHostnameManifest, error) {
	if err := loadGeneratedHostnameCorpus(); err != nil {
		return GeneratedHostnameManifest{}, err
	}
	return generatedHostnameManifest, nil
}

func loadGeneratedHostnameCorpus() error {
	generatedHostnameOnce.Do(func() {
		generatedHostnameCorpusErr = initializeGeneratedHostnameCorpus()
	})
	return generatedHostnameCorpusErr
}

func initializeGeneratedHostnameCorpus() error {
	if err := json.Unmarshal(generatedHostnameManifestJSON, &generatedHostnameManifest); err != nil {
		return fmt.Errorf("naming: decode generated hostname corpus manifest: %w", err)
	}
	if generatedHostnameManifest.FormatVersion != 1 || generatedHostnameManifest.UpstreamRepository == "" ||
		len(generatedHostnameManifest.UpstreamCommit) != 40 {
		return errors.New("naming: invalid generated hostname corpus manifest")
	}
	for name, value := range map[string]struct {
		data []byte
		want string
	}{
		"word corpus":     {generatedHostnameWordsJSON, generatedHostnameManifest.FriendlyWordsSHA256},
		"exclusions":      {generatedHostnameExclusions, generatedHostnameManifest.ExclusionListSHA256},
		"pair quarantine": {generatedHostnamePairQuarantine, generatedHostnameManifest.PairQuarantineSHA256},
	} {
		digest := sha256.Sum256(value.data)
		if hex.EncodeToString(digest[:]) != value.want {
			return fmt.Errorf("naming: %s hash does not match manifest", name)
		}
	}
	if err := json.Unmarshal(generatedHostnameWordsJSON, &generatedHostnameCorpus); err != nil {
		return fmt.Errorf("naming: decode generated hostname word corpus: %w", err)
	}
	if len(generatedHostnameCorpus.Predicates) != generatedHostnameManifest.PredicateCount ||
		len(generatedHostnameCorpus.Objects) != generatedHostnameManifest.ObjectCount {
		return errors.New("naming: generated hostname corpus count does not match manifest")
	}
	if err := validateWordList("predicate", generatedHostnameCorpus.Predicates); err != nil {
		return err
	}
	if err := validateWordList("object", generatedHostnameCorpus.Objects); err != nil {
		return err
	}
	exclusions, err := parseReviewedLines(generatedHostnameExclusions)
	if err != nil {
		return fmt.Errorf("naming: exclusions: %w", err)
	}
	excluded := make(map[string]struct{}, len(exclusions))
	for _, word := range exclusions {
		if !validGeneratedHostnameWord(word) {
			return fmt.Errorf("naming: invalid excluded word %q", word)
		}
		excluded[word] = struct{}{}
	}
	generatedHostnameCorpus.Predicates = filterWords(generatedHostnameCorpus.Predicates, excluded)
	generatedHostnameCorpus.Objects = filterWords(generatedHostnameCorpus.Objects, excluded)
	pairs, err := parseReviewedLines(generatedHostnamePairQuarantine)
	if err != nil {
		return fmt.Errorf("naming: pair quarantine: %w", err)
	}
	generatedHostnamePairs = make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		left, right, found := strings.Cut(pair, "-")
		if !found || !validGeneratedHostnameWord(left) || !validGeneratedHostnameWord(right) {
			return fmt.Errorf("naming: invalid quarantined pair %q", pair)
		}
		generatedHostnamePairs[pair] = struct{}{}
	}
	var capacity int64
	for _, predicate := range generatedHostnameCorpus.Predicates {
		for _, object := range generatedHostnameCorpus.Objects {
			candidate := predicate + "-" + object
			if len(candidate) <= MaxLabelBytes {
				if _, quarantined := generatedHostnamePairs[candidate]; !quarantined {
					capacity++
				}
			}
		}
	}
	if capacity != generatedHostnameManifest.RemainingNamespaceCapacity {
		return fmt.Errorf("naming: remaining generated hostname namespace is %d, manifest records %d",
			capacity, generatedHostnameManifest.RemainingNamespaceCapacity)
	}
	return nil
}

func validateWordList(kind string, words []string) error {
	seen := make(map[string]struct{}, len(words))
	for _, word := range words {
		if !validGeneratedHostnameWord(word) {
			return fmt.Errorf("naming: invalid generated hostname %s %q", kind, word)
		}
		if _, duplicate := seen[word]; duplicate {
			return fmt.Errorf("naming: duplicate generated hostname %s %q", kind, word)
		}
		seen[word] = struct{}{}
	}
	return nil
}

func validGeneratedHostnameWord(word string) bool {
	if word == "" || len(word) > MaxLabelBytes {
		return false
	}
	for _, char := range word {
		if char < 'a' || char > 'z' {
			return false
		}
	}
	return true
}

func parseReviewedLines(data []byte) ([]string, error) {
	text := string(data)
	if text == "" || !strings.HasSuffix(text, "\n") {
		return nil, errors.New("list must be nonempty and newline-terminated")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if !slices.IsSorted(lines) {
		return nil, errors.New("list must be sorted")
	}
	for index, line := range lines {
		if line == "" || index > 0 && line == lines[index-1] {
			return nil, errors.New("list contains an empty or duplicate entry")
		}
	}
	return lines, nil
}

func filterWords(words []string, excluded map[string]struct{}) []string {
	result := make([]string, 0, len(words))
	for _, word := range words {
		if _, found := excluded[word]; !found {
			result = append(result, word)
		}
	}
	return result
}

func randomWord(words []string) (string, error) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(words))))
	if err != nil {
		return "", fmt.Errorf("naming: select generated hostname word: %w", err)
	}
	return words[index.Int64()], nil
}
