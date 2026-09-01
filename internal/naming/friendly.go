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
var friendlyWordsJSON []byte

//go:embed corpus/manifest.json
var friendlyManifestJSON []byte

//go:embed corpus/exclusions.txt
var friendlyExclusions []byte

//go:embed corpus/quarantined-pairs.txt
var friendlyPairQuarantine []byte

type friendlyWords struct {
	Predicates []string `json:"predicates"`
	Objects    []string `json:"objects"`
}

type FriendlyManifest struct {
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
	friendlyOnce      sync.Once
	friendlyCorpus    friendlyWords
	friendlyManifest  FriendlyManifest
	friendlyPairs     map[string]struct{}
	friendlyCorpusErr error
)

// FriendlyName returns one cryptographically selected, reviewed DNS label.
func FriendlyName() (string, error) {
	if err := loadFriendlyCorpus(); err != nil {
		return "", err
	}
	for range 32 {
		predicate, err := randomWord(friendlyCorpus.Predicates)
		if err != nil {
			return "", err
		}
		object, err := randomWord(friendlyCorpus.Objects)
		if err != nil {
			return "", err
		}
		candidate := predicate + "-" + object
		if len(candidate) > MaxLabelBytes {
			continue
		}
		if _, quarantined := friendlyPairs[candidate]; quarantined {
			continue
		}
		return candidate, nil
	}
	return "", errors.New("naming: friendly-name selection exhausted")
}

// ValidateFriendlyCorpus validates hashes, filtering, and remaining capacity.
func ValidateFriendlyCorpus() error { return loadFriendlyCorpus() }

// FriendlyCorpusManifest returns the validated vendored corpus metadata.
func FriendlyCorpusManifest() (FriendlyManifest, error) {
	if err := loadFriendlyCorpus(); err != nil {
		return FriendlyManifest{}, err
	}
	return friendlyManifest, nil
}

func loadFriendlyCorpus() error {
	friendlyOnce.Do(func() {
		friendlyCorpusErr = initializeFriendlyCorpus()
	})
	return friendlyCorpusErr
}

func initializeFriendlyCorpus() error {
	if err := json.Unmarshal(friendlyManifestJSON, &friendlyManifest); err != nil {
		return fmt.Errorf("naming: decode friendly corpus manifest: %w", err)
	}
	if friendlyManifest.FormatVersion != 1 || friendlyManifest.UpstreamRepository == "" ||
		len(friendlyManifest.UpstreamCommit) != 40 {
		return errors.New("naming: invalid friendly corpus manifest")
	}
	for name, value := range map[string]struct {
		data []byte
		want string
	}{
		"friendly words":  {friendlyWordsJSON, friendlyManifest.FriendlyWordsSHA256},
		"exclusions":      {friendlyExclusions, friendlyManifest.ExclusionListSHA256},
		"pair quarantine": {friendlyPairQuarantine, friendlyManifest.PairQuarantineSHA256},
	} {
		digest := sha256.Sum256(value.data)
		if hex.EncodeToString(digest[:]) != value.want {
			return fmt.Errorf("naming: %s hash does not match manifest", name)
		}
	}
	if err := json.Unmarshal(friendlyWordsJSON, &friendlyCorpus); err != nil {
		return fmt.Errorf("naming: decode friendly words: %w", err)
	}
	if len(friendlyCorpus.Predicates) != friendlyManifest.PredicateCount ||
		len(friendlyCorpus.Objects) != friendlyManifest.ObjectCount {
		return errors.New("naming: friendly corpus count does not match manifest")
	}
	if err := validateWordList("predicate", friendlyCorpus.Predicates); err != nil {
		return err
	}
	if err := validateWordList("object", friendlyCorpus.Objects); err != nil {
		return err
	}
	exclusions, err := parseReviewedLines(friendlyExclusions)
	if err != nil {
		return fmt.Errorf("naming: exclusions: %w", err)
	}
	excluded := make(map[string]struct{}, len(exclusions))
	for _, word := range exclusions {
		if !validFriendlyWord(word) {
			return fmt.Errorf("naming: invalid excluded word %q", word)
		}
		excluded[word] = struct{}{}
	}
	friendlyCorpus.Predicates = filterWords(friendlyCorpus.Predicates, excluded)
	friendlyCorpus.Objects = filterWords(friendlyCorpus.Objects, excluded)
	pairs, err := parseReviewedLines(friendlyPairQuarantine)
	if err != nil {
		return fmt.Errorf("naming: pair quarantine: %w", err)
	}
	friendlyPairs = make(map[string]struct{}, len(pairs))
	for _, pair := range pairs {
		left, right, found := strings.Cut(pair, "-")
		if !found || !validFriendlyWord(left) || !validFriendlyWord(right) {
			return fmt.Errorf("naming: invalid quarantined pair %q", pair)
		}
		friendlyPairs[pair] = struct{}{}
	}
	var capacity int64
	for _, predicate := range friendlyCorpus.Predicates {
		for _, object := range friendlyCorpus.Objects {
			candidate := predicate + "-" + object
			if len(candidate) <= MaxLabelBytes {
				if _, quarantined := friendlyPairs[candidate]; !quarantined {
					capacity++
				}
			}
		}
	}
	if capacity != friendlyManifest.RemainingNamespaceCapacity {
		return fmt.Errorf("naming: remaining friendly namespace is %d, manifest records %d",
			capacity, friendlyManifest.RemainingNamespaceCapacity)
	}
	return nil
}

func validateWordList(kind string, words []string) error {
	seen := make(map[string]struct{}, len(words))
	for _, word := range words {
		if !validFriendlyWord(word) {
			return fmt.Errorf("naming: invalid friendly %s %q", kind, word)
		}
		if _, duplicate := seen[word]; duplicate {
			return fmt.Errorf("naming: duplicate friendly %s %q", kind, word)
		}
		seen[word] = struct{}{}
	}
	return nil
}

func validFriendlyWord(word string) bool {
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
		return "", fmt.Errorf("naming: select friendly word: %w", err)
	}
	return words[index.Int64()], nil
}
