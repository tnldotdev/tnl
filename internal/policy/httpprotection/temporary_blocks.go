package httpprotection

import (
	"errors"
	"net/netip"
	"time"

	"github.com/tnldotdev/tnl/internal/policy/ippolicy"
)

const (
	BlockThreshold = 10
	BlockWindow    = time.Minute
	BlockDuration  = time.Minute
	// history outlives the full collection window plus report freshness.
	BlockRetention = 2 * time.Minute
	MaxBlocks      = 256
)

type TemporaryBlock struct {
	SourceDigest string    `json:"source_digest"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// Blocks is an immutable, bounded snapshot. expiry is checked locally even
// when the next control refresh cannot complete.
type Blocks struct {
	key     [32]byte
	sources map[string]time.Time
}

func DecodeBlocks(key []byte, records []TemporaryBlock) (Blocks, error) {
	if len(key) == 0 && len(records) == 0 {
		return Blocks{}, nil
	}
	if len(key) != 32 || [32]byte(key) == [32]byte{} || len(records) > MaxBlocks {
		return Blocks{}, errors.New("too many temporary source blocks")
	}
	blocks := Blocks{key: [32]byte(key), sources: make(map[string]time.Time, len(records))}
	for _, record := range records {
		_, err := ippolicy.ParseDigest(record.SourceDigest)
		if err != nil || record.ExpiresAt.IsZero() {
			return Blocks{}, errors.New("invalid temporary source block")
		}
		if _, exists := blocks.sources[record.SourceDigest]; exists {
			return Blocks{}, errors.New("duplicate temporary source block")
		}
		blocks.sources[record.SourceDigest] = record.ExpiresAt
	}
	return blocks, nil
}

func (b Blocks) Blocked(source netip.Addr, now time.Time) bool {
	digest, err := ippolicy.HashAddress(b.key, source)
	return err == nil && now.Before(b.sources[digest])
}

func (b Blocks) Key() [32]byte { return b.key }

type Rejections struct {
	SourceDigest string    `json:"source_digest"`
	StartedAt    time.Time `json:"started_at"`
	EndedAt      time.Time `json:"ended_at"`
	Count        int       `json:"count"`
	RuleIDs      []int     `json:"rule_ids"`
}

func EligibleRule(id int) bool {
	// explicit detection rules for traversal, inclusion, command execution,
	// XSS, SQL injection, and Java injection; not generic protocol policy.
	switch id {
	case 930100, 930110, 930120, 931100,
		932100, 932105, 932110, 932115, 932130,
		933100, 941100, 941110, 941120, 942100, 942190, 942260, 944100:
		return true
	}
	return false
}

func (r Rejections) Validate(now time.Time) error {
	_, err := ippolicy.ParseDigest(r.SourceDigest)
	if err != nil ||
		r.Count != BlockThreshold || r.EndedAt.Before(r.StartedAt) || r.StartedAt.Before(r.EndedAt.Add(-BlockWindow)) ||
		r.StartedAt.IsZero() || r.EndedAt.After(now.Add(5*time.Second)) || r.EndedAt.Before(now.Add(-10*time.Second)) || len(r.RuleIDs) == 0 || len(r.RuleIDs) > 32 {
		return errors.New("invalid or stale temporary-block evidence")
	}
	for _, id := range r.RuleIDs {
		if !EligibleRule(id) {
			return errors.New("temporary-block evidence needs eligible rejections")
		}
	}
	return nil
}
