package httpprotection

import (
	"errors"
	"net/netip"
	"time"
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
	SourceIP  string    `json:"source_ip"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Blocks is an immutable, bounded snapshot. expiry is checked locally even
// when the next control refresh cannot complete.
type Blocks struct {
	sources map[netip.Addr]time.Time
}

func DecodeBlocks(records []TemporaryBlock) (Blocks, error) {
	if len(records) == 0 {
		return Blocks{}, nil
	}
	if len(records) > MaxBlocks {
		return Blocks{}, errors.New("too many temporary source blocks")
	}
	blocks := Blocks{sources: make(map[netip.Addr]time.Time, len(records))}
	for _, record := range records {
		source, err := netip.ParseAddr(record.SourceIP)
		if err != nil || source.Zone() != "" || source != source.Unmap() || source.String() != record.SourceIP || record.ExpiresAt.IsZero() {
			return Blocks{}, errors.New("invalid temporary source block")
		}
		if _, exists := blocks.sources[source]; exists {
			return Blocks{}, errors.New("duplicate temporary source block")
		}
		blocks.sources[source] = record.ExpiresAt
	}
	return blocks, nil
}

func (b Blocks) Blocked(source netip.Addr, now time.Time) bool {
	return now.Before(b.sources[source.Unmap()])
}

type Rejections struct {
	SourceIP  string    `json:"source_ip"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Count     int       `json:"count"`
	RuleIDs   []int     `json:"rule_ids"`
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
	ip, err := netip.ParseAddr(r.SourceIP)
	if err != nil || ip.Zone() != "" || ip != ip.Unmap() || ip.String() != r.SourceIP ||
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
