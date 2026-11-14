package httpprotection

import (
	"net/netip"
	"testing"
	"time"
)

func TestTemporaryBlockSnapshotsValidateAndExpireLocally(t *testing.T) {
	now := time.Now()
	records := []TemporaryBlock{{SourceIP: "192.0.2.1", ExpiresAt: now.Add(time.Minute)}, {SourceIP: "2001:db8::1", ExpiresAt: now.Add(time.Minute)}}
	blocks, err := DecodeBlocks(records)
	if err != nil {
		t.Fatal(err)
	}
	records[0].SourceIP = "203.0.113.1"
	for _, ip := range []string{"192.0.2.1", "::ffff:192.0.2.1", "2001:db8::1"} {
		source := netip.MustParseAddr(ip)
		if !blocks.Blocked(source, now) || blocks.Blocked(source, now.Add(time.Minute)) {
			t.Fatal("snapshot did not retain exact locally expiring IPs", source)
		}
	}
	for _, ip := range []string{"192.0.2.2", "2001:db8::2", "203.0.113.1"} {
		if blocks.Blocked(netip.MustParseAddr(ip), now) {
			t.Fatal("snapshot mutated or expanded beyond its exact IPs")
		}
	}
	for _, invalid := range [][]TemporaryBlock{
		{{SourceIP: "192.0.2.1/32", ExpiresAt: now}},
		{{SourceIP: "::ffff:192.0.2.1", ExpiresAt: now}},
		{{SourceIP: "fe80::1%en0", ExpiresAt: now}},
		{{SourceIP: "192.0.2.1"}},
		{records[0], records[0]}, make([]TemporaryBlock, MaxBlocks+1),
	} {
		if _, err := DecodeBlocks(invalid); err == nil {
			t.Fatal("accepted invalid block snapshot", invalid)
		}
	}
}

func TestTemporaryBlockOptIn(t *testing.T) {
	for _, mode := range []Mode{"", Block, Detect, Off} {
		for _, enabled := range []bool{false, true} {
			s := Settings{WAF: mode, TemporaryBlocks: enabled}
			if s.BlocksSources() != (enabled && (mode == "" || mode == Block)) {
				t.Fatal("temporary block opt-in changed", s)
			}
		}
	}
}

func TestTemporaryBlockEvidence(t *testing.T) {
	now := time.Now()
	valid := Rejections{SourceIP: "192.0.2.1", StartedAt: now.Add(-time.Second), EndedAt: now, Count: BlockThreshold, RuleIDs: []int{942100}}
	if err := valid.Validate(now); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Rejections){
		func(r *Rejections) { r.SourceIP = "192.0.2.1/32" },
		func(r *Rejections) { r.SourceIP = "::ffff:192.0.2.1" },
		func(r *Rejections) { r.SourceIP = "fe80::1%en0" },
		func(r *Rejections) { r.Count-- },
		func(r *Rejections) { r.StartedAt = now.Add(-BlockWindow - time.Nanosecond) },
		func(r *Rejections) { r.StartedAt = now.Add(time.Second) },
		func(r *Rejections) { r.EndedAt = now.Add(6 * time.Second) },
		func(r *Rejections) { r.EndedAt = now.Add(-11 * time.Second); r.StartedAt = r.EndedAt },
		func(r *Rejections) { r.RuleIDs = []int{920420, 949110} },
		func(r *Rejections) { r.RuleIDs = make([]int, 33); r.RuleIDs[0] = 942100 },
	} {
		rejected := valid
		change(&rejected)
		if err := rejected.Validate(now); err == nil {
			t.Fatalf("accepted invalid evidence: %+v", rejected)
		}
	}
	for _, source := range []string{"192.0.2.1", "2001:db8::1"} {
		valid.SourceIP = source
		if err := valid.Validate(now); err != nil {
			t.Fatal(err)
		}
	}
}
