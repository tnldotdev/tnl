package daemon

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// these are committed record mutations, not API attempts, DNS queries, or billed
// Route 53 operations. timestamps come from the existing atomic fixture commit.
type integrationDNSServiceChanges struct {
	EndpointA    map[string]int `json:"endpoint_a"`
	OwnerTXT     map[string]int `json:"owner_txt"`
	ChallengeTXT map[string]int `json:"challenge_txt"`
	endpointAt   time.Time
	ownerAt      time.Time
}

func (f *integrationRoute53) serviceChanges(hostname string, started, through time.Time) integrationDNSServiceChanges {
	result := integrationDNSServiceChanges{EndpointA: map[string]int{}, OwnerTXT: map[string]int{}, ChallengeTXT: map[string]int{}}
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, change := range f.changes {
		if change.zoneID != f.zoneID || change.committedAt.Before(started) || change.committedAt.After(through) {
			continue
		}
		switch {
		case change.Record.Name == dns.Fqdn(hostname) && change.Record.Type == "A":
			result.EndpointA[change.Action]++
			if change.Action != "DELETE" && result.endpointAt.IsZero() {
				result.endpointAt = change.committedAt
			}
		case change.Record.Name == dns.Fqdn("_tnl-owner."+hostname) && change.Record.Type == "TXT":
			result.OwnerTXT[change.Action]++
			if change.Action != "DELETE" && result.ownerAt.IsZero() {
				result.ownerAt = change.committedAt
			}
		case change.Record.Name == dns.Fqdn("_acme-challenge."+hostname) && change.Record.Type == "TXT":
			result.ChallengeTXT[change.Action]++
		}
	}
	return result
}

type integrationDNSStartupObservation struct {
	started, ownerPrepared, publisherStarted, certificateObserved, ready, firstGETStarted, firstGETFinished time.Time
}

func (o integrationDNSStartupObservation) phases(changes integrationDNSServiceChanges) (map[string]time.Duration, error) {
	ordered := []time.Time{o.started, o.ownerPrepared, o.publisherStarted, o.certificateObserved, o.ready, o.firstGETStarted, o.firstGETFinished}
	for index, at := range ordered {
		if at.IsZero() || index > 0 && at.Before(ordered[index-1]) {
			return nil, errors.New("service startup phase is missing or out of order")
		}
	}
	for _, at := range []time.Time{changes.endpointAt, changes.ownerAt} {
		if at.IsZero() || at.Before(o.started) || at.After(o.ready) {
			return nil, errors.New("owned endpoint records were not observed before Ready")
		}
	}
	recordsAt := changes.endpointAt
	if changes.ownerAt.After(recordsAt) {
		recordsAt = changes.ownerAt
	}
	// DNS and certificate work can overlap owner enrollment and each other.
	// the two observation offsets below are not additive pipeline durations.
	return map[string]time.Duration{
		"save_and_enroll_ns":                      o.ownerPrepared.Sub(o.started),
		"publisher_start_to_ready_ns":             o.ready.Sub(o.publisherStarted),
		"save_to_ready_ns":                        o.ready.Sub(o.started),
		"save_to_first_configured_dns_https_ns":   o.firstGETFinished.Sub(o.started),
		"endpoint_records_committed_offset_ns":    recordsAt.Sub(o.started),
		"certificate_material_observed_offset_ns": o.certificateObserved.Sub(o.started),
		"ready_to_first_configured_dns_https_ns":  o.firstGETFinished.Sub(o.ready),
		"first_configured_dns_https_ns":           o.firstGETFinished.Sub(o.firstGETStarted),
	}, nil
}

func TestDNSStartupChangesObserveOnlyAtomicSuccessfulCommits(t *testing.T) {
	f := &integrationRoute53{zoneID: "fixture", zone: &integrationDNSZone{records: make(map[string]integrationDNSRecord)}}
	entered, release := make(chan struct{}), make(chan struct{})
	done := make(chan error, 1)
	f.setBeforeChange(func(context.Context, integrationDNSChange) error {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		return nil
	})
	changes := []integrationDNSChange{
		{Action: "CREATE", Record: integrationDNSRecord{Name: "service.example.test.", Type: "A", TTL: 1}},
		{Action: "CREATE", Record: integrationDNSRecord{Name: "_tnl-owner.service.example.test.", Type: "TXT", TTL: 1}},
	}
	started := time.Now()
	go func() { done <- f.applyChanges(t.Context(), changes) }()
	<-entered
	f.mu.Lock()
	pendingRecords, pendingChanges := len(f.zone.records), len(f.changes)
	f.mu.Unlock()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	finished := time.Now()
	if pendingRecords != 0 || pendingChanges != 0 {
		t.Fatal("pending provider change was reported as a committed DNS mutation")
	}
	if len(f.changes) != 2 {
		t.Fatal("successful atomic batch was not observed", len(f.changes))
	}
	for _, change := range f.changes {
		if change.committedAt.IsZero() || change.committedAt.Before(started) || change.committedAt.After(finished) ||
			change.committedAt != f.changes[0].committedAt || change.zoneID != f.zoneID {
			t.Fatal("DNS mutation has no exact atomic commit observation", change.committedAt)
		}
	}
	f.setBeforeChange(nil)
	if err := f.applyChanges(t.Context(), []integrationDNSChange{{Action: "DELETE", Record: integrationDNSRecord{Name: "missing.example.test.", Type: "A"}}}); err == nil {
		t.Fatal("fixture accepted invalid removal")
	}
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	if err := f.applyChanges(canceled, changes); err == nil {
		t.Fatal("fixture accepted canceled change")
	}
	if len(f.changes) != 2 {
		t.Fatal("failed or canceled API attempts were counted as committed mutations")
	}
}

func TestDNSStartupChangesKeepExactServiceWindowAndCounts(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	const hostname = "service.example.test"
	f := &integrationRoute53{zoneID: "fixture"}
	add := func(name, recordType, action, zone string, at time.Time) {
		f.changes = append(f.changes, integrationDNSChange{Action: action, zoneID: zone, committedAt: at,
			Record: integrationDNSRecord{Name: dns.Fqdn(name), Type: recordType}})
	}
	add(hostname, "A", "CREATE", f.zoneID, start.Add(-time.Second))
	add("sibling.example.test", "A", "CREATE", f.zoneID, start)
	add("*.example.test", "A", "CREATE", f.zoneID, start)
	add(hostname, "A", "CREATE", "other-zone", start)
	add(hostname, "A", "CREATE", f.zoneID, start.Add(time.Second))
	add("_tnl-owner."+hostname, "TXT", "CREATE", f.zoneID, start.Add(2*time.Second))
	add(hostname, "A", "UPSERT", f.zoneID, start.Add(3*time.Second))
	add("_acme-challenge."+hostname, "TXT", "CREATE", f.zoneID, start.Add(3*time.Second))
	add("_acme-challenge."+hostname, "TXT", "DELETE", f.zoneID, start.Add(4*time.Second))
	add(hostname, "A", "DELETE", f.zoneID, start.Add(6*time.Second))
	first := f.serviceChanges(hostname, start, start.Add(3*time.Second))
	after := f.serviceChanges(hostname, start, start.Add(5*time.Second))
	if !reflect.DeepEqual(first.EndpointA, map[string]int{"CREATE": 1, "UPSERT": 1}) ||
		!reflect.DeepEqual(first.OwnerTXT, map[string]int{"CREATE": 1}) ||
		!reflect.DeepEqual(first.ChallengeTXT, map[string]int{"CREATE": 1}) ||
		!reflect.DeepEqual(after.ChallengeTXT, map[string]int{"CREATE": 1, "DELETE": 1}) ||
		!reflect.DeepEqual(after.EndpointA, first.EndpointA) ||
		!first.endpointAt.Equal(start.Add(time.Second)) || !first.ownerAt.Equal(start.Add(2*time.Second)) {
		t.Fatal("per-service observation included another name, zone, time window, or deduplicated actual commits", first, after)
	}
}

func TestDNSStartupPhasesRequireObservationsNotPerformanceLimits(t *testing.T) {
	start := time.Unix(1_800_000_000, 0)
	valid := integrationDNSStartupObservation{started: start, ownerPrepared: start.Add(time.Hour), publisherStarted: start.Add(2 * time.Hour),
		certificateObserved: start.Add(3 * time.Hour), ready: start.Add(4 * time.Hour),
		firstGETStarted: start.Add(5 * time.Hour), firstGETFinished: start.Add(6 * time.Hour)}
	changes := integrationDNSServiceChanges{endpointAt: start.Add(30 * time.Minute), ownerAt: start.Add(90 * time.Minute)}
	phases, err := valid.phases(changes)
	if err != nil || phases["save_to_ready_ns"] != 4*time.Hour || phases["first_configured_dns_https_ns"] != time.Hour ||
		phases["endpoint_records_committed_offset_ns"] != 90*time.Minute {
		t.Fatal("measurement introduced a performance threshold or changed phase meaning", phases, err)
	}
	for _, field := range []string{"start", "enrollment", "publisher", "certificate", "ready", "request", "response", "DNS", "late DNS"} {
		t.Run(field, func(t *testing.T) {
			observation, records := valid, changes
			switch field {
			case "start":
				observation.started = time.Time{}
			case "enrollment":
				observation.ownerPrepared = time.Time{}
			case "publisher":
				observation.publisherStarted = observation.ownerPrepared.Add(-time.Second)
			case "certificate":
				observation.certificateObserved = time.Time{}
			case "ready":
				observation.ready = time.Time{}
			case "request":
				observation.firstGETStarted = observation.ready.Add(-time.Second)
			case "response":
				observation.firstGETFinished = observation.firstGETStarted.Add(-time.Second)
			case "DNS":
				records.ownerAt = time.Time{}
			case "late DNS":
				records.endpointAt = observation.ready.Add(time.Second)
			}
			if _, err := observation.phases(records); err == nil {
				t.Fatal("missing or invalid measurement passed as an observed phase")
			}
		})
	}
}
