package main

import (
	"cmp"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/benchworkload"
	"github.com/tnldotdev/tnl/internal/publisher"
	"github.com/tnldotdev/tnl/internal/tunnel"
)

type benchmarkResult struct {
	SchemaVersion         int                             `json:"schema_version"`
	RunID                 string                          `json:"run_id"`
	Plan                  benchmarkPlan                   `json:"plan"`
	StartedAt             time.Time                       `json:"started_at"`
	FinishedAt            time.Time                       `json:"finished_at"`
	Status                string                          `json:"status"`
	Error                 string                          `json:"error,omitempty"`
	PublicURLs            []string                        `json:"public_urls,omitempty"`
	PublicURLInfo         []benchmarkPublicURL            `json:"public_url_info,omitempty"`
	Activation            time.Duration                   `json:"activation_duration,omitempty"`
	Fallbacks             []benchmarkTransportFallback    `json:"transport_fallbacks,omitempty"`
	Observations          []benchmarkPublisherObservation `json:"publisher_observations,omitempty"`
	Dropped               int                             `json:"publisher_observations_dropped,omitempty"`
	Direct                benchworkload.VisitorResult     `json:"direct_baseline"`
	DirectWarmupBandwidth *benchworkload.BandwidthResult  `json:"direct_warmup_bandwidth,omitempty"`
	DirectBandwidth       *benchworkload.BandwidthResult  `json:"direct_bandwidth,omitempty"`
	DirectHeld            *heldProgress                   `json:"direct_held,omitempty"`
	WarmupBandwidth       *benchworkload.BandwidthResult  `json:"warmup_bandwidth,omitempty"`
	Steady                []benchworkload.VisitorResult   `json:"steady"`
	SteadyBandwidth       []benchworkload.BandwidthResult `json:"steady_bandwidth,omitempty"`
	SteadyHeld            []heldProgress                  `json:"steady_held,omitempty"`
	SteadyByURL           []map[string]*urlVisitorResult  `json:"steady_by_public_url,omitempty"`
	CleanupExact          bool                            `json:"cleanup_exact"`
	CleanupStatus         string                          `json:"cleanup_status"`
	Generator             generatorResult                 `json:"generator"`
}

type heldProgress struct {
	Open        int   `json:"open"`
	Progressing int   `json:"progressing"`
	Bytes       int64 `json:"bytes"`
}

type benchmarkPublicURL struct {
	Index       int           `json:"index"`
	PublicURL   string        `json:"public_url"`
	PublicURLID string        `json:"public_url_id"`
	Transport   string        `json:"transport"`
	Activation  time.Duration `json:"activation"`
}

type benchmarkPublisherObservation struct {
	Index       int       `json:"index"`
	PublicURLID string    `json:"public_url_id,omitempty"`
	At          time.Time `json:"at"`
	Kind        string    `json:"kind"`
	Detail      string    `json:"detail,omitempty"`
}

const maxPublisherObservations = 64

type publisherObservationRecorder struct {
	mu      sync.Mutex
	events  []benchmarkPublisherObservation
	dropped int
}

func (r *publisherObservationRecorder) add(event benchmarkPublisherObservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) == maxPublisherObservations {
		oldest := 0
		for index, previous := range r.events {
			if previous.Kind == "error" {
				oldest = index
				break
			}
		}
		copy(r.events[oldest:], r.events[oldest+1:])
		r.events[len(r.events)-1] = event
		r.dropped++
		return
	}
	r.events = append(r.events, event)
}

func (r *publisherObservationRecorder) Observe(index int, event publisher.Event) error {
	r.add(benchmarkPublisherObservation{Index: index, PublicURLID: event.PublicURLID, At: time.Now().UTC(), Kind: string(event.Type)})
	return nil
}

func (r *publisherObservationRecorder) Report(index int, err error) {
	r.add(benchmarkPublisherObservation{Index: index, At: time.Now().UTC(), Kind: "error", Detail: err.Error()})
}

func (r *publisherObservationRecorder) Snapshot() ([]benchmarkPublisherObservation, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]benchmarkPublisherObservation(nil), r.events...), r.dropped
}

type benchmarkTransportFallback struct {
	PublicURLID string    `json:"public_url_id"`
	At          time.Time `json:"at"`
}

type transportFallbackRecorder struct {
	mu     sync.Mutex
	events []benchmarkTransportFallback
}

func (r *transportFallbackRecorder) Observe(_ int, event publisher.Event) error {
	if event.Type == publisher.EventTransportFallback {
		r.mu.Lock()
		r.events = append(r.events, benchmarkTransportFallback{PublicURLID: event.PublicURLID, At: time.Now().UTC()})
		r.mu.Unlock()
	}
	return nil
}

func (r *transportFallbackRecorder) Snapshot() []benchmarkTransportFallback {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]benchmarkTransportFallback(nil), r.events...)
}

type urlVisitorResult struct {
	Scheduled    int                          `json:"scheduled"`
	Started      int                          `json:"started"`
	Successes    int                          `json:"successes"`
	Failures     int                          `json:"failures"`
	Timeouts     int                          `json:"timeouts"`
	Missed       int                          `json:"missed"`
	QueueExpired int                          `json:"queue_expired"`
	FirstFailure *benchworkload.RequestResult `json:"first_failure,omitempty"`
}

type generatorResult struct {
	Goroutines int           `json:"goroutines"`
	HeapBytes  uint64        `json:"heap_bytes"`
	Elapsed    time.Duration `json:"elapsed"`
}

func recordReadyPublicURLs(result *benchmarkResult, ready []benchworkload.PublishedPublicURL, transport benchworkload.TransportChoice, count int) []string {
	urls := make([]string, count)
	for _, publicURL := range ready {
		urls[publicURL.Index] = publicURL.Ready.PublicURL
		selected := string(transport)
		if transport == benchworkload.TransportTCP || transport == benchworkload.TransportMixed && publicURL.Index%2 != 0 {
			selected = string(tunnel.TransportTLSTCP)
		} else if transport == benchworkload.TransportQUIC || transport == benchworkload.TransportMixed {
			selected = string(tunnel.TransportQUIC)
		}
		result.PublicURLInfo = append(result.PublicURLInfo, benchmarkPublicURL{
			Index: publicURL.Index, PublicURL: publicURL.Ready.PublicURL, PublicURLID: publicURL.Ready.PublicURLID,
			Transport: selected, Activation: publicURL.Activation,
		})
	}
	slices.SortFunc(result.PublicURLInfo, func(a, b benchmarkPublicURL) int { return cmp.Compare(a.Index, b.Index) })
	for _, publicURL := range result.PublicURLInfo {
		result.PublicURLs = append(result.PublicURLs, publicURL.PublicURL)
	}
	return urls
}

func newURLVisitorResults(urls []string) (map[string]*urlVisitorResult, func(benchworkload.RequestResult)) {
	results := make(map[string]*urlVisitorResult, len(urls))
	for _, publicURL := range urls {
		results[publicURL] = new(urlVisitorResult)
	}
	// Visitor.Run serializes callbacks from its workers.
	observe := func(row benchworkload.RequestResult) {
		summary := results[row.URL]
		if row.QueueExpired {
			summary.QueueExpired++
		} else {
			summary.Started++
			if row.Error == "" {
				summary.Successes++
			} else {
				summary.Failures++
				if row.Timeout {
					summary.Timeouts++
				}
			}
		}
		if row.Error != "" && summary.FirstFailure == nil {
			summary.FirstFailure = &row
		}
	}
	return results, observe
}

func completeURLVisitorResults(urls []string, scheduled int, results map[string]*urlVisitorResult) error {
	perURL, remainder := scheduled/len(urls), scheduled%len(urls)
	for index, publicURL := range urls {
		summary := results[publicURL]
		summary.Scheduled = perURL
		if index < remainder {
			summary.Scheduled++
		}
		summary.Missed = summary.Scheduled - summary.Started - summary.QueueExpired
		if summary.Missed < 0 {
			return fmt.Errorf("public URL %s has more completed requests than scheduled", publicURL)
		}
	}
	return nil
}
