// package placement measures the publisher's path to live relay services before
// a run is reserved. control still owns eligibility, capacity, and assignments.
package placement

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/region"
	"github.com/tnldotdev/tnl/internal/transport/muxsession"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const (
	maximumCandidates = 32
	maximumRegions    = 16
	probeDeadline     = 2 * time.Second
	sweepDeadline     = 5 * time.Second
)

type CandidateReader interface {
	RelayCandidates(context.Context, string) (controlv1.RelayCandidates, error)
}

type measuredRanking struct {
	preferred []string
	expires   time.Time
}

type chooser struct {
	mu      sync.Mutex
	results map[[32]byte]measuredRanking
	flights map[[32]byte]chan struct{}
}

var sharedChooser chooser

// PreferredRegions is an optional startup hint. transport or control failures
// leave placement to control's eligible-capacity selector.
func PreferredRegions(ctx context.Context, reader CandidateReader, publisherAccess string) []string {
	ctx, stop := context.WithTimeout(ctx, sweepDeadline)
	defer stop()
	candidates, err := reader.RelayCandidates(ctx, publisherAccess)
	if err != nil {
		return nil
	}
	return sharedChooser.choose(ctx, candidates)
}

func (c *chooser) choose(ctx context.Context, candidates controlv1.RelayCandidates) []string {
	if len(candidates.Candidates) == 0 || len(candidates.Candidates) > maximumCandidates {
		return nil
	}
	encoded, err := json.Marshal(candidates)
	if err != nil {
		return nil
	}
	key := sha256.Sum256(encoded)
	c.mu.Lock()
	if entry, ok := c.results[key]; ok && entry.expires.After(time.Now()) {
		c.mu.Unlock()
		return slices.Clone(entry.preferred)
	}
	if done := c.flights[key]; done != nil {
		c.mu.Unlock()
		select {
		case <-ctx.Done():
			return nil
		case <-done:
		}
		c.mu.Lock()
		entry := c.results[key]
		c.mu.Unlock()
		if entry.expires.After(time.Now()) {
			return slices.Clone(entry.preferred)
		}
		return nil
	}
	if c.flights == nil {
		c.flights = make(map[[32]byte]chan struct{})
	}
	if len(c.flights) >= 16 {
		c.mu.Unlock()
		return nil
	}
	done := make(chan struct{})
	c.flights[key] = done
	c.mu.Unlock()

	preferred := Rank(ctx, candidates, nil)
	c.mu.Lock()
	if len(preferred) > 0 {
		if len(c.results) >= 16 {
			c.results = nil
		}
		if c.results == nil {
			c.results = make(map[[32]byte]measuredRanking)
		}
		c.results[key] = measuredRanking{preferred: slices.Clone(preferred), expires: time.Now().Add(10 * time.Minute)}
	}
	delete(c.flights, key)
	close(done)
	c.mu.Unlock()
	return preferred
}

type observation struct {
	code    region.Code
	elapsed time.Duration
	ok      bool
}

// Rank measures two distinct relay services per region. the whole sweep is
// bounded and a failed measurement leaves control's ordinary placement intact.
func Rank(ctx context.Context, candidates controlv1.RelayCandidates, trust *tls.Config) []string {
	if len(candidates.Candidates) > maximumCandidates || ctx.Err() != nil {
		return nil
	}
	groups := make(map[region.Code][]controlv1.RelayProbeCandidate)
	for _, candidate := range candidates.Candidates {
		code, known := region.Parse(candidate.Region)
		if !known || string(code) != candidate.Region || candidate.RelayServiceId == "" ||
			candidate.RelayAddress == "" || candidate.TlsServerName == "" {
			return nil
		}
		if _, _, err := net.SplitHostPort(candidate.RelayAddress); err != nil {
			return nil
		}
		groups[code] = append(groups[code], candidate)
	}
	if len(groups) < 2 || len(groups) > maximumRegions {
		return nil
	}
	ctx, stop := context.WithTimeout(ctx, sweepDeadline)
	defer stop()
	gate := make(chan struct{}, 4)
	results := make(chan observation, 2*len(groups))
	var workers sync.WaitGroup
	for code, services := range groups {
		slices.SortFunc(services, func(a, b controlv1.RelayProbeCandidate) int {
			return strings.Compare(a.RelayServiceId, b.RelayServiceId)
		})
		if len(services) < 2 || services[0].RelayServiceId == services[1].RelayServiceId {
			continue
		}
		for _, candidate := range services[:2] {
			workers.Go(func() {
				select {
				case gate <- struct{}{}:
					defer func() { <-gate }()
				case <-ctx.Done():
					results <- observation{code: code}
					return
				}
				best := observation{code: code}
				for range 2 {
					attempt, cancel := context.WithTimeout(ctx, probeDeadline)
					started := time.Now()
					configuration := &tls.Config{MinVersion: tls.VersionTLS13}
					if trust != nil {
						configuration = trust.Clone()
					}
					configuration.MinVersion, configuration.ServerName = tls.VersionTLS13, candidate.TlsServerName
					if configuration.InsecureSkipVerify {
						cancel()
						break
					}
					configuration.NextProtos = []string{muxsession.ProbeALPN}
					var nonce [16]byte
					if _, err := rand.Read(nonce[:]); err != nil {
						cancel()
						break
					}
					connection, err := (&tls.Dialer{Config: configuration}).DialContext(attempt, "tcp", candidate.RelayAddress)
					if err == nil {
						secure := connection.(*tls.Conn)
						if deadline, ok := attempt.Deadline(); ok {
							_ = secure.SetDeadline(deadline)
						}
						var echoed [16]byte
						if secure.ConnectionState().NegotiatedProtocol == muxsession.ProbeALPN {
							_, err = secure.Write(nonce[:])
							if err == nil {
								_, err = io.ReadFull(secure, echoed[:])
							}
						} else {
							err = errors.New("relay probe did not negotiate its protocol")
						}
						_ = connection.Close()
						if err == nil && subtle.ConstantTimeCompare(nonce[:], echoed[:]) != 1 {
							err = errors.New("relay probe reply did not match")
						}
					}
					elapsed := time.Since(started)
					observability.PublisherRelayProbe(ctx, candidate.Region, elapsed, err)
					if err == nil && (!best.ok || elapsed < best.elapsed) {
						best.ok, best.elapsed = true, elapsed
					}
					cancel()
				}
				results <- best
			})
		}
	}
	workers.Wait()
	close(results)
	measured := make(map[region.Code][]time.Duration)
	for result := range results {
		if result.ok {
			measured[result.code] = append(measured[result.code], result.elapsed)
		}
	}
	type ranked struct {
		code  region.Code
		worst time.Duration
	}
	var choices []ranked
	for code, timings := range measured {
		if len(timings) == 2 {
			choices = append(choices, ranked{code: code, worst: max(timings[0], timings[1])})
		}
	}
	slices.SortFunc(choices, func(a, b ranked) int {
		if a.worst < b.worst {
			return -1
		}
		if a.worst > b.worst {
			return 1
		}
		return strings.Compare(string(a.code), string(b.code))
	})
	preferred := make([]string, 0, len(choices))
	for _, choice := range choices[:min(len(choices), 8)] {
		preferred = append(preferred, string(choice.code))
	}
	return preferred
}
