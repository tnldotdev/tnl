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
	"strconv"
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
	preferred []region.Code
	expires   time.Time
}

type rankingKey struct {
	inventory [32]byte
	trust     *tls.Config
}

type chooser struct {
	mu      sync.Mutex
	results map[rankingKey]measuredRanking
	flights map[rankingKey]chan struct{}
	measure func(context.Context, controlv1.RelayCandidates) []region.Code
}

var sharedChooser chooser

// PreferredRegions is an optional startup hint. transport or control failures
// leave placement to control's eligible-capacity selector.
func PreferredRegions(ctx context.Context, reader CandidateReader, publisherAccess string, trust *tls.Config) []string {
	ctx, stop := context.WithTimeout(ctx, sweepDeadline)
	defer stop()
	candidates, err := reader.RelayCandidates(ctx, publisherAccess)
	if err != nil {
		return nil
	}
	codes := sharedChooser.choose(ctx, candidates, trust)
	preferred := make([]string, len(codes))
	for index, code := range codes {
		preferred[index] = string(code)
	}
	return preferred
}

func (c *chooser) choose(ctx context.Context, candidates controlv1.RelayCandidates, trust *tls.Config) []region.Code {
	if len(candidates.Candidates) == 0 || len(candidates.Candidates) > maximumCandidates {
		return nil
	}
	encoded, err := json.Marshal(candidates)
	if err != nil {
		return nil
	}
	// distinct transport trust cannot reuse another publisher's probe result.
	key := rankingKey{inventory: sha256.Sum256(encoded), trust: trust}
	for ctx.Err() == nil {
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
			continue
		}
		if c.flights == nil {
			c.flights = make(map[rankingKey]chan struct{})
		}
		if len(c.flights) >= 16 {
			c.mu.Unlock()
			return nil
		}
		done := make(chan struct{})
		c.flights[key] = done
		c.mu.Unlock()

		measure := c.measure
		if measure == nil {
			measure = func(ctx context.Context, candidates controlv1.RelayCandidates) []region.Code {
				return Rank(ctx, candidates, trust)
			}
		}
		preferred := measure(ctx, candidates)
		c.mu.Lock()
		if ctx.Err() == nil && len(preferred) > 0 {
			if len(c.results) >= 16 {
				c.results = nil
			}
			if c.results == nil {
				c.results = make(map[rankingKey]measuredRanking)
			}
			c.results[key] = measuredRanking{preferred: slices.Clone(preferred), expires: time.Now().Add(10 * time.Minute)}
		}
		delete(c.flights, key)
		close(done)
		c.mu.Unlock()
		if ctx.Err() != nil {
			return nil
		}
		return preferred
	}
	return nil
}

type observation struct {
	code    region.Code
	elapsed time.Duration
	ok      bool
}

// Rank measures two distinct relay services per region. the whole sweep is
// bounded and a failed measurement leaves control's ordinary placement intact.
type regionPair struct {
	code  region.Code
	peers [2]muxsession.Endpoint
}

func candidatePairs(candidates controlv1.RelayCandidates) []regionPair {
	if len(candidates.Candidates) > maximumCandidates {
		return nil
	}
	groups := make(map[region.Code][]controlv1.RelayProbeCandidate)
	seen := make(map[string]bool)
	endpoints := make(map[string]bool)
	for _, candidate := range candidates.Candidates {
		code, known := region.Parse(candidate.Region)
		if !known {
			continue // a newer server catalog must not hide known usable pairs
		}
		if string(code) != candidate.Region || candidate.RelayServiceId == "" || seen[candidate.RelayServiceId] || candidate.TlsServerName == "" {
			return nil
		}
		host, port, err := net.SplitHostPort(candidate.RelayAddress)
		number, numberErr := strconv.Atoi(port)
		endpoint := candidate.RelayAddress + "\x00" + candidate.TlsServerName
		if err != nil || host == "" || numberErr != nil || number < 1 || number > 65535 || endpoints[endpoint] {
			return nil
		}
		seen[candidate.RelayServiceId] = true
		endpoints[endpoint] = true
		groups[code] = append(groups[code], candidate)
	}
	var pairs []regionPair
	for code, services := range groups {
		slices.SortFunc(services, func(a, b controlv1.RelayProbeCandidate) int {
			return strings.Compare(a.RelayServiceId, b.RelayServiceId)
		})
		if len(services) < 2 {
			continue
		}
		pairs = append(pairs, regionPair{code: code, peers: [2]muxsession.Endpoint{
			{Address: services[0].RelayAddress, ServerName: services[0].TlsServerName},
			{Address: services[1].RelayAddress, ServerName: services[1].TlsServerName},
		}})
	}
	slices.SortFunc(pairs, func(a, b regionPair) int { return strings.Compare(string(a.code), string(b.code)) })
	return pairs
}

func Rank(ctx context.Context, candidates controlv1.RelayCandidates, trust *tls.Config) []region.Code {
	if len(candidates.Candidates) > maximumCandidates || ctx.Err() != nil {
		return nil
	}
	pairs := candidatePairs(candidates)
	if len(pairs) < 2 || len(pairs) > maximumRegions {
		return nil
	}
	ctx, stop := context.WithTimeout(ctx, sweepDeadline)
	defer stop()
	gate := make(chan struct{}, 4)
	results := make(chan observation, 2*len(pairs))
	var workers sync.WaitGroup
	for _, pair := range pairs {
		code := pair.code
		for _, candidate := range pair.peers {
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
					configuration.MinVersion, configuration.ServerName = tls.VersionTLS13, candidate.ServerName
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
					connection, err := (&tls.Dialer{Config: configuration}).DialContext(attempt, "tcp", candidate.Address)
					if err == nil {
						secure := connection.(*tls.Conn)
						stop := context.AfterFunc(attempt, func() { _ = secure.Close() })
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
						stop()
						if err == nil && subtle.ConstantTimeCompare(nonce[:], echoed[:]) != 1 {
							err = errors.New("relay probe reply did not match")
						}
					}
					elapsed := time.Since(started)
					observability.PublisherRelayProbe(ctx, string(code), elapsed, err)
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
	preferred := make([]region.Code, 0, len(choices))
	for _, choice := range choices[:min(len(choices), 8)] {
		preferred = append(preferred, choice.code)
	}
	return preferred
}
