package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/controlstate"
)

func sampleResources(ctx context.Context, rawURLs []string, moment string) []resourceSample {
	result := make([]resourceSample, len(rawURLs))
	var workers sync.WaitGroup
	for index, rawURL := range rawURLs {
		workers.Add(1)
		go func() {
			defer workers.Done()
			identity := rawURL
			role := "unknown"
			if parsed, err := url.Parse(rawURL); err == nil {
				identity = parsed.Hostname()
				role = metricRole(parsed.Fragment)
			}
			if role == "unknown" {
				role = metricRole(identity)
			}
			sample := resourceSample{Role: role, Identity: identity, Moment: moment, Timestamp: time.Now().UTC()}
			values, err := sampleMetrics(ctx, rawURL)
			if err != nil {
				sample.Error = err.Error()
			} else {
				sample.Metrics = make(map[string]float64)
				for name, value := range values {
					if strings.HasPrefix(name, "tnl_") || strings.HasPrefix(name, "process_") || name == "go_goroutines" {
						sample.Metrics[name] = value
					}
				}
			}
			result[index] = sample
		}()
	}
	workers.Wait()
	return result
}

type resourceSampler struct {
	cancel  context.CancelFunc
	done    chan []resourceSample
	once    sync.Once
	result  []resourceSample
	dropped int
}

// Failure snapshots fit beside the bounded periodic window in one result body.
func sampleFailureResources(ctx context.Context, endpoints []string) []resourceSample {
	samples := sampleResources(context.WithoutCancel(ctx), endpoints[:min(len(endpoints), 16)], "failure")
	remaining := 512 << 10
	for index := range samples {
		data, err := json.Marshal(samples[index])
		if err != nil || len(data) > remaining {
			samples[index].Metrics = nil
			samples[index].Error = "failure metrics payload limit exceeded"
		} else {
			remaining -= len(data)
		}
	}
	return samples
}

func startResourceSampler(parent context.Context, rawURLs []string, interval time.Duration) *resourceSampler {
	ctx, cancel := context.WithCancel(parent)
	sampler := &resourceSampler{cancel: cancel, done: make(chan []resourceSample, 1)}
	go func() {
		var samples []resourceSample
		var sizes []int
		bytes := 0
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		sequence := 0
		for {
			select {
			case <-ctx.Done():
				sampler.done <- samples
				return
			default:
			}
			select {
			case <-ticker.C:
				sequence++
				for _, sample := range sampleResources(parent, rawURLs, fmt.Sprintf("sample-%06d", sequence)) {
					data, _ := json.Marshal(sample)
					samples, sizes = append(samples, sample), append(sizes, len(data))
					bytes += len(data)
					// Keep the most recent window within the coordinator's result-body
					// limit, leaving room for boundary samples and diagnostics.
					for bytes > 1<<20 && len(samples) > 0 {
						bytes -= sizes[0]
						samples, sizes = samples[1:], sizes[1:]
						sampler.dropped++
					}
				}
			case <-ctx.Done():
				sampler.done <- samples
				return
			}
		}
	}()
	return sampler
}

func (s *resourceSampler) Stop() []resourceSample {
	s.once.Do(func() {
		s.cancel()
		s.result = <-s.done
	})
	return append([]resourceSample(nil), s.result...)
}

func metricRole(identity string) string {
	for _, role := range []string{"control", "ingress", "relay"} {
		if strings.Contains(identity, role) {
			return role
		}
	}
	return "unknown"
}

func sampleMetrics(ctx context.Context, metricsURL string) (map[string]float64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metricsURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		return nil, err
	}
	body, readErr := io.ReadAll(io.LimitReader(response.Body, 2<<20))
	closeErr := response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", response.StatusCode)
	}
	if readErr != nil || closeErr != nil {
		return nil, errors.Join(readErr, closeErr)
	}
	return parseMetrics(string(body)), nil
}

func parseMetrics(body string) map[string]float64 {
	values := make(map[string]float64)
	for line := range strings.SplitSeq(body, "\n") {
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Labels can contain spaces (for example a matched HTTP route pattern).
		separator := strings.LastIndexByte(line, ' ')
		if separator < 0 {
			continue
		}
		value, err := strconv.ParseFloat(line[separator+1:], 64)
		if err == nil {
			values[line[:separator]] = value
		}
	}
	return values
}

type databaseDiagnostic struct {
	Identity  string                            `json:"identity"`
	Timestamp time.Time                         `json:"timestamp"`
	Snapshot  *controlstate.DatabaseDiagnostics `json:"snapshot,omitempty"`
	Error     string                            `json:"error,omitempty"`
}

func sampleDatabaseDiagnostics(parent context.Context, endpoints []string) []databaseDiagnostic {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), 5*time.Second)
	defer cancel()
	endpoints = endpoints[:min(len(endpoints), 8)]
	results := make([]databaseDiagnostic, len(endpoints))
	var workers sync.WaitGroup
	for index, endpoint := range endpoints {
		workers.Go(func() {
			diagnostic := databaseDiagnostic{Identity: endpoint, Timestamp: time.Now().UTC()}
			defer func() { results[index] = diagnostic }()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				diagnostic.Error = "invalid database diagnostics endpoint"
				return
			}
			response, err := http.DefaultClient.Do(request)
			if err != nil {
				diagnostic.Error = err.Error()
				return
			}
			defer response.Body.Close()
			if response.StatusCode != http.StatusOK {
				var problem struct {
					Error string `json:"error"`
				}
				_ = json.NewDecoder(io.LimitReader(response.Body, 4<<10)).Decode(&problem)
				diagnostic.Error = fmt.Sprintf("HTTP %d: %s", response.StatusCode, problem.Error)
				return
			}
			var snapshot controlstate.DatabaseDiagnostics
			if err := json.NewDecoder(io.LimitReader(response.Body, controlstate.MaxDatabaseDiagnosticBytes)).Decode(&snapshot); err != nil {
				diagnostic.Error = fmt.Sprintf("decode database diagnostics: %v", err)
				return
			}
			diagnostic.Snapshot = &snapshot
			diagnostic.Error = snapshot.Error
		})
	}
	workers.Wait()
	return results
}

func databaseDiagnosticURLs(metricsURLs []string) []string {
	var endpoints []string
	for _, endpoint := range metricsURLs {
		if strings.HasSuffix(endpoint, "/metrics#control") {
			endpoints = append(endpoints, strings.TrimSuffix(endpoint, "/metrics#control")+"/debug/database")
		}
	}
	return endpoints
}
