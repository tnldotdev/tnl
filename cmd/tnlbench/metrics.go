package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
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
	cancel context.CancelFunc
	done   chan []resourceSample
	once   sync.Once
	result []resourceSample
}

func startResourceSampler(parent context.Context, rawURLs []string, interval time.Duration) *resourceSampler {
	ctx, cancel := context.WithCancel(parent)
	sampler := &resourceSampler{cancel: cancel, done: make(chan []resourceSample, 1)}
	go func() {
		var samples []resourceSample
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
				samples = append(samples, sampleResources(parent, rawURLs, fmt.Sprintf("load-%06d", sequence))...)
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
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err == nil {
			values[fields[0]] = value
		}
	}
	return values
}
