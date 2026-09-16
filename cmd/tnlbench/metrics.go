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
	"time"
)

func sampleResources(ctx context.Context, rawURLs []string, moment string) []resourceSample {
	result := make([]resourceSample, 0, len(rawURLs))
	for _, rawURL := range rawURLs {
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
		result = append(result, sample)
	}
	return result
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
