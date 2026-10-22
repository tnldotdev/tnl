package app

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/observability"
	publisherproxy "github.com/tnldotdev/tnl/internal/publisher/proxy"
)

const ProbeHeader = publisherproxy.ReadinessProbeHeader
const DiagnosticHeader = "Tnl-Error-Code"

type Readiness struct {
	Path string `json:"path"`
}

type Observation struct {
	Target         string    `json:"-"`
	RegistrationID string    `json:"registration_id"`
	RunNumber      uint64    `json:"run_number"`
	CheckedAt      time.Time `json:"checked_at"`
	Status         int       `json:"status,omitempty"`
	Ready          bool      `json:"ready"`
	Reason         string    `json:"reason,omitempty"`
	Readiness      Readiness `json:"readiness"`
}

// probe reads headers only; redirects, streaming bodies, and app credentials are
// deliberately outside the readiness boundary. the default transport uses DNS
// and WebPKI exactly as a visitor would.
func Probe(ctx context.Context, service Service, transport http.RoundTripper) Observation {
	return ProbeWithProof(ctx, service, transport, "")
}

func ProbeWithProof(ctx context.Context, service Service, transport http.RoundTripper, proof string) (observation Observation) {
	ctx, finish := observability.PublisherOperation(ctx, "readiness_probe")
	var probeErr error
	defer func() {
		var err error
		if !observation.Ready {
			err = errors.New("readiness check failed")
			if probeErr != nil {
				err = probeErr
			}
			if ctx.Err() != nil {
				err = ctx.Err()
			}
		}
		finish(err)
		observability.PublisherReadiness(ctx, observation.Ready)
	}()
	observation = Observation{Target: service.Target, RegistrationID: service.RegistrationID, RunNumber: service.RunNumber, CheckedAt: time.Now().UTC(), Readiness: service.Readiness}
	path := service.Readiness.Path
	if path == "" {
		path = "/"
	}
	probeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, service.PublicURL+path, nil)
	if err != nil {
		observation.Reason = "runtime.probe_failed"
		return observation
	}
	if proof != "" {
		request.Header.Set(ProbeHeader, proof)
	}
	request.Header.Set("User-Agent", "tnl-readiness/1")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		probeErr = err
		observation.Reason = "runtime.probe_failed"
		return observation
	}
	defer response.Body.Close()
	observation.Status = response.StatusCode
	observation.Ready = response.Header.Get(DiagnosticHeader) == "" && response.StatusCode >= 200 && response.StatusCode < 300
	if !observation.Ready {
		observation.Reason = "runtime.probe_rejected"
	}
	return observation
}

func RetryDelay(attempt int) time.Duration {
	if attempt <= 0 {
		return 500 * time.Millisecond
	}
	if attempt == 1 {
		return time.Second
	}
	return 2 * time.Second
}
