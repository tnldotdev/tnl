package clientruntime

import (
	"context"
	"net/http"
	"time"

	"github.com/tnldotdev/tnl/internal/localproxy"
)

const ProbeHeader = localproxy.ReadinessProbeHeader
const DiagnosticHeader = "Tnl-Error-Code"

type Readiness struct {
	Path   string `json:"path"`
	Status int    `json:"status,omitempty"`
}

type Observation struct {
	RegistrationID   string    `json:"registration_id"`
	PublishRunNumber uint64    `json:"publish_run_number"`
	CheckedAt        time.Time `json:"checked_at"`
	Status           int       `json:"status,omitempty"`
	Ready            bool      `json:"ready"`
	Reason           string    `json:"reason,omitempty"`
	Readiness        Readiness `json:"readiness"`
}

// probe reads headers only; redirects, streaming bodies, and app credentials are
// deliberately outside the readiness boundary. the default transport uses DNS
// and WebPKI exactly as a visitor would.
func Probe(ctx context.Context, service Service, transport http.RoundTripper) Observation {
	observation := Observation{RegistrationID: service.RegistrationID, PublishRunNumber: service.PublishRunNumber, CheckedAt: time.Now().UTC(), Readiness: service.Readiness}
	path := service.Readiness.Path
	if path == "" {
		path = "/"
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, service.PublicURL+path, nil)
	if err != nil {
		observation.Reason = "runtime.probe_failed"
		return observation
	}
	request.Header.Set(ProbeHeader, "1")
	request.Header.Set("User-Agent", "tnl-readiness/1")
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(request)
	if err != nil {
		observation.Reason = "runtime.probe_failed"
		return observation
	}
	defer response.Body.Close()
	observation.Status = response.StatusCode
	observation.Ready = response.Header.Get(DiagnosticHeader) == "" && response.StatusCode >= 200 && response.StatusCode <= 499 && response.StatusCode != 408 && response.StatusCode != 429
	if service.Readiness.Status != 0 {
		observation.Ready = observation.Ready && response.StatusCode == service.Readiness.Status
	}
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
