package benchworkload

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	"github.com/tnldotdev/tnl/internal/security/credentials"
	"github.com/tnldotdev/tnl/internal/transport/tunnel"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

const publisherStartupHistoryLimit = 8

// startup observations select non-secret values before retaining anything.
// never retain whole control responses, credentials, or error text here.
type publisherStartupApproval struct {
	StartedAt          time.Time `json:"started_at"`
	FinishedAt         time.Time `json:"finished_at"`
	Completed          bool      `json:"completed"`
	Error              bool      `json:"error"`
	RequestedServiceID string    `json:"requested_service_id"`
	ServiceID          string    `json:"service_id"`
	EndpointRevision   int64     `json:"endpoint_revision"`
	Hostname           string    `json:"hostname"`
	Public             bool      `json:"public"`
}

type publisherStartupHealth struct {
	Healthy        bool  `json:"healthy"`
	StreamCapacity int32 `json:"stream_capacity"`
	ActiveStreams  int32 `json:"active_streams"`
}

type publisherStartupState struct {
	ServiceID           string                         `json:"service_id"`
	RunID               string                         `json:"service_run_id"`
	RunNumber           int64                          `json:"run_number"`
	State               controlv1.ServiceRunStateState `json:"state"`
	EndpointRevision    int64                          `json:"endpoint_revision"`
	PublicEndpointReady bool                           `json:"public_endpoint_ready"`
	HealthyPresent      bool                           `json:"healthy_present"`
	Healthy             bool                           `json:"healthy"`
	PublisherExpiresAt  time.Time                      `json:"publisher_expires_at"`
}

type publisherStartupHeartbeat struct {
	Sequence   uint64                 `json:"sequence"`
	ServiceID  string                 `json:"service_id"`
	RunID      string                 `json:"service_run_id"`
	StartedAt  time.Time              `json:"started_at"`
	FinishedAt time.Time              `json:"finished_at"`
	Completed  bool                   `json:"completed"`
	Error      bool                   `json:"error"`
	Request    publisherStartupHealth `json:"request"`
	Response   publisherStartupState  `json:"response"`
}

type publisherStartupReadiness struct {
	ObservedAt           time.Time           `json:"observed_at"`
	Ready                bool                `json:"ready"`
	TargetHealthy        bool                `json:"target_healthy"`
	ConfigurationCurrent bool                `json:"configuration_current"`
	LastCheck            time.Time           `json:"last_check"`
	LastSuccess          time.Time           `json:"last_success"`
	LeaseExpiresAt       time.Time           `json:"lease_expires_at"`
	Connected            [2]bool             `json:"connected"`
	Transports           [2]tunnel.Transport `json:"transports"`
	Draining             bool                `json:"draining"`
}

type publisherStartupSnapshot struct {
	CapturedAt      time.Time                   `json:"captured_at"`
	Approval        *publisherStartupApproval   `json:"approval"`
	HeartbeatCalls  uint64                      `json:"heartbeat_calls"`
	Heartbeats      []publisherStartupHeartbeat `json:"heartbeats"`
	ReadinessChecks uint64                      `json:"readiness_checks"`
	Readiness       []publisherStartupReadiness `json:"readiness"`
}

type publisherStartupTrace struct {
	mu      sync.Mutex
	stopped bool
	facts   publisherStartupSnapshot
}

func observePublisherStartup(config publisherservice.RunConfig, trace *publisherStartupTrace) publisherservice.RunConfig {
	config.Control = &publisherStartupControl{RunControl: config.Control, trace: trace}
	observe, ready := config.ObserveReadiness, config.Ready
	config.ObserveReadiness = func(status publisherservice.RunStatus) {
		trace.observeReadiness(status)
		if observe != nil {
			observe(status)
		}
	}
	config.Ready = func() error {
		if ready != nil {
			if err := ready(); err != nil {
				return err
			}
		}
		trace.mu.Lock()
		trace.stopped = true
		trace.mu.Unlock()
		return nil
	}
	return config
}

type publisherStartupControl struct {
	publisherservice.RunControl
	trace *publisherStartupTrace
}

func (c *publisherStartupControl) GetPublisherService(ctx context.Context, serviceID, access string) (controlv1.Service, error) {
	c.trace.mu.Lock()
	var approval *publisherStartupApproval
	if !c.trace.stopped {
		approval = &publisherStartupApproval{StartedAt: time.Now(), RequestedServiceID: serviceID}
		c.trace.facts.Approval = approval
	}
	c.trace.mu.Unlock()
	service, err := c.RunControl.GetPublisherService(ctx, serviceID, access)
	finished := time.Now()
	c.trace.mu.Lock()
	if approval != nil && !c.trace.stopped {
		approval.FinishedAt, approval.Completed, approval.Error = finished, true, err != nil
		approval.ServiceID = service.Id
		approval.EndpointRevision = service.EndpointRevision
		if service.Endpoint != nil {
			approval.Hostname, approval.Public = service.Endpoint.Hostname, service.Endpoint.Public
		}
	}
	c.trace.mu.Unlock()
	return service, err
}

func (c *publisherStartupControl) HeartbeatServiceRun(ctx context.Context, serviceID, runID string, token credentials.ServiceRunToken, health controlv1.ServiceRunHeartbeat) (controlv1.ServiceRunState, error) {
	c.trace.mu.Lock()
	var sequence uint64
	if !c.trace.stopped {
		c.trace.facts.HeartbeatCalls++
		sequence = c.trace.facts.HeartbeatCalls
		c.trace.facts.Heartbeats = appendPublisherStartupFact(c.trace.facts.Heartbeats, publisherStartupHeartbeat{
			Sequence: sequence, ServiceID: serviceID, RunID: runID, StartedAt: time.Now(),
			Request: publisherStartupHealth{Healthy: health.Healthy, StreamCapacity: health.StreamCapacity, ActiveStreams: health.ActiveStreams},
		})
	}
	c.trace.mu.Unlock()
	state, err := c.RunControl.HeartbeatServiceRun(ctx, serviceID, runID, token, health)
	finished := time.Now()
	c.trace.mu.Lock()
	if sequence != 0 && !c.trace.stopped {
		for index := range c.trace.facts.Heartbeats {
			observation := &c.trace.facts.Heartbeats[index]
			if observation.Sequence != sequence {
				continue
			}
			observation.FinishedAt, observation.Completed, observation.Error = finished, true, err != nil
			observation.Response = publisherStartupState{
				ServiceID: state.ServiceId, RunID: state.ServiceRunId, RunNumber: state.RunNumber,
				State: state.State, EndpointRevision: state.EndpointRevision, PublicEndpointReady: state.PublicEndpointReady,
				HealthyPresent: state.Healthy != nil, PublisherExpiresAt: state.PublisherExpiresAt,
			}
			if state.Healthy != nil {
				observation.Response.Healthy = *state.Healthy
			}
			break
		}
	}
	c.trace.mu.Unlock()
	return state, err
}

func (t *publisherStartupTrace) observeReadiness(status publisherservice.RunStatus) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped {
		return
	}
	t.facts.ReadinessChecks++
	t.facts.Readiness = appendPublisherStartupFact(t.facts.Readiness, publisherStartupReadiness{
		ObservedAt: time.Now(), Ready: status.Ready, TargetHealthy: status.TargetHealthy, ConfigurationCurrent: status.ConfigurationCurrent,
		LastCheck: status.LastCheck, LastSuccess: status.LastSuccess, LeaseExpiresAt: status.LeaseExpiresAt,
		Connected: status.Connected, Transports: status.Transports, Draining: status.Draining,
	})
}

func appendPublisherStartupFact[T any](history []T, fact T) []T {
	if len(history) == publisherStartupHistoryLimit {
		copy(history, history[1:])
		history[len(history)-1] = fact
		return history
	}
	return append(history, fact)
}

// freeze at activation failure, before group cancellation can change the facts.
// formatting is failure-only; successful startups never serialize observations.
func (t *publisherStartupTrace) failureJSON() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.stopped = true
	t.facts.CapturedAt = time.Now()
	data, err := json.Marshal(t.facts)
	if err != nil {
		return []byte(`{"encoding_failed":true}`)
	}
	return data
}
