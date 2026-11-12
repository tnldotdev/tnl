package group

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	publisherruntime "github.com/tnldotdev/tnl/internal/publisher/runtime"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrAssignment = errors.New("publisher assignment does not match the enrolled environment or revision")

type Control interface {
	publisherruntime.Control
	ServerURL() string
	Assignments(context.Context, string) (controlv1.EnvironmentPublisherAssignments, error)
	Acknowledge(context.Context, string, controlv1.EnvironmentPublisherAcknowledgement) error
}

type Runtime struct {
	Control      Control
	Publisher    controlv1.EnvironmentPublisher
	Private      ed25519.PrivateKey
	Publish      func(context.Context, controlv1.EnvironmentPublication, controlv1.EnvironmentPublisherAssignment, func(bool)) error
	Observe      func(int64, bool) error
	PollInterval time.Duration
	Deployment   *controlv1.PublisherDeploymentReport
}

func (Runtime) String() string   { return "environment publisher runtime" }
func (Runtime) GoString() string { return "environment publisher runtime" }

type running struct {
	definition string
	cancel     context.CancelFunc
	done       chan struct{}
	healthy    bool
	lease      *time.Timer
	err        error
}

// serve fences replaced workers before starting their replacements. losing the
// environment lease stops assignments; a polling failure never extends that lease.
func (r Runtime) Serve(ctx context.Context) (retErr error) {
	defer func() {
		if cause := context.Cause(ctx); cause != nil && !failure.Only(cause, context.Canceled) {
			retErr = errors.Join(retErr, cause)
		}
	}()
	if r.Control == nil || r.Publish == nil || len(r.Private) != ed25519.PrivateKeySize || r.Publisher.EnvironmentId == "" {
		return ErrAssignment
	}
	if r.PollInterval == 0 {
		r.PollInterval = 5 * time.Second
	}
	if r.PollInterval < time.Millisecond || r.PollInterval > time.Minute {
		return ErrAssignment
	}
	workers := map[string]*running{}
	owner, err := publisherruntime.New(r.Control, r.Control.ServerURL(), r.Publisher.PublisherIdentityId, r.Publisher.KeyId, r.Publisher.EnvironmentId, r.Private, r.Deployment)
	if err != nil {
		return err
	}
	defer func() {
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		finish, end := observability.PublisherOperation(observability.Independent(finish), "group_shutdown")
		err := owner.Stop(finish)
		end(err)
		retErr = errors.Join(retErr, err)
	}()
	var mu sync.Mutex
	stop := func() error {
		for _, w := range workers {
			w.lease.Stop()
			w.cancel()
		}
		var result error
		for _, w := range workers {
			<-w.done
			result = errors.Join(result, w.err)
		}
		clear(workers)
		return result
	}
	defer func() { retErr = errors.Join(retErr, stop()) }()
	var lease controlv1.EnvironmentPublisherLease
	var revision int64
	var configurationHash string
	var observed bool
	var observedRevision int64
	var observedHealthy bool
	observe := func(revision int64, healthy bool) error {
		if observed && observedRevision == revision && observedHealthy == healthy {
			return nil
		}
		if r.Observe != nil {
			if err := r.Observe(revision, healthy); err != nil {
				return err
			}
		}
		observed, observedRevision, observedHealthy = true, revision, healthy
		return nil
	}
	for ctx.Err() == nil {
		if time.Until(lease.ExpiresAt) <= 2*r.PollInterval {
			leaseCtx, finish := observability.PublisherOperation(ctx, "group_lease")
			response, err := owner.Renew(leaseCtx)
			finish(err)
			if err != nil && ctx.Err() != nil {
				if failure.Only(err, ctx.Err()) {
					return nil
				}
				return err
			}
			var next controlv1.EnvironmentPublisherLease
			if response.EnvironmentLease != nil {
				next = *response.EnvironmentLease
			}
			if err != nil && !temporary(err) && ctx.Err() == nil {
				return err
			}
			if err == nil && (next.AccessToken == "" || !next.ExpiresAt.After(time.Now())) {
				return ErrAssignment
			}
			if err == nil && next.AccessToken != "" && next.ExpiresAt.After(time.Now()) {
				lease = next
				ctx = owner.ObservabilityContext(ctx, r.Publisher.TeamId, r.Publisher.EnvironmentId)
				observability.PublisherLease(ctx, lease.ExpiresAt)
				for _, w := range workers {
					w.lease.Reset(time.Until(lease.ExpiresAt))
				}
			} else if !lease.ExpiresAt.After(time.Now()) {
				if err := stop(); err != nil {
					return err
				}
				if err := observe(revision, false); err != nil {
					return err
				}
			}
		}
		if lease.ExpiresAt.After(time.Now()) {
			pollCtx, cancelPoll := context.WithDeadline(ctx, minTime(lease.ExpiresAt, time.Now().Add(10*time.Second)))
			poll, finishPoll := observability.PublisherOperation(pollCtx, "group_assignments")
			assignment, err := r.Control.Assignments(poll, lease.AccessToken)
			finishPoll(err)
			cancelPoll()
			if err != nil && ctx.Err() != nil {
				if failure.Only(err, ctx.Err()) {
					return nil
				}
				return err
			}
			if failure.Only(err, clientcontrol.ErrUnauthenticated) {
				if err := stop(); err != nil {
					return err
				}
				lease = controlv1.EnvironmentPublisherLease{}
				if err := observe(revision, false); err != nil {
					return err
				}
			} else if err != nil && !temporary(err) && ctx.Err() == nil {
				return err
			}
			if err == nil {
				if ctx.Err() != nil {
					return nil
				}
				if !lease.ExpiresAt.After(time.Now()) {
					if err := stop(); err != nil {
						return err
					}
					if err := observe(revision, false); err != nil {
						return err
					}
					continue
				}
				publication := assignment.Environment
				hash, hashErr := hex.DecodeString(publication.ConfigurationHash)
				if assignment.Publisher != r.Publisher || publication.EnvironmentId != r.Publisher.EnvironmentId || publication.MutationRevision < revision || publication.MutationRevision < 1 || len(hash) != 32 || hashErr != nil || hex.EncodeToString(hash) != publication.ConfigurationHash || publication.MutationRevision == revision && publication.ConfigurationHash != configurationHash || len(assignment.Services) > 128 {
					return ErrAssignment
				}
				definitions := map[string]string{}
				ids := map[string]bool{}
				for _, service := range assignment.Services {
					if service.Service == "" || service.ServiceId == "" || service.GrantId == "" || !service.Configuration.Protocol.Valid() || service.TrustRevision < 1 || definitions[service.Service] != "" || ids[service.ServiceId] {
						return ErrAssignment
					}
					ids[service.ServiceId] = true
					// an unchanged running service keeps its connections. a newly
					// started worker receives the exact current envelope explicitly.
					data, err := json.Marshal(service)
					if err != nil {
						return err
					}
					definitions[service.Service] = string(data)
				}
				for name, w := range workers {
					if definitions[name] != w.definition {
						w.lease.Stop()
						w.cancel()
					}
				}
				for name, w := range workers {
					if definitions[name] != w.definition {
						<-w.done
						delete(workers, name)
						if w.err != nil && !retryablePublication(w.err) {
							return w.err
						}
						continue
					}
					select {
					case <-w.done:
						w.lease.Stop()
						w.cancel()
						delete(workers, name)
						if w.err != nil && !retryablePublication(w.err) {
							return w.err
						}
					default:
					}
				}
				for _, service := range assignment.Services {
					if workers[service.Service] != nil {
						continue
					}
					workerCtx, cancel := context.WithCancel(observability.Independent(observability.NarrowIdentity(ctx, observability.Identity{ServiceID: service.ServiceId})))
					w := &running{definition: definitions[service.Service], cancel: cancel, done: make(chan struct{})}
					w.lease = time.AfterFunc(time.Until(lease.ExpiresAt), cancel)
					workers[service.Service] = w
					go func() {
						defer close(w.done)
						w.err = r.Publish(workerCtx, publication, service, func(healthy bool) { mu.Lock(); w.healthy = healthy; mu.Unlock() })
						if workerCtx.Err() != nil && failure.Only(w.err, workerCtx.Err()) {
							w.err = nil
						}
						mu.Lock()
						w.healthy = false
						mu.Unlock()
					}()
				}
				revision = publication.MutationRevision
				configurationHash = publication.ConfigurationHash
				healthy := true
				mu.Lock()
				for _, w := range workers {
					healthy = healthy && w.healthy
				}
				mu.Unlock()
				ackCtx, cancelAck := context.WithDeadline(ctx, minTime(lease.ExpiresAt, time.Now().Add(10*time.Second)))
				ack, finishAck := observability.PublisherOperation(ackCtx, "group_acknowledge")
				err = r.Control.Acknowledge(ack, lease.AccessToken, controlv1.EnvironmentPublisherAcknowledgement{Environment: publication, Healthy: healthy})
				finishAck(err)
				cancelAck()
				if err != nil && ctx.Err() != nil {
					if failure.Only(err, ctx.Err()) {
						return nil
					}
					return err
				}
				if err != nil && !temporary(err) && !failure.Only(err, clientcontrol.ErrStatusConflict) && !failure.Only(err, clientcontrol.ErrUnauthenticated) {
					return err
				}
				if err == nil {
					if err := observe(revision, healthy); err != nil {
						return err
					}
				}
			}
		}
		timer := time.NewTimer(r.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
	return nil
}

func minTime(first, second time.Time) time.Time {
	if first.Before(second) {
		return first
	}
	return second
}

func retryablePublication(err error) bool {
	if !joinedPublicationCauses(err, retryablePublication) {
		return false
	}
	var discovery *publisherdiscovery.Error
	if errors.As(err, &discovery) {
		return temporary(discovery)
	}
	// an apply or namespace rename can revoke a service grant just after a
	// successful poll. refresh assignments rather than killing the group task;
	// revoked group membership still fails at the lease/assignment boundary.
	if temporary(err) || errors.Is(err, publisherservice.ErrPrivateStream) || errors.Is(err, clientcontrol.ErrStatusConflict) || errors.Is(err, clientcontrol.ErrUnauthenticated) {
		return true
	}
	var network net.Error
	return errors.As(err, &network)
}

func temporary(err error) bool {
	if !joinedPublicationCauses(err, temporary) {
		return false
	}
	var discovery *publisherdiscovery.Error
	if errors.As(err, &discovery) {
		switch discovery.Kind {
		case publisherdiscovery.Unavailable, publisherdiscovery.Stale, publisherdiscovery.NotReady:
			return true
		default:
			return false
		}
	}
	if errors.Is(err, clientcontrol.ErrUnavailable) || errors.Is(err, clientcontrol.ErrRateLimited) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	reason, _ := failure.ReasonOf(err)
	return reason == failure.ServerUnavailable || reason == failure.ServerRateLimited
}

// each joined branch is an independent failure. a retryable operation must not
// hide cleanup failures beside it, even beneath a diagnostic or fmt wrapper.
func joinedPublicationCauses(err error, retryable func(error) bool) bool {
	for err != nil {
		if joined, ok := err.(interface{ Unwrap() []error }); ok {
			for _, cause := range joined.Unwrap() {
				if cause != nil && !failure.Only(cause, context.Canceled) && !retryable(cause) {
					return false
				}
			}
			return true
		}
		err = errors.Unwrap(err)
	}
	return true
}
