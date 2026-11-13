package deployment

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	clientcontrol "github.com/tnldotdev/tnl/internal/client/control"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	processidentity "github.com/tnldotdev/tnl/internal/publisher/processidentity"
	publisherservice "github.com/tnldotdev/tnl/internal/publisher/service"
	publisherdiscovery "github.com/tnldotdev/tnl/internal/publisher/target/discovery"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

var ErrAssignment = errors.New("deployment assignment does not match the enrolled project, deployment or revision")

type Control interface {
	processidentity.Control
	ServerURL() string
	Assignments(context.Context, string) (controlv1.DeploymentPublisherAssignments, error)
	Acknowledge(context.Context, string, controlv1.DeploymentPublisherAcknowledgement) error
}

type Runtime struct {
	Control       Control
	Member        controlv1.DeploymentPublisherIdentity
	Private       ed25519.PrivateKey
	Publish       func(context.Context, controlv1.DeploymentPublisherServiceAssignment, func(bool)) error
	Observe       func(int64, bool) error
	MemberChanged func(controlv1.DeploymentPublisherIdentity) error
	PollInterval  time.Duration
	Deployment    *controlv1.PublisherDeploymentReport
}

func (Runtime) String() string   { return "deployment runtime" }
func (Runtime) GoString() string { return "deployment runtime" }

type running struct {
	definition string
	cancel     context.CancelFunc
	done       chan struct{}
	healthy    bool
	lease      *time.Timer
	err        error
}

// Serve fences replaced workers before starting their replacements. losing the
// deployment lease stops all assignments; a polling failure never extends that lease.
func (r Runtime) Serve(ctx context.Context) error {
	if r.Control == nil || r.Publish == nil || len(r.Private) != ed25519.PrivateKeySize || r.Member.DeploymentId == "" {
		return ErrAssignment
	}
	if r.PollInterval == 0 {
		r.PollInterval = 5 * time.Second
	}
	if r.PollInterval < time.Millisecond || r.PollInterval > time.Minute {
		return ErrAssignment
	}
	workers := map[string]*running{}
	owner, err := processidentity.New(r.Control, r.Control.ServerURL(), r.Member.PublisherIdentityId, r.Member.KeyId, r.Member.DeploymentId, r.Private, r.Deployment)
	if err != nil {
		return err
	}
	defer func() {
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		finish, end := observability.PublisherOperation(observability.Independent(finish), "deployment_shutdown")
		end(owner.Stop(finish))
	}()
	var mu sync.Mutex
	stop := func() {
		for _, w := range workers {
			w.lease.Stop()
			w.cancel()
		}
		for _, w := range workers {
			<-w.done
		}
		clear(workers)
	}
	defer stop()
	var lease controlv1.DeploymentPublisherLease
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
			leaseCtx, finish := observability.PublisherOperation(ctx, "deployment_lease")
			response, err := owner.Renew(leaseCtx)
			finish(err)
			var next controlv1.DeploymentPublisherLease
			if response.DeploymentLease != nil {
				next = *response.DeploymentLease
			}
			if err != nil && !temporary(err) && ctx.Err() == nil {
				return err
			}
			if err == nil && (next.AccessToken == "" || !next.ExpiresAt.After(time.Now())) {
				return ErrAssignment
			}
			if err == nil && next.AccessToken != "" && next.ExpiresAt.After(time.Now()) {
				lease = next
				ctx = owner.ObservabilityContext(ctx, r.Member.TeamId, r.Member.DeploymentId)
				observability.PublisherLease(ctx, lease.ExpiresAt)
				for _, w := range workers {
					w.lease.Reset(time.Until(lease.ExpiresAt))
				}
			} else if !lease.ExpiresAt.After(time.Now()) {
				stop()
				if err := observe(revision, false); err != nil {
					return err
				}
			}
		}
		if lease.ExpiresAt.After(time.Now()) {
			poll, finishPoll := observability.PublisherOperation(ctx, "deployment_assignments")
			assignment, err := r.Control.Assignments(poll, lease.AccessToken)
			finishPoll(err)
			if errors.Is(err, clientcontrol.ErrUnauthenticated) {
				stop()
				lease = controlv1.DeploymentPublisherLease{}
				if err := observe(revision, false); err != nil {
					return err
				}
			} else if err != nil && !temporary(err) && ctx.Err() == nil {
				return err
			}
			if err == nil {
				currentMember := assignment.Member
				currentMember.DeploymentName = r.Member.DeploymentName
				if currentMember != r.Member || assignment.Revision < revision || assignment.Revision < 1 || len(assignment.ConfigurationHash) != 64 || assignment.Revision == revision && assignment.ConfigurationHash != configurationHash {
					return ErrAssignment
				}
				if r.Member.DeploymentName != assignment.Member.DeploymentName || revision == 0 {
					if r.MemberChanged != nil {
						if err := r.MemberChanged(assignment.Member); err != nil {
							return err
						}
					}
				}
				r.Member.DeploymentName = assignment.Member.DeploymentName
				definitions := map[string]string{}
				for _, service := range assignment.Services {
					if service.Service == "" || service.ServiceId == "" || service.GrantId == "" || definitions[service.Service] != "" {
						return ErrAssignment
					}
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
						<-w.done
						delete(workers, name)
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
					workerCtx, cancel := context.WithCancel(observability.Independent(observability.NarrowIdentity(poll, observability.Identity{ServiceID: service.ServiceId})))
					w := &running{definition: definitions[service.Service], cancel: cancel, done: make(chan struct{})}
					w.lease = time.AfterFunc(time.Until(lease.ExpiresAt), cancel)
					workers[service.Service] = w
					go func() {
						defer close(w.done)
						w.err = r.Publish(workerCtx, service, func(healthy bool) { mu.Lock(); w.healthy = healthy; mu.Unlock() })
						if workerCtx.Err() != nil {
							w.err = nil
						}
						mu.Lock()
						w.healthy = false
						mu.Unlock()
					}()
				}
				revision = assignment.Revision
				configurationHash = assignment.ConfigurationHash
				healthy := true
				mu.Lock()
				for _, w := range workers {
					healthy = healthy && w.healthy
				}
				mu.Unlock()
				ack, finishAck := observability.PublisherOperation(ctx, "deployment_acknowledge")
				err = r.Control.Acknowledge(ack, lease.AccessToken, controlv1.DeploymentPublisherAcknowledgement{Revision: revision, ConfigurationHash: assignment.ConfigurationHash, Healthy: healthy})
				finishAck(err)
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

func retryablePublication(err error) bool {
	var discovery *publisherdiscovery.Error
	if errors.As(err, &discovery) {
		return temporary(err)
	}
	// an apply or namespace rename can revoke a service grant just after a
	// successful poll. refresh assignments rather than killing the deployment task;
	// revoked deployment membership still fails at the lease/assignment boundary.
	if temporary(err) || errors.Is(err, publisherservice.ErrPrivateStream) || errors.Is(err, clientcontrol.ErrStatusConflict) || errors.Is(err, clientcontrol.ErrUnauthenticated) {
		return true
	}
	var network net.Error
	return errors.As(err, &network)
}

func temporary(err error) bool {
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
