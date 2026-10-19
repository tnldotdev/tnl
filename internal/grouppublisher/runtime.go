package grouppublisher

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/tnldotdev/tnl/internal/controlclient"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/observability"
	"github.com/tnldotdev/tnl/internal/privatepublisher"
	"github.com/tnldotdev/tnl/internal/publisherruntime"
	"github.com/tnldotdev/tnl/pkg/api/controlv1"
)

var ErrAssignment = errors.New("publisher group assignment does not match the enrolled project, group or revision")

type Control interface {
	publisherruntime.Control
	ServerURL() string
	Assignments(context.Context, string) (controlv1.PublisherGroupAssignments, error)
	Acknowledge(context.Context, string, controlv1.PublisherGroupAcknowledgement) error
}

type Runtime struct {
	Control       Control
	Member        controlv1.PublisherGroupMember
	Private       ed25519.PrivateKey
	Publish       func(context.Context, controlv1.PublisherGroupServiceAssignment, func(bool)) error
	Observe       func(int64, bool) error
	MemberChanged func(controlv1.PublisherGroupMember) error
	PollInterval  time.Duration
	Deployment    *controlv1.PublisherDeploymentReport
}

func (Runtime) String() string   { return "publisher group runtime" }
func (Runtime) GoString() string { return "publisher group runtime" }

type running struct {
	definition string
	cancel     context.CancelFunc
	done       chan struct{}
	healthy    bool
	lease      *time.Timer
	err        error
}

// Serve fences replaced workers before starting their replacements. losing the
// group lease stops all assignments; a polling failure never extends that lease.
func (r Runtime) Serve(ctx context.Context) error {
	if r.Control == nil || r.Publish == nil || len(r.Private) != ed25519.PrivateKeySize || r.Member.GroupId == "" {
		return ErrAssignment
	}
	if r.PollInterval == 0 {
		r.PollInterval = 5 * time.Second
	}
	if r.PollInterval < time.Millisecond || r.PollInterval > time.Minute {
		return ErrAssignment
	}
	workers := map[string]*running{}
	owner, err := publisherruntime.New(r.Control, r.Control.ServerURL(), r.Member.PublisherIdentityId, r.Member.KeyId, r.Member.GroupId, r.Private, r.Deployment)
	if err != nil {
		return err
	}
	defer func() {
		finish, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = owner.Stop(finish)
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
	var lease controlv1.PublisherGroupLease
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
			var next controlv1.PublisherGroupLease
			if response.GroupLease != nil {
				next = *response.GroupLease
			}
			if err != nil && !temporary(err) && ctx.Err() == nil {
				return err
			}
			if err == nil && (next.AccessToken == "" || !next.ExpiresAt.After(time.Now())) {
				return ErrAssignment
			}
			if err == nil && next.AccessToken != "" && next.ExpiresAt.After(time.Now()) {
				lease = next
				ctx = observability.WithIdentity(ctx, observability.Identity{TeamID: r.Member.TeamId, GroupID: r.Member.GroupId, PublisherID: r.Member.PublisherIdentityId})
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
			assignment, err := r.Control.Assignments(ctx, lease.AccessToken)
			if errors.Is(err, controlclient.ErrUnauthenticated) {
				stop()
				lease = controlv1.PublisherGroupLease{}
				if err := observe(revision, false); err != nil {
					return err
				}
			} else if err != nil && !temporary(err) && ctx.Err() == nil {
				return err
			}
			if err == nil {
				currentMember := assignment.Member
				currentMember.GroupName = r.Member.GroupName
				if currentMember != r.Member || assignment.Revision < revision || assignment.Revision < 1 || len(assignment.ConfigurationHash) != 64 || assignment.Revision == revision && assignment.ConfigurationHash != configurationHash {
					return ErrAssignment
				}
				if r.Member.GroupName != assignment.Member.GroupName || revision == 0 {
					if r.MemberChanged != nil {
						if err := r.MemberChanged(assignment.Member); err != nil {
							return err
						}
					}
				}
				r.Member.GroupName = assignment.Member.GroupName
				definitions := map[string]string{}
				for _, service := range assignment.Services {
					if service.Service == "" || service.ServiceId == "" || service.GrantId == "" || service.Configuration.Publisher == nil || *service.Configuration.Publisher != r.Member.GroupName || definitions[service.Service] != "" {
						return ErrAssignment
					}
					// the selector is descriptive; changing it must not restart an
					// unchanged publication or replace its certificate and connections.
					definition := service
					definition.Configuration.Publisher = nil
					data, err := json.Marshal(definition)
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
					workerCtx, cancel := context.WithCancel(observability.WithIdentity(ctx, observability.Identity{ServiceID: service.ServiceId}))
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
				err = r.Control.Acknowledge(ctx, lease.AccessToken, controlv1.PublisherGroupAcknowledgement{Revision: revision, ConfigurationHash: assignment.ConfigurationHash, Healthy: healthy})
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
	// an apply or namespace rename can revoke a service grant just after a
	// successful poll. refresh assignments rather than killing the group task;
	// revoked group membership still fails at the lease/assignment boundary.
	if temporary(err) || errors.Is(err, privatepublisher.ErrPrivateStream) || errors.Is(err, controlclient.ErrStatusConflict) || errors.Is(err, controlclient.ErrUnauthenticated) {
		return true
	}
	var network net.Error
	return errors.As(err, &network)
}

func temporary(err error) bool {
	if errors.Is(err, controlclient.ErrUnavailable) || errors.Is(err, controlclient.ErrRateLimited) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	reason, _ := failure.ReasonOf(err)
	return reason == failure.ServerUnavailable || reason == failure.ServerRateLimited
}
