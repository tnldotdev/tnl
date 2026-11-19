package session

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tnldotdev/tnl/internal/client/auth"
	clientauthority "github.com/tnldotdev/tnl/internal/client/authority"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/naming"
	"github.com/tnldotdev/tnl/internal/naming/opaqueid"
)

type WorkloadOptions struct {
	Name              string `json:"name"`
	SourceFingerprint string `json:"sourceFingerprint"`
}

var fingerprint = regexp.MustCompile(`^[0-9a-f]{64}$`)

// NewWorkloadDeployment exchanges a callback-provided assertion with control.
// the connector owner must join MaintainWorkload before closing the session.
func NewWorkloadDeployment(ctx context.Context, request DeploymentOptions, options WorkloadOptions, acquire func(context.Context) (string, error), httpClient *http.Client) (*Deployment, error) {
	team, project, ok := strings.Cut(request.Project, "/")
	if request.Deployment == "" {
		request.Deployment = request.Name
	}
	if !ok || team == "" || project == "" || strings.Contains(project, "/") ||
		len(team) > 128 || len(project) > 128 || !fingerprint.MatchString(options.SourceFingerprint) ||
		!naming.ValidServiceName(options.Name) || request.Credential != "" ||
		request.Deployment == "local" || !(naming.ValidServiceName(request.Deployment) || opaqueid.Valid(request.Deployment, "dpl_")) ||
		request.Name != "" && request.Deployment != request.Name || len(request.Services) == 0 || len(request.Services) > 32 {
		return nil, auth.ErrDeploymentCredential
	}
	request.Services = slices.Clone(request.Services)
	slices.Sort(request.Services)
	for i, name := range request.Services {
		if !naming.ValidServiceName(name) || i > 0 && request.Services[i-1] == name {
			return nil, auth.ErrDeploymentCredential
		}
	}
	server := request.ControlURL
	if server == "" {
		server = naming.DefaultControlURL
	}
	client, err := workload.New(server, httpClient)
	if err != nil {
		return nil, err
	}
	assertion, err := workload.AcquireAssertion(ctx, acquire)
	if err != nil {
		return nil, err
	}
	if _, err := client.Exchange(ctx, team, project, options.SourceFingerprint, options.Name, assertion, request.Services); err != nil {
		return nil, err
	}
	return &Deployment{request: request, workload: client}, nil
}

// MaintainWorkload renews the lease and reacquires proof before the verified
// identity expires. a failed refresh never buys time past the last lease.
func (d *Deployment) MaintainWorkload(ctx context.Context, acquire func(context.Context) (string, error)) error {
	if d.workload == nil {
		return nil
	}
	var backoff time.Time
	for {
		current, err := d.workload.Session()
		if err != nil {
			return err
		}
		until := earlier(current.LeaseExpiresAt, workload.SessionDeadline(current))
		now := time.Now()
		if !until.After(now) {
			return workload.ErrSessionExpired
		}
		// refresh before renewing when both are due, so a new lease can
		// advance beyond the old proof without waiting another lease period.
		proofAt := current.IdentityExpiresAt.Add(-10 * time.Second)
		if current.ExpiresAt != nil && !current.ExpiresAt.After(current.IdentityExpiresAt) {
			proofAt = *current.ExpiresAt
		}
		due := earlier(current.RenewAfter, proofAt)
		if backoff.After(due) {
			due = backoff
		}
		due = earlier(until, due)
		timer := time.NewTimer(time.Until(due))
		select {
		case <-ctx.Done():
			timer.Stop()
			return context.Cause(ctx)
		case <-timer.C:
		}
		if !until.After(time.Now()) {
			return workload.ErrSessionExpired
		}
		call, cancel := context.WithDeadline(ctx, earlier(until, time.Now().Add(10*time.Second)))
		if !time.Now().Before(proofAt) {
			assertion, acquireErr := workload.AcquireAssertion(call, acquire)
			if acquireErr == nil {
				next, attachErr := d.workload.Attach(call, assertion)
				if errors.Is(attachErr, workload.ErrSessionExpired) {
					cancel()
					return attachErr
				}
				if attachErr != nil || !next.IdentityExpiresAt.After(current.IdentityExpiresAt) {
					backoff = time.Now().Add(2 * time.Second)
				}
			} else {
				backoff = time.Now().Add(2 * time.Second)
			}
		}
		if !time.Now().Before(current.RenewAfter) {
			if _, err := d.workload.Renew(call); err != nil {
				var problem *clientauthority.ProblemError
				if errors.As(err, &problem) && (problem.Status == http.StatusForbidden || problem.Status == http.StatusGone) {
					cancel()
					return err
				}
				backoff = time.Now().Add(2 * time.Second)
			}
		}
		cancel()
	}
}

func earlier(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (d *Deployment) CloseWorkload(ctx context.Context) error {
	if d.workload == nil {
		return nil
	}
	return d.workload.Revoke(ctx)
}
