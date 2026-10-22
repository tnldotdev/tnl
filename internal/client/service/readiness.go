package publisherjob

import (
	"context"
	"errors"
	"time"

	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/publisher"
	clientruntime "github.com/tnldotdev/tnl/internal/publisher/app"
)

// VerifyPublicationReadiness proves that the current run carried a request to
// the HTTP target before reporting ready. a one-use proof bypasses visitor login
// for this check only; no operator credential or anonymous policy is needed.
func VerifyPublicationReadiness(ctx context.Context, cfg *publisher.Config, path string) {
	if path == "" {
		path = "/"
	}
	var proof *publisher.ReadinessProof
	var run publisher.PublishRunIdentity
	cfg.ReadinessProof = func(identity publisher.PublishRunIdentity) *publisher.ReadinessProof {
		run = identity
		proof, _ = publisher.NewReadinessProof(identity, path)
		return proof
	}
	observe := cfg.Observe
	cfg.Observe = func(event publisher.Event) error {
		if event.Type == publisher.EventReady {
			if proof == nil || event.PublishRunNumber != run.Number || event.PublicURLID != run.PublicURLID || event.PublicURL != "https://"+run.Hostname {
				return ErrScope
			}
			check, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			for {
				secret, err := proof.Renew()
				if err != nil {
					return err
				}
				observation := clientruntime.ProbeWithProof(check, clientruntime.Service{PublicURL: event.PublicURL, PublishRunNumber: run.Number, Readiness: clientruntime.Readiness{Path: path}}, nil, secret)
				// consumption is local evidence that this exact run, rather than an
				// older run or unrelated HTTP responder, accepted the proof.
				if observation.Ready && proof.HeaderValue() == "" {
					break
				}
				if err := wait(check, 250*time.Millisecond); err != nil {
					return failure.Wrap("verify public URL", failure.AppReadinessTimeout, errors.Join(err, context.Cause(check)))
				}
			}
		}
		if observe != nil {
			return observe(event)
		}
		return nil
	}
}
