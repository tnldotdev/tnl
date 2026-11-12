package visitorfixture

import (
	"context"
	"crypto/ed25519"
	"errors"
	"sync/atomic"
	"time"

	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

type PolicyClient struct {
	Key      ed25519.PrivateKey
	Fail     atomic.Bool
	Calls    atomic.Int64
	Revision atomic.Int64
}

func (f *PolicyClient) ReadPublisherVisitorPolicy(_ context.Context, body controlv1.PublisherVisitorPolicyRequest, credential string) (controlv1.VisitorPolicyUpdate, error) {
	f.Calls.Add(1)
	if credential != "run-secret" {
		return controlv1.VisitorPolicyUpdate{}, errors.New("wrong run credential")
	}
	if f.Fail.Load() {
		return controlv1.VisitorPolicyUpdate{}, errors.New("control unavailable")
	}
	now := time.Now()
	revision := max(int64(1), f.Revision.Load())
	events := []int64{}
	if body.AfterRevision != 0 {
		for next := body.AfterRevision + 1; next <= revision; next++ {
			events = append(events, next)
		}
	}
	return controlv1.VisitorPolicyUpdate{AfterRevision: body.AfterRevision, Revisions: events, SnapshotRequired: body.AfterRevision == 0,
		VisitorSourceKey: SourceKeyBytes(),
		Policy: controlv1.VisitorPolicySnapshot{Resource: body.Resource, Hostname: "preview.example.test", Port: 443, Issuer: "https://control.example.test", VisitorPolicyRevision: revision, KeyRevision: 1,
			ObservedAt: now, ValidUntil: now.Add(10 * time.Second), Enabled: true, Anonymous: false, VerificationKeys: []controlv1.VisitorVerificationKey{{Id: "test-key", PublicKey: f.Key.Public().(ed25519.PublicKey)}}, WorkloadLeases: []controlv1.VisitorWorkloadLease{}}}, nil
}

type TokenClient struct {
	Issue func(context.Context, controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error)
	Calls atomic.Int64
}

func (f *TokenClient) IssueVisitorToken(ctx context.Context, body controlv1.VisitorTokenRequest) (controlv1.VisitorTokenResponse, error) {
	f.Calls.Add(1)
	return f.Issue(ctx, body)
}
