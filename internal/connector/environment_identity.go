package connector

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"reflect"
	"time"

	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	"github.com/tnldotdev/tnl/internal/failure"
	"github.com/tnldotdev/tnl/internal/security/machineproof"
	"github.com/tnldotdev/tnl/internal/security/publisherproof"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

func (b *connectorConnectionBackend) sourceSelection() (authorityv1.IdentitySourceVisitorSelection, *workload.Client, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	selection := b.scope.Environment
	if b.closed || selection == nil || selection.Validate() != nil || b.workload == nil || !machineproof.ValidSource(b.environmentSource) {
		return authorityv1.IdentitySourceVisitorSelection{}, nil, connectorruntime.ErrInvalid
	}
	protocols := make(map[string]controlv1.ServiceProtocol, len(selection.Services))
	for name, protocol := range selection.Services { protocols[name] = controlv1.ServiceProtocol(protocol) }
	return authorityv1.IdentitySourceVisitorSelection{Environment: selection.Environment, PermissionId: selection.PermissionID, Services: protocols}, b.workload, nil
}

// identityChallenge keeps one fixed-delivery slot per native owner. issuing a
// second challenge retires the first; neither renewal nor delivery extends it.
func (b *connectorConnectionBackend) IdentityChallenge() (authorityv1.IdentitySourceChallenge, error) {
	b.identityMu.Lock()
	defer b.identityMu.Unlock()
	selection, client, err := b.sourceSelection()
	if err != nil { return authorityv1.IdentitySourceChallenge{}, err }
	challenge, err := client.SourceChallenge(b.environmentSource, selection, b.directory, time.Now())
	if err != nil { return authorityv1.IdentitySourceChallenge{}, err }
	b.environmentChallenge = new(challenge)
	// the caller never receives aliases into the retained slot.
	challenge.Selection = new(*challenge.Selection)
	challenge.Selection.Services = maps.Clone(challenge.Selection.Services)
	return challenge, nil
}

func (b *connectorConnectionBackend) consumeEnvironmentReply(reply authorityv1.IdentitySourceReply) (string, error) {
	b.identityMu.Lock()
	defer b.identityMu.Unlock()
	challenge := b.environmentChallenge
	if challenge == nil || reply.Schema != 1 || reply.ChallengeId != challenge.Id || machineproof.ValidateSourceChallenge(*challenge, time.Now()) != nil {
		return "", connectorruntime.ErrInvalid
	}
	selection, client, err := b.sourceSelection()
	if err != nil { return "", err }
	current, err := client.SourceChallenge(b.environmentSource, selection, b.directory, time.Now())
	if err != nil { return "", err }
	if challenge.Source != current.Source || challenge.BindingDigest != current.BindingDigest || challenge.NativePublicKey != current.NativePublicKey || challenge.Operation != current.Operation || challenge.ExpiresAt.After(current.ExpiresAt) || !reflect.DeepEqual(challenge.Selection, current.Selection) {
		return "", connectorruntime.ErrInvalid
	}
	assertion, err := (workload.AssertionSource{Assertion: reply.Assertion}).Acquire(context.Background())
	if err != nil { return "", err }
	if challenge.Source.Kind == "registered_key" {
		key, err := publisherproof.KeyID(assertion)
		if err != nil || key != challenge.Source.KeyId { return "", connectorruntime.ErrInvalid }
	}
	// consume before sending authority traffic, even when that reply is lost.
	b.environmentChallenge = nil
	return assertion, nil
}

func (b *connectorConnectionBackend) UseEnvironmentIdentity(ctx context.Context, request connectorruntime.Request) error {
	ctx, finish, err := b.begin(ctx)
	if err != nil { return err }
	defer finish()
	if request.IdentityReply == nil && request.SDKEnvironment == nil {
		// borrowed handles consume already-confirmed authority without acquiring
		// a new proof. explicit SDK source reads carry their private input object.
		return nil
	}
	var assertion string
	if b.environmentAcquisition != nil {
		if request.IdentityReply != nil { return connectorruntime.ErrInvalid }
		getenv := (connectorruntime.SDKEnvironment{}).Getenv
		if request.SDKEnvironment != nil { snapshot := *request.SDKEnvironment; getenv = snapshot.Getenv }
		hints := *b.environmentAcquisition
		assertion, err = b.acquireEnvironmentFrom(ctx, func(ctx context.Context) (string,error){ return workload.Acquire(ctx, hints, nil, getenv) })
	} else {
		if request.IdentityReply == nil || request.SDKEnvironment != nil { return connectorruntime.ErrInvalid }
		assertion, err = b.consumeEnvironmentReply(*request.IdentityReply)
	}
	if err != nil {
		if errors.Is(err, workload.ErrAssertionSource) || errors.Is(err, workload.ErrAssertionUnavailable) { return failure.Wrap("acquire environment identity proof", failure.WorkloadAssertionUnavailable, err) }
		return err
	}
	return b.attach(ctx, assertion, true)
}

func (b *connectorConnectionBackend) configureEnvironmentAcquisition(request connectorruntime.EnvironmentStart) error {
	if request.Acquisition == nil {
		if request.Environment != nil || request.GitHubActionsRefresh != nil { return connectorruntime.ErrInvalid }
		return nil
	}
	if request.Source.Kind != "oidc" { return connectorruntime.ErrInvalid }
	hints := *request.Acquisition
	if workload.ValidateAcquisition(hints) != nil { return connectorruntime.ErrInvalid }
	getenv := (connectorruntime.SDKEnvironment{}).Getenv
	if request.Environment != nil {
		environment := *request.Environment
		getenv = environment.Getenv
	}
	refresh := workload.RefreshSource(b.directory, hints, getenv)
	if request.GitHubActionsRefresh != nil {
		job := *request.GitHubActionsRefresh
		if b.parentPID != 0 || b.sdk != nil || request.Environment != nil || hints.Method != "github-actions" || job.Audience != hints.Audience || workload.ValidateGitHubActionsSource(job.Getenv) != nil {
			return connectorruntime.ErrInvalid
		}
		getenv = job.Getenv
		refresh = new(hints)
	}
	if hints.Method == "token-file" && !filepath.IsAbs(hints.TokenFile) { return connectorruntime.ErrInvalid }
	b.environmentAcquisition = new(hints)
	b.environmentAcquire = func(ctx context.Context) (string, error) { return workload.Acquire(ctx, hints, nil, getenv) }
	if refresh != nil {
		// request-only token values/callbacks never become background sources.
		selected := *refresh
		acquire := func(ctx context.Context) (string, error) { return workload.Acquire(ctx, selected, nil, getenv) }
		b.refreshAssertion = func(ctx context.Context) (string, error) { return b.acquireEnvironmentFrom(ctx, acquire) }
	}
	return nil
}

func (b *connectorConnectionBackend) acquireEnvironmentAssertion(ctx context.Context) (string, error) {
	if b.environmentAcquire == nil { return "", connectorruntime.ErrInvalid }
	return b.acquireEnvironmentFrom(ctx, b.environmentAcquire)
}

func (b *connectorConnectionBackend) acquireEnvironmentFrom(ctx context.Context, acquire func(context.Context) (string, error)) (string, error) {
	b.identityMu.Lock()
	if b.sourceGate == nil { b.sourceGate = make(chan struct{}, 1) }
	gate := b.sourceGate
	b.identityMu.Unlock()
	select {
	case gate <- struct{}{}: defer func(){ <-gate }()
	case <-ctx.Done(): return "", context.Cause(ctx)
	}
	challenge, err := b.IdentityChallenge()
	if err != nil { return "", err }
	call, cancel := context.WithDeadline(ctx, challenge.ExpiresAt)
	defer cancel()
	assertion, err := acquire(call)
	if err != nil { return "", err }
	if err := context.Cause(call); err != nil { return "", err }
	return b.consumeEnvironmentReply(authorityv1.IdentitySourceReply{Schema: 1, ChallengeId: challenge.Id, Assertion: assertion})
}
