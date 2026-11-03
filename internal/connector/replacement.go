package connector

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/tnldotdev/tnl/internal/client/project/meta"
	connectorruntime "github.com/tnldotdev/tnl/internal/connector/runtime"
	"github.com/tnldotdev/tnl/internal/connector/workload"
	authorityv1 "github.com/tnldotdev/tnl/pkg/api/control/authority/v1"
	controlv1 "github.com/tnldotdev/tnl/pkg/api/control/public/v1"
)

// one transaction retains its retry key/nonce, fixed scope, and confirmed result.
// sessionGate owns progress; mu protects publication/removal of the transaction.
// shutdown reads progress only after joining operations.
type workloadReplacement struct {
	previous *workload.Client
	client   *workload.Client
	binding  string
	progress workloadReplacementProgress
}

type workloadReplacementProgress interface{ workloadReplacementProgress() }

type replacementAllocated struct{}
type replacementExchangePending struct {
	scope connectorruntime.Context
	// retained only while the response may be lost, so cleanup can recover and
	// revoke an issued session with this exact key, nonce, and selected scope.
	assertion string
}
type replacementExchanged struct {
	scope   connectorruntime.Context
	session authorityv1.WorkloadSession
}
type replacementValidated struct {
	replacementExchanged
	services map[string]controlv1.Service
	metadata meta.PublicMetadata
}

func (replacementAllocated) workloadReplacementProgress()        {}
func (*replacementExchangePending) workloadReplacementProgress() {}
func (*replacementExchanged) workloadReplacementProgress()       {}
func (*replacementValidated) workloadReplacementProgress()       {}

func (r *workloadReplacement) selectScope(configured connectorruntime.Context, identity authorityv1.WorkloadIdentity, assertion string) (*replacementExchangePending, error) {
	if identity.Binding != r.binding {
		return nil, connectorruntime.ErrUnauthorized
	}
	var scope connectorruntime.Context
	switch p := r.progress.(type) {
	case replacementAllocated:
		scope = configured
		scope.Services = nil
		for _, name := range configured.Services {
			if slices.Contains(identity.Services, name) {
				scope.Services = append(scope.Services, name)
			}
		}
	case *replacementExchangePending:
		// a policy change or rotated assertion cannot widen an ambiguous exchange.
		scope = p.scope
	default:
		return nil, connectorruntime.ErrInvalid
	}
	if len(scope.Services) == 0 {
		return nil, connectorruntime.ErrUnauthorized
	}
	pending := &replacementExchangePending{scope: scope, assertion: assertion}
	r.progress = pending
	return pending, nil
}

func (r *workloadReplacement) confirmExchange(pending *replacementExchangePending, session authorityv1.WorkloadSession) (*replacementExchanged, error) {
	if r.progress != pending {
		return nil, connectorruntime.ErrInvalid
	}
	exchanged := &replacementExchanged{scope: pending.scope, session: session}
	r.progress = exchanged
	return exchanged, nil
}

func (r *workloadReplacement) confirmAttachment(current workloadReplacementProgress, session authorityv1.WorkloadSession) (*replacementExchanged, error) {
	if r.progress != current {
		return nil, connectorruntime.ErrInvalid
	}
	var scope connectorruntime.Context
	switch p := current.(type) {
	case *replacementExchanged:
		scope = p.scope
	case *replacementValidated:
		// a rejected promotion must revalidate inventory after attachment.
		scope = p.scope
	default:
		return nil, connectorruntime.ErrInvalid
	}
	exchanged := &replacementExchanged{scope: scope, session: session}
	r.progress = exchanged
	return exchanged, nil
}

func (r *workloadReplacement) validateInventory(exchanged *replacementExchanged, configuration projectConfiguration, inventory controlv1.WorkloadServices) (*replacementValidated, error) {
	if r.progress != exchanged {
		return nil, connectorruntime.ErrInvalid
	}
	services, err := workloadInventoryServices(inventory, exchanged.session.TeamId)
	if err != nil {
		return nil, err
	}
	services, metadata, err := projectConnectionMetadata(configuration.Config, exchanged.scope.Services, services)
	if err != nil {
		return nil, err
	}
	validated := &replacementValidated{replacementExchanged: *exchanged, services: services, metadata: metadata}
	r.progress = validated
	return validated, nil
}

// replaceWorkload runs only under sessionGate, after control confirmed expiry.
func (b *connectorConnectionBackend) replaceWorkload(ctx context.Context, previous *workload.Client, binding, assertion string) error {
	b.mu.Lock()
	r := b.replacement
	closed := b.closed
	b.mu.Unlock()
	if closed {
		return connectorruntime.ErrExpired
	}
	if r == nil {
		client, err := workload.New(b.scope.Server, b.httpClient)
		if err != nil {
			return err
		}
		r = &workloadReplacement{previous: previous, client: client, binding: binding, progress: replacementAllocated{}}
		b.mu.Lock()
		if b.closed || b.workload != previous {
			b.mu.Unlock()
			return connectorruntime.ErrExpired
		}
		b.replacement = r
		b.mu.Unlock()
	}
	if r.previous != previous || r.binding != binding {
		return connectorruntime.ErrInvalid
	}
	identity, err := r.client.IdentifyPolicy(ctx, b.scope.TeamID, b.scope.ProjectKey, b.scope.SourceID, b.scope.Workload, assertion)
	if err != nil {
		return err
	}
	if identity.Binding != r.binding {
		return connectorruntime.ErrUnauthorized
	}
	var exchanged *replacementExchanged
	switch current := r.progress; current.(type) {
	case *replacementExchanged, *replacementValidated:
		// inventory recovery uses the confirmed session, not another exchange.
		// a new assertion still has to prove access to that exact session.
		session, err := r.client.Attach(ctx, assertion)
		if err != nil {
			b.discardExpiredReplacement(r, err)
			return err
		}
		exchanged, err = r.confirmAttachment(current, session)
		if err != nil {
			return err
		}
	case replacementAllocated, *replacementExchangePending:
		pending, err := r.selectScope(b.scope, identity, assertion)
		if err != nil {
			return err
		}
		session, err := exchangeConnectionWorkload(ctx, r.client, pending.scope, pending.assertion)
		if err != nil {
			b.discardExpiredReplacement(r, err)
			return err
		}
		exchanged, err = r.confirmExchange(pending, session)
		if err != nil {
			return err
		}
	default:
		return connectorruntime.ErrInvalid
	}
	if exchanged.session.Binding != r.binding {
		_ = r.client.Revoke(ctx)
		return connectorruntime.ErrUnauthorized
	}
	inventory, err := r.client.ListServices(ctx)
	if err != nil {
		return err
	}
	validated, err := r.validateInventory(exchanged, b.project, inventory)
	if err != nil {
		return err
	}
	return b.promoteReplacement(r, validated, assertion, identity)
}

func (b *connectorConnectionBackend) discardExpiredReplacement(r *workloadReplacement, err error) {
	// only control-confirmed expiry permits another retry nonce/key.
	if !errors.Is(err, workload.ErrSessionExpired) {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.replacement == r && !b.closed {
		b.replacement = nil
	}
}

func (b *connectorConnectionBackend) promoteReplacement(r *workloadReplacement, validated *replacementValidated, assertion string, identity authorityv1.WorkloadIdentity) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.closed {
		return connectorruntime.ErrExpired
	}
	if b.replacement != r || b.workload != r.previous || r.progress != validated {
		return connectorruntime.ErrInvalid
	}
	if !validated.session.ExpiresAt.After(time.Now()) || !validated.session.LeaseExpiresAt.After(time.Now()) {
		return connectorruntime.ErrExpired
	}
	b.workload = r.client
	b.deadline = validated.session.ExpiresAt
	b.services, b.metadata = validated.services, validated.metadata
	b.rememberAssertion(assertion, identity.AssertionExpiresAt, validated.session)
	b.replacement = nil
	b.publishLocked()
	return nil
}

// recoverForCleanup runs after operations join, within the caller's budget. an
// ambiguous exchange must recover its credential before it can be revoked.
func (r *workloadReplacement) recoverForCleanup(ctx context.Context) error {
	pending, ok := r.progress.(*replacementExchangePending)
	if !ok {
		return nil
	}
	session, err := exchangeConnectionWorkload(ctx, r.client, pending.scope, pending.assertion)
	if errors.Is(err, workload.ErrSessionExpired) {
		return nil
	}
	if err != nil {
		return err
	}
	_, err = r.confirmExchange(pending, session)
	return err
}
